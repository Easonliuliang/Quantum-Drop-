use std::fs;
use std::sync::Arc;
use std::time::Instant;

use log::warn;
use serde::Deserialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};
use tokio::time::{timeout, Duration};

use crate::config::ConfigStore;

#[cfg(feature = "transport-webrtc")]
use super::webrtc::WebRtcAdapter;
#[cfg(feature = "transport-quic")]
use super::QuicAdapter;
use super::{MockLocalAdapter, SessionDesc, TransportAdapter, TransportError, TransportStream};
#[cfg(feature = "transport-relay")]
use super::{RelayAdapter, RelayHint};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RouteKind {
    Lan,
    P2p,
    Relay,
    MockLocal,
}

impl RouteKind {
    pub fn label(&self) -> &'static str {
        match self {
            RouteKind::Lan => "lan",
            RouteKind::P2p => "p2p",
            RouteKind::Relay => "relay",
            RouteKind::MockLocal => "mock",
        }
    }
}

pub struct SelectedRoute {
    pub route: RouteKind,
    pub stream: Box<dyn TransportStream>,
    pub attempt_notes: Vec<String>,
}

type AdapterHandle = Arc<dyn TransportAdapter>;

#[derive(Default)]
struct TransportPreferences {
    routes: Vec<RouteKind>,
    stun: Vec<String>,
    turn: Vec<TurnServerConfig>,
    signaling: Option<String>,
    timeouts: RouteTimeouts,
    #[cfg(feature = "transport-relay")]
    relay: Option<String>,
    #[cfg(feature = "transport-webrtc")]
    app_handle: Option<AppHandle>,
}

#[derive(Debug, Clone, Default)]
struct TurnServerConfig {
    urls: Vec<String>,
    username: Option<String>,
    credential: Option<String>,
}

#[derive(Clone, Copy)]
struct RouteTimeouts {
    lan: Duration,
    p2p: Duration,
    relay: Duration,
}

impl Default for RouteTimeouts {
    fn default() -> Self {
        Self {
            lan: Duration::from_secs(3),
            p2p: Duration::from_secs(10),
            relay: Duration::from_secs(8),
        }
    }
}

pub struct Router {
    preferred: Vec<RouteKind>,
    mock: AdapterHandle,
    lan: Option<AdapterHandle>,
    p2p: Option<AdapterHandle>,
    relay: Option<AdapterHandle>,
    timeouts: RouteTimeouts,
    #[cfg(feature = "transport-relay")]
    relay_hint: Option<RelayHint>,
}

impl Router {
    pub fn from_app(app: &AppHandle) -> Self {
        Self::from_app_with_override(app, None)
    }

    pub fn from_app_with_routes(app: &AppHandle, routes: Vec<RouteKind>) -> Self {
        Self::from_app_with_override(app, Some(routes))
    }

    #[allow(dead_code)]
    pub fn new(preferred: Vec<RouteKind>) -> Self {
        let mut prefs = TransportPreferences::default();
        prefs.routes = preferred;
        Self::build_router(prefs)
    }

    pub fn preferred_routes(&self) -> &[RouteKind] {
        &self.preferred
    }

    pub fn p2p_only(app: &AppHandle) -> Self {
        Self::from_app_with_routes(app, vec![RouteKind::P2p])
    }

    fn from_app_with_override(app: &AppHandle, routes: Option<Vec<RouteKind>>) -> Self {
        let mut prefs = read_transport_preferences(app);
        #[cfg(feature = "transport-webrtc")]
        {
            prefs.app_handle = Some(app.clone());
        }
        if let Some(values) = routes {
            prefs.routes = values;
        }
        Self::build_router(prefs)
    }

    fn build_router(prefs: TransportPreferences) -> Self {
        let mut preferred = prefs.routes.clone();
        if preferred.is_empty() {
            preferred = vec![RouteKind::Lan, RouteKind::P2p, RouteKind::Relay];
        }
        if preferred.iter().all(|route| route != &RouteKind::MockLocal) {
            preferred.push(RouteKind::MockLocal);
        }

        let mock: AdapterHandle = Arc::new(MockLocalAdapter::new());

        #[cfg(feature = "transport-quic")]
        let lan: Option<AdapterHandle> = match QuicAdapter::new() {
            Ok(adapter) => Some(Arc::new(adapter)),
            Err(err) => {
                warn!("failed to initialise QUIC adapter: {err}");
                None
            }
        };
        #[cfg(not(feature = "transport-quic"))]
        let lan: Option<AdapterHandle> = {
            if preferred.iter().any(|route| route == &RouteKind::Lan) {
                warn!("transport-quic feature disabled; lan route unavailable");
            }
            None
        };

        #[cfg(feature = "transport-webrtc")]
        let p2p: Option<AdapterHandle> = build_webrtc_adapter(&prefs).map(|adapter| {
            let handle: AdapterHandle = Arc::new(adapter);
            handle
        });
        #[cfg(feature = "transport-webrtc")]
        if p2p.is_none() && preferred.iter().any(|route| route == &RouteKind::P2p) {
            warn!("signaling url missing; p2p route unavailable");
        }
        #[cfg(not(feature = "transport-webrtc"))]
        let p2p: Option<AdapterHandle> = {
            if preferred.iter().any(|route| route == &RouteKind::P2p) {
                warn!("transport-webrtc feature disabled; p2p route unavailable");
            }
            let _ = &stun;
            None
        };

        #[cfg(feature = "transport-relay")]
        let relay_adapter: Option<AdapterHandle> = Some(Arc::new(RelayAdapter::new()));
        #[cfg(not(feature = "transport-relay"))]
        let relay_adapter: Option<AdapterHandle> = {
            if preferred.iter().any(|route| route == &RouteKind::Relay) {
                warn!("transport-relay feature disabled; relay route unavailable");
            }
            None
        };

        #[cfg(feature = "transport-relay")]
        let relay_hint =
            prefs
                .relay
                .as_ref()
                .and_then(|endpoint| match parse_relay_hint(endpoint) {
                    Ok(hint) => Some(hint),
                    Err(err) => {
                        warn!("invalid relay endpoint '{}': {}", endpoint, err);
                        None
                    }
                });

        Router {
            preferred,
            mock,
            lan,
            p2p,
            relay: relay_adapter,
            timeouts: prefs.timeouts,
            #[cfg(feature = "transport-relay")]
            relay_hint,
        }
    }

    pub async fn connect(&self, session: &SessionDesc) -> Result<SelectedRoute, TransportError> {
        let mut notes = Vec::new();
        let mut real_routes = 0usize;

        for route in &self.preferred {
            if *route == RouteKind::MockLocal {
                continue;
            }
            let Some(adapter) = self.adapter_for(route) else {
                notes.push(format!("{} adapter unavailable", route.label()));
                continue;
            };
            real_routes += 1;
            let session_clone = {
                #[cfg(feature = "transport-relay")]
                {
                    if *route == RouteKind::Relay {
                        session_with_relay_hint(session, self.relay_hint.as_ref())
                    } else {
                        session.clone()
                    }
                }
                #[cfg(not(feature = "transport-relay"))]
                {
                    session.clone()
                }
            };
            match run_route_attempt(
                route.clone(),
                adapter.clone(),
                session_clone,
                self.timeout_for(route),
            )
            .await
            {
                Ok((route, stream, note)) => {
                    notes.push(note);
                    return Ok(SelectedRoute {
                        route,
                        stream,
                        attempt_notes: notes,
                    });
                }
                Err(note) => notes.push(note),
            }
        }

        if self
            .preferred
            .iter()
            .any(|route| route == &RouteKind::MockLocal)
        {
            let started = Instant::now();
            match self.mock.connect(session).await {
                Ok(stream) => {
                    let elapsed_ms = started.elapsed().as_millis();
                    notes.push(format!("mock success in {}ms", elapsed_ms));
                    return Ok(SelectedRoute {
                        route: RouteKind::MockLocal,
                        stream,
                        attempt_notes: notes,
                    });
                }
                Err(err) => {
                    notes.push(format!("mock failed: {}", err));
                }
            }
        } else if real_routes == 0 {
            notes.push("no transport routes available".into());
        }

        let summary = if notes.is_empty() {
            "transport selection failed".to_string()
        } else {
            format!("transport selection failed: {}", notes.join(" | "))
        };
        Err(TransportError::Setup(summary))
    }

    fn adapter_for(&self, route: &RouteKind) -> Option<&AdapterHandle> {
        match route {
            RouteKind::Lan => self.lan.as_ref(),
            RouteKind::P2p => self.p2p.as_ref(),
            RouteKind::Relay => self.relay.as_ref(),
            RouteKind::MockLocal => Some(&self.mock),
        }
    }

    fn timeout_for(&self, route: &RouteKind) -> Duration {
        match route {
            RouteKind::Lan => self.timeouts.lan,
            RouteKind::P2p => self.timeouts.p2p,
            RouteKind::Relay => self.timeouts.relay,
            RouteKind::MockLocal => Duration::from_secs(1),
        }
    }
}

#[cfg(feature = "transport-relay")]
fn parse_relay_hint(endpoint: &str) -> Result<RelayHint, String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err("empty relay endpoint".into());
    }
    let scheme_stripped = trimmed
        .strip_prefix("tcp://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let mut parts = scheme_stripped.rsplitn(2, ':');
    let port_str = parts
        .next()
        .ok_or_else(|| "relay endpoint missing port".to_string())?;
    let host_part = parts
        .next()
        .ok_or_else(|| "relay endpoint missing host".to_string())?;
    let host = host_part
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    if host.is_empty() {
        return Err("relay endpoint host empty".into());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|err| format!("invalid relay port: {err}"))?;
    Ok(RelayHint {
        host: host.to_string(),
        port,
    })
}

#[cfg(feature = "transport-relay")]
fn default_local_relay_hint() -> RelayHint {
    RelayHint {
        host: "127.0.0.1".into(),
        port: 0,
    }
}

#[cfg(feature = "transport-relay")]
fn session_with_relay_hint(session: &SessionDesc, hint: Option<&RelayHint>) -> SessionDesc {
    if session.relay.is_some() {
        return session.clone();
    }
    let mut clone = session.clone();
    let fallback = hint.cloned().unwrap_or_else(default_local_relay_hint);
    clone.relay = Some(fallback);
    clone
}

fn read_transport_preferences(app: &AppHandle) -> TransportPreferences {
    if let Some(store) = app.try_state::<ConfigStore>() {
        let settings = store.get();
        let mut prefs = TransportPreferences::default();
        for value in settings.preferred_routes {
            if let Some(route) = parse_route(&value) {
                #[cfg(feature = "transport-relay")]
                if route == RouteKind::Relay && !settings.relay_enabled {
                    continue;
                }
                prefs.routes.push(route);
            }
        }
        #[cfg(feature = "transport-relay")]
        {
            if !settings.relay_enabled {
                prefs.relay = None;
            }
        }
        if !prefs.routes.is_empty() {
            return prefs;
        }
    }
    if let Some(prefs) = read_transport_from_app_yaml(app) {
        return prefs;
    }
    if let Ok(value) = serde_json::to_value(app.config()) {
        return extract_transport_preferences(&value);
    }
    TransportPreferences::default()
}

fn extract_transport_preferences(config: &Value) -> TransportPreferences {
    let pointer = "/app/s2/transport";
    if let Some(node) = config.pointer(pointer) {
        if let Ok(transport) = serde_json::from_value::<TransportYaml>(node.clone()) {
            return transport.into();
        }
    }
    TransportPreferences::default()
}

fn parse_route(route: &str) -> Option<RouteKind> {
    match route.to_ascii_lowercase().as_str() {
        "lan" => Some(RouteKind::Lan),
        "p2p" => Some(RouteKind::P2p),
        "relay" => Some(RouteKind::Relay),
        "mock" => Some(RouteKind::MockLocal),
        _ => None,
    }
}

fn read_transport_from_app_yaml(app: &AppHandle) -> Option<TransportPreferences> {
    let mut path = app.path().app_config_dir().ok()?;
    path.push("app.yaml");
    let contents = fs::read_to_string(path).ok()?;
    let parsed: AppYaml = serde_yaml::from_str(&contents).ok()?;
    let transport = parsed.s2?.transport?;
    Some(transport.into())
}

#[cfg(feature = "transport-webrtc")]
fn build_webrtc_adapter(prefs: &TransportPreferences) -> Option<WebRtcAdapter> {
    use webrtc::ice_transport::ice_server::RTCIceServer;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    let signaling = prefs.signaling.clone()?;

    let mut ice_servers = Vec::new();
    for url in prefs.stun.iter().filter(|value| !value.trim().is_empty()) {
        ice_servers.push(RTCIceServer {
            urls: vec![url.clone()],
            ..Default::default()
        });
    }

    for entry in &prefs.turn {
        if entry.urls.is_empty() {
            continue;
        }
        ice_servers.push(RTCIceServer {
            urls: entry.urls.clone(),
            username: entry.username.clone().unwrap_or_default(),
            credential: entry.credential.clone().unwrap_or_default(),
            ..Default::default()
        });
    }

    let mut config = RTCConfiguration::default();
    if !ice_servers.is_empty() {
        config.ice_servers = ice_servers;
    }
    #[cfg(feature = "transport-webrtc")]
    {
        return Some(WebRtcAdapter::with_signaling(
            config,
            signaling,
            prefs.app_handle.clone(),
        ));
    }
    #[cfg(not(feature = "transport-webrtc"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tokio::runtime::Runtime;
    use tokio::time::{sleep, Duration as TestDuration};

    #[test]
    fn prefers_quic_for_lan_route() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let mut router = Router::new(vec![RouteKind::Lan, RouteKind::P2p]);
            router.lan = Some(Arc::new(StubAdapter::success(TestDuration::from_millis(1))));
            router.p2p = Some(Arc::new(StubAdapter::success(TestDuration::from_millis(
                10,
            ))));

            let session = SessionDesc::new("router-quic");
            let SelectedRoute {
                route, mut stream, ..
            } = router.connect(&session).await.expect("connect lan");
            assert_eq!(route, RouteKind::Lan);
            stream.close().await.expect("close");
        });
    }

    #[derive(Clone)]
    struct StubAdapter {
        delay: TestDuration,
        fail: Option<String>,
    }

    impl StubAdapter {
        fn success(delay: TestDuration) -> Self {
            Self { delay, fail: None }
        }

        fn failure(message: impl Into<String>, delay: TestDuration) -> Self {
            Self {
                delay,
                fail: Some(message.into()),
            }
        }
    }

    #[async_trait]
    impl TransportAdapter for StubAdapter {
        async fn connect(
            &self,
            session: &SessionDesc,
        ) -> Result<Box<dyn TransportStream>, TransportError> {
            if !self.delay.is_zero() {
                sleep(self.delay).await;
            }
            if let Some(message) = &self.fail {
                Err(TransportError::Setup(message.clone()))
            } else {
                MockLocalAdapter::new().connect(session).await
            }
        }
    }

    #[test]
    fn falls_back_to_p2p_when_lan_times_out() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let mut router = Router::new(vec![RouteKind::Lan, RouteKind::P2p, RouteKind::Relay]);
            router.lan = Some(Arc::new(StubAdapter::success(TestDuration::from_secs(4))));
            router.p2p = Some(Arc::new(StubAdapter::success(TestDuration::from_millis(
                10,
            ))));

            let session = SessionDesc::new("timeout-test");
            let SelectedRoute {
                route, mut stream, ..
            } = router.connect(&session).await.expect("connect fallback");
            assert_eq!(route, RouteKind::P2p);
            stream.close().await.expect("close");
        });
    }

    #[cfg(feature = "transport-relay")]
    #[test]
    fn falls_back_to_relay_when_direct_routes_fail() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let mut router = Router::new(vec![RouteKind::Lan, RouteKind::P2p, RouteKind::Relay]);
            router.lan = Some(Arc::new(StubAdapter::failure(
                "lan failure",
                TestDuration::from_millis(5),
            )));
            router.p2p = Some(Arc::new(StubAdapter::failure(
                "p2p failure",
                TestDuration::from_millis(5),
            )));
            router.relay = Some(Arc::new(StubAdapter::success(TestDuration::from_millis(5))));
            router.relay_hint = Some(default_local_relay_hint());

            let session = SessionDesc::new("relay-fallback");
            let SelectedRoute {
                route, mut stream, ..
            } = router.connect(&session).await.expect("connect relay");
            assert_eq!(route, RouteKind::Relay);
            stream.close().await.expect("close");
        });
    }

    #[test]
    fn attempt_notes_capture_failures_before_success() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let mut router = Router::new(vec![RouteKind::Lan, RouteKind::P2p]);
            router.lan = Some(Arc::new(StubAdapter::failure(
                "lan failure",
                TestDuration::from_millis(5),
            )));
            router.p2p = Some(Arc::new(StubAdapter::success(TestDuration::from_millis(1))));

            let session = SessionDesc::new("attempt-notes-success");
            let SelectedRoute {
                route,
                mut stream,
                attempt_notes,
            } = router.connect(&session).await.expect("connect");
            assert_eq!(route, RouteKind::P2p);
            assert!(attempt_notes
                .iter()
                .any(|note| note.contains("lan failure")));
            assert!(attempt_notes
                .iter()
                .any(|note| note.contains("p2p success")));
            stream.close().await.expect("close");
        });
    }

    #[test]
    fn attempt_notes_included_in_error_summary() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let mut router = Router::new(vec![RouteKind::Lan, RouteKind::P2p]);
            router.lan = Some(Arc::new(StubAdapter::failure(
                "lan failure",
                TestDuration::from_millis(2),
            )));
            router.p2p = Some(Arc::new(StubAdapter::failure(
                "p2p failure",
                TestDuration::from_millis(2),
            )));

            let session = SessionDesc::new("attempt-notes-error");
            let err = match router.connect(&session).await {
                Ok(success) => {
                    panic!("expected failure, got route {:?}", success.route);
                }
                Err(err) => err,
            };
            match err {
                TransportError::Setup(message) => {
                    assert!(message.contains("lan failure"));
                    assert!(message.contains("p2p failure"));
                }
                other => panic!("unexpected error variant: {other:?}"),
            }
        });
    }
}

#[derive(Debug, Default, Deserialize)]
struct AppYaml {
    #[serde(default)]
    s2: Option<S2Config>,
}

#[derive(Debug, Default, Deserialize)]
struct S2Config {
    #[serde(default)]
    transport: Option<TransportYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct TransportYaml {
    #[serde(rename = "preferredRoutes", default)]
    preferred_routes: Vec<String>,
    #[serde(default)]
    stun: Vec<String>,
    #[serde(rename = "signalingUrl", default)]
    signaling_url: Option<String>,
    #[serde(default)]
    turn: Option<TurnSection>,
    #[serde(default)]
    timeouts: Option<RouteTimeoutYaml>,
    #[cfg(feature = "transport-relay")]
    #[serde(rename = "relayEndpoint", default)]
    relay_endpoint: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct TurnSection {
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    credential: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RouteTimeoutYaml {
    #[serde(default)]
    lan: Option<String>,
    #[serde(default)]
    p2p: Option<String>,
    #[serde(default)]
    relay: Option<String>,
}

impl From<TransportYaml> for TransportPreferences {
    fn from(value: TransportYaml) -> Self {
        let routes = value
            .preferred_routes
            .into_iter()
            .filter_map(|route| parse_route(&route))
            .collect();
        let stun = value
            .stun
            .into_iter()
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect();
        let signaling = value.signaling_url.and_then(|url| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let mut turn = Vec::new();
        if let Some(section) = value.turn {
            let urls = section
                .urls
                .into_iter()
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>();
            if !urls.is_empty() {
                let username = section.username.and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                });
                let credential = section.credential.and_then(|value| {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                });
                turn.push(TurnServerConfig {
                    urls,
                    username,
                    credential,
                });
            }
        }
        let mut timeouts = RouteTimeouts::default();
        if let Some(custom) = value.timeouts {
            if let Some(raw) = custom.lan.as_deref().and_then(parse_duration_str) {
                timeouts.lan = raw;
            }
            if let Some(raw) = custom.p2p.as_deref().and_then(parse_duration_str) {
                timeouts.p2p = raw;
            }
            if let Some(raw) = custom.relay.as_deref().and_then(parse_duration_str) {
                timeouts.relay = raw;
            }
        }
        #[cfg(feature = "transport-relay")]
        let relay = value.relay_endpoint.and_then(|entry| {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        TransportPreferences {
            routes,
            stun,
            turn,
            signaling,
            timeouts,
            #[cfg(feature = "transport-relay")]
            relay,
            #[cfg(feature = "transport-webrtc")]
            app_handle: None,
        }
    }
}

fn parse_duration_str(value: &str) -> Option<Duration> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    humantime::parse_duration(trimmed)
        .or_else(|_| trimmed.parse::<u64>().map(Duration::from_secs))
        .ok()
}

async fn run_route_attempt(
    route: RouteKind,
    adapter: AdapterHandle,
    session: SessionDesc,
    timeout_duration: Duration,
) -> Result<(RouteKind, Box<dyn TransportStream>, String), String> {
    let started = Instant::now();
    match timeout(timeout_duration, adapter.connect(&session)).await {
        Ok(Ok(stream)) => {
            let elapsed = started.elapsed().as_millis();
            Ok((
                route.clone(),
                stream,
                format!("{} success in {}ms", route.label(), elapsed),
            ))
        }
        Ok(Err(err)) => {
            let elapsed = started.elapsed().as_millis();
            Err(format!(
                "{} error after {}ms: {}",
                route.label(),
                elapsed,
                err
            ))
        }
        Err(_) => Err(format!(
            "{} timed out after {:?}",
            route.label(),
            timeout_duration
        )),
    }
}
