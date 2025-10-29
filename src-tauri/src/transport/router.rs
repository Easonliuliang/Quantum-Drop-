use std::fs;

use std::sync::Arc;

use log::warn;
use serde::Deserialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};
use tokio::time::{timeout, Duration};

#[cfg(feature = "transport-webrtc")]
use super::webrtc::WebRtcAdapter;
#[cfg(feature = "transport-quic")]
use super::QuicAdapter;
use super::{MockLocalAdapter, SessionDesc, TransportAdapter, TransportError, TransportStream};
#[cfg(feature = "transport-relay")]
use super::{RelayAdapter, RelayHint};

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

type AdapterHandle = Arc<dyn TransportAdapter>;

#[derive(Default)]
struct TransportPreferences {
    routes: Vec<RouteKind>,
    stun: Vec<String>,
    #[cfg(feature = "transport-relay")]
    relay: Option<String>,
}

pub struct Router {
    preferred: Vec<RouteKind>,
    mock: AdapterHandle,
    lan: Option<AdapterHandle>,
    p2p: Option<AdapterHandle>,
    relay: Option<AdapterHandle>,
    #[cfg(feature = "transport-relay")]
    relay_hint: Option<RelayHint>,
}

impl Router {
    pub fn from_app(app: &AppHandle) -> Self {
        let prefs = read_transport_preferences(app);
        Self::build_router(
            prefs.routes,
            prefs.stun,
            #[cfg(feature = "transport-relay")]
            prefs.relay,
        )
    }

    #[allow(dead_code)]
    pub fn new(preferred: Vec<RouteKind>) -> Self {
        Self::build_router(
            preferred,
            Vec::new(),
            #[cfg(feature = "transport-relay")]
            None,
        )
    }

    pub fn preferred_routes(&self) -> &[RouteKind] {
        &self.preferred
    }

    pub fn p2p_only(app: &AppHandle) -> Self {
        let prefs = read_transport_preferences(app);
        Self::build_router(
            vec![RouteKind::P2p],
            prefs.stun,
            #[cfg(feature = "transport-relay")]
            prefs.relay,
        )
    }

    fn build_router(
        mut preferred: Vec<RouteKind>,
        stun: Vec<String>,
        #[cfg(feature = "transport-relay")] relay: Option<String>,
    ) -> Self {
        if preferred.is_empty() {
            preferred = vec![RouteKind::Lan, RouteKind::P2p, RouteKind::Relay];
        }
        if preferred.iter().all(|route| route != &RouteKind::MockLocal) {
            preferred.push(RouteKind::MockLocal);
        }

        #[cfg(not(feature = "transport-webrtc"))]
        let _ = &stun;

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
        let lan: Option<AdapterHandle> = None;

        #[cfg(feature = "transport-webrtc")]
        let p2p: Option<AdapterHandle> = build_webrtc_adapter(&stun).map(|adapter| {
            let handle: AdapterHandle = Arc::new(adapter);
            handle
        });
        #[cfg(not(feature = "transport-webrtc"))]
        let p2p: Option<AdapterHandle> = None;

        #[cfg(feature = "transport-relay")]
        let relay_adapter: Option<AdapterHandle> = Some(Arc::new(RelayAdapter::new()));
        #[cfg(not(feature = "transport-relay"))]
        let relay_adapter: Option<AdapterHandle> = None;

        #[cfg(feature = "transport-relay")]
        let relay_hint = relay
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
            #[cfg(feature = "transport-relay")]
            relay_hint,
        }
    }

    pub async fn connect(&self, session: &SessionDesc) -> Result<SelectedRoute, TransportError> {
        let mut last_error: Option<TransportError> = None;
        for route in &self.preferred {
            match route {
                RouteKind::Lan => {
                    if let Some(adapter) = &self.lan {
                        match timeout(Duration::from_secs(3), adapter.connect(session)).await {
                            Ok(Ok(stream)) => {
                                return Ok(SelectedRoute {
                                    route: RouteKind::Lan,
                                    stream,
                                })
                            }
                            Ok(Err(err)) => last_error = Some(err),
                            Err(_) => {
                                last_error = Some(TransportError::Timeout(
                                    "lan route timed out after 3s".into(),
                                ))
                            }
                        }
                    }
                }
                RouteKind::P2p => {
                    if let Some(adapter) = &self.p2p {
                        match timeout(Duration::from_secs(6), adapter.connect(session)).await {
                            Ok(Ok(stream)) => {
                                return Ok(SelectedRoute {
                                    route: RouteKind::P2p,
                                    stream,
                                })
                            }
                            Ok(Err(err)) => last_error = Some(err),
                            Err(_) => {
                                last_error = Some(TransportError::Timeout(
                                    "p2p route timed out after 6s".into(),
                                ))
                            }
                        }
                    }
                }
                RouteKind::Relay =>
                {
                    #[cfg(feature = "transport-relay")]
                    if let Some(relay) = &self.relay {
                        let relay_session =
                            session_with_relay_hint(session, self.relay_hint.as_ref());
                        match timeout(Duration::from_secs(8), relay.connect(&relay_session)).await {
                            Ok(Ok(stream)) => {
                                return Ok(SelectedRoute {
                                    route: RouteKind::Relay,
                                    stream,
                                })
                            }
                            Ok(Err(err)) => last_error = Some(err),
                            Err(_) => {
                                last_error = Some(TransportError::Timeout(
                                    "relay route timed out after 8s".into(),
                                ))
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let stream = self
            .mock
            .connect(session)
            .await
            .map_err(|err| last_error.unwrap_or(err))?;
        Ok(SelectedRoute {
            route: RouteKind::MockLocal,
            stream,
        })
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

fn read_transport_preferences(app: &AppHandle) -> TransportPreferences {
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
    let mut prefs = TransportPreferences::default();
    if let Some(node) = config.pointer(pointer) {
        if let Some(routes) = node
            .get("preferredRoutes")
            .and_then(|value| value.as_array())
        {
            for value in routes {
                if let Some(route_str) = value.as_str() {
                    if let Some(route) = parse_route(route_str) {
                        prefs.routes.push(route);
                    }
                }
            }
        }
        if let Some(stun) = node.get("stun").and_then(|value| value.as_array()) {
            for value in stun {
                if let Some(url) = value.as_str() {
                    let trimmed = url.trim();
                    if !trimmed.is_empty() {
                        prefs.stun.push(trimmed.to_string());
                    }
                }
            }
        }
        #[cfg(feature = "transport-relay")]
        if let Some(relay) = node.get("relayEndpoint").and_then(|value| value.as_str()) {
            let trimmed = relay.trim();
            if !trimmed.is_empty() {
                prefs.relay = Some(trimmed.to_string());
            }
        }
    }
    prefs
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
    let routes = transport
        .preferred_routes
        .into_iter()
        .filter_map(|value| parse_route(&value))
        .collect();
    let stun = transport
        .stun
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .collect();
    #[cfg(feature = "transport-relay")]
    let relay = transport.relay_endpoint.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    Some(TransportPreferences {
        routes,
        stun,
        #[cfg(feature = "transport-relay")]
        relay,
    })
}

#[cfg(feature = "transport-webrtc")]
fn build_webrtc_adapter(stun: &[String]) -> Option<WebRtcAdapter> {
    use webrtc::ice_transport::ice_server::RTCIceServer;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    if stun.is_empty() {
        return Some(WebRtcAdapter::default());
    }

    let ice_servers = stun
        .iter()
        .filter(|value| !value.trim().is_empty())
        .map(|url| RTCIceServer {
            urls: vec![url.clone()],
            ..Default::default()
        })
        .collect::<Vec<_>>();

    let mut config = RTCConfiguration::default();
    if !ice_servers.is_empty() {
        config.ice_servers = ice_servers;
    }
    Some(WebRtcAdapter::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use tokio::runtime::Runtime;
    use tokio::time::{sleep, Duration as TestDuration};

    #[cfg(feature = "transport-quic")]
    #[test]
    fn prefers_quic_for_lan_route() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let router = Router::new(vec![RouteKind::Lan]);
            let session = SessionDesc::new("router-quic");
            let selection = router.connect(&session).await.expect("connect");
            assert_eq!(selection.route, RouteKind::Lan);
            let mut stream = selection.stream;
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
            let SelectedRoute { route, mut stream } =
                router.connect(&session).await.expect("connect fallback");
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
            let SelectedRoute { route, mut stream } =
                router.connect(&session).await.expect("connect relay");
            assert_eq!(route, RouteKind::Relay);
            stream.close().await.expect("close");
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
    #[cfg(feature = "transport-relay")]
    #[serde(rename = "relayEndpoint", default)]
    relay_endpoint: Option<String>,
}
