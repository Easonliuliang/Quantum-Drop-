use std::fs;

use serde::Deserialize;
use serde_json::Value;
use tauri::{AppHandle, Manager};

#[cfg(feature = "transport-webrtc")]
use super::webrtc::WebRtcAdapter;
#[cfg(feature = "transport-quic")]
use super::QuicAdapter;
use super::{MockLocalAdapter, SessionDesc, TransportAdapter, TransportError, TransportStream};

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

#[derive(Default)]
struct TransportPreferences {
    routes: Vec<RouteKind>,
    stun: Vec<String>,
}

pub struct Router {
    preferred: Vec<RouteKind>,
    mock: MockLocalAdapter,
    #[cfg(feature = "transport-quic")]
    quic: Option<QuicAdapter>,
    #[cfg(feature = "transport-webrtc")]
    webrtc: Option<WebRtcAdapter>,
}

impl Router {
    pub fn from_app(app: &AppHandle) -> Self {
        let prefs = read_transport_preferences(app);
        Self::build_router(prefs.routes, prefs.stun)
    }

    #[allow(dead_code)]
    pub fn new(preferred: Vec<RouteKind>) -> Self {
        Self::build_router(preferred, Vec::new())
    }

    pub fn preferred_routes(&self) -> &[RouteKind] {
        &self.preferred
    }

    pub fn p2p_only(app: &AppHandle) -> Self {
        let prefs = read_transport_preferences(app);
        Self::build_router(vec![RouteKind::P2p], prefs.stun)
    }

    fn build_router(mut preferred: Vec<RouteKind>, stun: Vec<String>) -> Self {
        if preferred.is_empty() {
            preferred = vec![RouteKind::P2p, RouteKind::Lan, RouteKind::Relay];
        }
        if preferred.iter().all(|route| route != &RouteKind::MockLocal) {
            preferred.push(RouteKind::MockLocal);
        }

        #[cfg(not(feature = "transport-webrtc"))]
        let _ = &stun;

        Router {
            preferred,
            mock: MockLocalAdapter::new(),
            #[cfg(feature = "transport-quic")]
            quic: QuicAdapter::new().ok(),
            #[cfg(feature = "transport-webrtc")]
            webrtc: build_webrtc_adapter(&stun),
        }
    }

    pub async fn connect(&self, session: &SessionDesc) -> Result<SelectedRoute, TransportError> {
        let mut last_error: Option<TransportError> = None;
        for route in &self.preferred {
            match route {
                RouteKind::Lan =>
                {
                    #[cfg(feature = "transport-quic")]
                    if let Some(quic) = &self.quic {
                        match quic.connect(session).await {
                            Ok(stream) => {
                                return Ok(SelectedRoute {
                                    route: RouteKind::Lan,
                                    stream,
                                })
                            }
                            Err(err) => last_error = Some(err),
                        }
                    }
                }
                RouteKind::P2p =>
                {
                    #[cfg(feature = "transport-webrtc")]
                    if let Some(webrtc) = &self.webrtc {
                        match webrtc.connect(session).await {
                            Ok(stream) => {
                                return Ok(SelectedRoute {
                                    route: RouteKind::P2p,
                                    stream,
                                })
                            }
                            Err(err) => last_error = Some(err),
                        }
                    }
                }
                RouteKind::Relay => {}
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
    Some(TransportPreferences { routes, stun })
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
    use tokio::runtime::Runtime;

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
}
