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
        let preferred = read_preferred_routes(app);
        Self::new(preferred)
    }

    pub fn new(preferred: Vec<RouteKind>) -> Self {
        let mut routes = if preferred.is_empty() {
            vec![RouteKind::Lan, RouteKind::P2p, RouteKind::Relay]
        } else {
            preferred
        };
        if routes.iter().all(|route| route != &RouteKind::MockLocal) {
            routes.push(RouteKind::MockLocal);
        }

        Router {
            preferred: routes,
            mock: MockLocalAdapter::new(),
            #[cfg(feature = "transport-quic")]
            quic: QuicAdapter::new().ok(),
            #[cfg(feature = "transport-webrtc")]
            webrtc: Some(WebRtcAdapter::default()),
        }
    }

    pub fn preferred_routes(&self) -> &[RouteKind] {
        &self.preferred
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

fn read_preferred_routes(app: &AppHandle) -> Vec<RouteKind> {
    if let Some(routes) = read_routes_from_app_yaml(app) {
        return routes;
    }
    if let Ok(value) = serde_json::to_value(app.config()) {
        return extract_preferred_routes(&value);
    }
    Vec::new()
}

fn extract_preferred_routes(config: &Value) -> Vec<RouteKind> {
    let pointer = "/app/s2/transport/preferredRoutes";
    let mut routes = Vec::new();
    if let Some(values) = config.pointer(pointer).and_then(|value| value.as_array()) {
        for value in values {
            if let Some(route_str) = value.as_str() {
                if let Some(route) = parse_route(route_str) {
                    routes.push(route);
                }
            }
        }
    }
    routes
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

fn read_routes_from_app_yaml(app: &AppHandle) -> Option<Vec<RouteKind>> {
    let mut path = app.path().app_config_dir().ok()?;
    path.push("app.yaml");
    let contents = fs::read_to_string(path).ok()?;
    let parsed: AppYaml = serde_yaml::from_str(&contents).ok()?;
    let routes = parsed
        .s2
        .and_then(|s2| s2.transport)
        .map(|transport| transport.preferred_routes)
        .unwrap_or_default();
    Some(
        routes
            .into_iter()
            .filter_map(|value| parse_route(&value))
            .collect(),
    )
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
            let session = SessionDesc {
                session_id: "router-quic".into(),
            };
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
}
