use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::time;

const SERVICE_TYPE: &str = "_quantumdrop._udp.local.";
const VERSION: &str = "1.0";

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderInfo {
    pub code: String,
    pub device_name: String,
    pub host: String,
    pub port: u16,
}

pub struct MdnsRegistry {
    daemon: ServiceDaemon,
    registered: tokio::sync::Mutex<HashMap<String, ServiceInfo>>,
}

impl MdnsRegistry {
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new().context("failed to start mDNS daemon")?;
        Ok(Self {
            daemon,
            registered: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    pub async fn register_sender(
        &self,
        code: &str,
        task_id: &str,
        port: u16,
        addresses: &[String],
        device_name: Option<String>,
    ) -> Result<()> {
        let mut props = HashMap::new();
        props.insert("code".into(), code.to_string());
        props.insert("task_id".into(), task_id.to_string());
        props.insert(
            "device".into(),
            device_name.clone().unwrap_or_else(|| "unknown".into()),
        );
        if !addresses.is_empty() {
            props.insert("addr_list".into(), addresses.join(","));
        }
        props.insert("version".into(), VERSION.into());

        let ip = addresses
            .iter()
            .filter_map(|addr| addr.parse::<IpAddr>().ok())
            .next()
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let service_name = format!("quantumdrop-{}", code);
        let host_label = format!("{}.local.", service_name);

        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &service_name,
            &host_label,
            ip,
            port,
            props,
        )
        .map_err(|err| anyhow!("failed to build mDNS info: {err}"))?;

        self.daemon
            .register(info.clone())
            .map_err(|err| anyhow!("mDNS register failed: {err}"))?;

        let mut guard = self.registered.lock().await;
        guard.insert(code.to_string(), info);
        Ok(())
    }

    pub async fn unregister(&self, code: &str) -> Result<()> {
        let mut guard = self.registered.lock().await;
        if let Some(info) = guard.remove(code) {
            self.daemon
                .unregister(info.get_fullname())
                .map_err(|err| anyhow!("mDNS unregister failed: {err}"))?;
        }
        Ok(())
    }

    pub async fn discover_sender(&self, code: &str, timeout: Duration) -> Result<SocketAddr> {
        let target = format!("quantumdrop-{}", code);
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|err| anyhow!("mDNS browse failed: {err}"))?;
        let timer = time::sleep(timeout);
        tokio::pin!(timer);
        loop {
            tokio::select! {
                _ = &mut timer => {
                    return Err(anyhow!("Timeout: sender with code '{code}' not found"));
                }
                event = receiver.recv_async() => {
                    match event {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            if info.get_fullname().starts_with(&target) {
                                if let Some(addr) = pick_addr(&info) {
                                    return Ok(SocketAddr::new(addr, info.get_port()));
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(err) => return Err(anyhow!("mDNS receive failed: {err}")),
                    }
                }
            }
        }
    }

    pub async fn list_senders(&self, timeout: Duration) -> Result<Vec<SenderInfo>> {
        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|err| anyhow!("mDNS browse failed: {err}"))?;
        let timer = time::sleep(timeout);
        tokio::pin!(timer);
        let mut list = Vec::new();
        loop {
            tokio::select! {
                _ = &mut timer => break,
                event = receiver.recv_async() => {
                    match event {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            if let Some(addr) = pick_addr(&info) {
                                if let Some(dto) = sender_info_from(&info, addr) {
                                    list.push(dto);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        }
        Ok(list)
    }
}

fn pick_addr(info: &ServiceInfo) -> Option<IpAddr> {
    info.get_addresses()
        .iter()
        .cloned()
        .find(|addr| !addr.is_loopback())
        .or_else(|| info.get_addresses().iter().cloned().next())
}

fn sender_info_from(info: &ServiceInfo, addr: IpAddr) -> Option<SenderInfo> {
    let code = info.get_property_val_str("code")?.to_string();
    let device_name = info
        .get_property_val_str("device")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".into());
    Some(SenderInfo {
        code,
        device_name,
        host: addr.to_string(),
        port: info.get_port(),
    })
}
