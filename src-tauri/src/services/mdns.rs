use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use tokio::time;

const SERVICE_TYPE: &str = "_quantumdrop._udp.local.";
const VERSION: &str = "1.0";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderInfo {
    pub code: String,
    pub device_name: String,
    pub host: String,
    pub port: u16,
    pub public_key: String,
    pub cert_fingerprint: String,
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
        public_key_hex: &str,
        cert_fingerprint: Option<&str>,
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
        props.insert("pubkey".into(), public_key_hex.into());
        if let Some(fp) = cert_fingerprint {
            props.insert("certfp".into(), fp.to_string());
        }

        let parsed_addrs: Vec<IpAddr> = addresses
            .iter()
            .filter_map(|addr| addr.parse::<IpAddr>().ok())
            .collect();
        let ip_addrs: Vec<IpAddr> = if parsed_addrs.is_empty() {
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        } else {
            parsed_addrs
        };
        let service_name = format!("quantumdrop-{}", code);
        let host_label = format!("{}.local.", service_name);

        info!(
            "[mDNS] 注册服务: code={}, service={}, host={}, ips={:?}, port={}, addresses={:?}",
            code, service_name, host_label, ip_addrs, port, addresses
        );

        let info = ServiceInfo::new(
            SERVICE_TYPE,
            &service_name,
            &host_label,
            ip_addrs.as_slice(),
            port,
            props,
        )
            .map_err(|err| {
                warn!("[mDNS] 构建 ServiceInfo 失败: {}", err);
                anyhow!("failed to build mDNS info: {err}")
            })?;

        self.daemon
            .register(info.clone())
            .map_err(|err| {
                warn!("[mDNS] 注册服务失败: {}", err);
                anyhow!("mDNS register failed: {err}")
            })?;

        info!("[mDNS] 服务注册成功: {}", info.get_fullname());

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

    pub async fn discover_sender(&self, code: &str, timeout: Duration) -> Result<SenderInfo> {
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
                                    if let Some(sender) = sender_info_from(&info, addr) {
                                        return Ok(sender);
                                    }
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
        info!("[mDNS] 开始浏览服务: type={}, timeout={:?}", SERVICE_TYPE, timeout);

        // Get our own registered codes to filter them out
        let own_codes: Vec<String> = {
            let guard = self.registered.lock().await;
            guard.keys().cloned().collect()
        };
        info!("[mDNS] 本机已注册的配对码: {:?}", own_codes);

        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|err| {
                warn!("[mDNS] 浏览服务失败: {}", err);
                anyhow!("mDNS browse failed: {err}")
            })?;

        let timer = time::sleep(timeout);
        tokio::pin!(timer);
        let mut list = Vec::new();
        let mut event_count = 0;

        loop {
            tokio::select! {
                _ = &mut timer => {
                    info!("[mDNS] 浏览超时，共收到 {} 个事件，发现 {} 个设备（过滤本机后）", event_count, list.len());
                    break;
                }
                event = receiver.recv_async() => {
                    event_count += 1;
                    match event {
                        Ok(ServiceEvent::ServiceResolved(info)) => {
                            debug!("[mDNS] ServiceResolved: fullname={}, addresses={:?}, port={}",
                                info.get_fullname(), info.get_addresses(), info.get_port());
                            if let Some(addr) = pick_addr(&info) {
                                if let Some(dto) = sender_info_from(&info, addr) {
                                    // Filter out our own registered services
                                    if own_codes.contains(&dto.code) {
                                        debug!("[mDNS] 跳过本机服务: code={}", dto.code);
                                        continue;
                                    }
                                    info!("[mDNS] 发现远程设备: code={}, name={}, host={}:{}",
                                        dto.code, dto.device_name, dto.host, dto.port);
                                    list.push(dto);
                                } else {
                                    debug!("[mDNS] 无法解析 SenderInfo，可能缺少必要属性");
                                }
                            } else {
                                debug!("[mDNS] 无法获取有效地址");
                            }
                        }
                        Ok(ServiceEvent::ServiceFound(svc_type, fullname)) => {
                            debug!("[mDNS] ServiceFound: type={}, name={}", svc_type, fullname);
                        }
                        Ok(ServiceEvent::ServiceRemoved(svc_type, fullname)) => {
                            debug!("[mDNS] ServiceRemoved: type={}, name={}", svc_type, fullname);
                        }
                        Ok(ServiceEvent::SearchStarted(svc_type)) => {
                            debug!("[mDNS] SearchStarted: type={}", svc_type);
                        }
                        Ok(ServiceEvent::SearchStopped(svc_type)) => {
                            debug!("[mDNS] SearchStopped: type={}", svc_type);
                        }
                        Err(err) => {
                            warn!("[mDNS] 接收事件错误: {:?}", err);
                            break;
                        }
                    }
                }
            }
        }
        Ok(list)
    }
}

fn pick_addr(info: &ServiceInfo) -> Option<IpAddr> {
    // Prefer real LAN IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    // Skip VPN/virtual interfaces like 198.18.x.x
    let is_preferred_lan = |addr: &IpAddr| -> bool {
        if let IpAddr::V4(v4) = addr {
            let octets = v4.octets();
            // 192.168.x.x - most common home/office LAN
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 10.x.x.x - private network
            if octets[0] == 10 {
                return true;
            }
            // 172.16.x.x - 172.31.x.x - private network
            if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
                return true;
            }
        }
        false
    };

    let is_vpn_or_virtual = |addr: &IpAddr| -> bool {
        if let IpAddr::V4(v4) = addr {
            let octets = v4.octets();
            // 198.18.x.x / 198.19.x.x - benchmarking, often used by VPN/proxy
            if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                return true;
            }
            // 100.64.x.x - 100.127.x.x - Carrier-grade NAT
            if octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127 {
                return true;
            }
        }
        false
    };

    let addrs: Vec<IpAddr> = info.get_addresses().iter().cloned().collect();

    // First try: preferred LAN IPs
    if let Some(addr) = addrs.iter().find(|a| is_preferred_lan(a) && !a.is_loopback()) {
        return Some(*addr);
    }

    // Second try: any non-loopback, non-VPN address
    if let Some(addr) = addrs.iter().find(|a| !a.is_loopback() && !is_vpn_or_virtual(a)) {
        return Some(*addr);
    }

    // Fallback: any non-loopback
    addrs.iter().find(|a| !a.is_loopback()).cloned()
}

fn sender_info_from(info: &ServiceInfo, addr: IpAddr) -> Option<SenderInfo> {
    let code = info.get_property_val_str("code")?.to_string();
    let device_name = info
        .get_property_val_str("device")
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".into());
    let public_key = info.get_property_val_str("pubkey").map(|s| s.to_string())?;
    let cert_fingerprint = info
        .get_property_val_str("certfp")
        .map(|s| s.to_string())
        .unwrap_or_default();
    Some(SenderInfo {
        code,
        device_name,
        host: addr.to_string(),
        port: info.get_port(),
        public_key,
        cert_fingerprint,
    })
}
