use std::time::Duration;

use anyhow::Result;
use tauri::AppHandle;

use super::mdns::{MdnsRegistry, SenderInfo};

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    Mdns,
    Ble,
}

pub struct DiscoveryResult {
    pub source: DiscoverySource,
    pub sender: SenderInfo,
}

pub struct DiscoveryService {
    mdns: MdnsRegistry,
    app: AppHandle,
}

impl DiscoveryService {
    pub fn new(mdns: MdnsRegistry, app: AppHandle) -> Self {
        Self { mdns, app }
    }

    pub fn mdns(&self) -> &MdnsRegistry {
        &self.mdns
    }

    pub fn app(&self) -> &AppHandle {
        &self.app
    }

    pub async fn discover_by_code(
        &self,
        code: &str,
        timeout: Duration,
    ) -> Result<DiscoveryResult> {
        #[cfg(feature = "transport-ble")]
        {
            self.discover_racing_ble(code, timeout).await
        }
        #[cfg(not(feature = "transport-ble"))]
        {
            let sender = self.mdns.discover_sender(code, timeout).await?;
            Ok(DiscoveryResult {
                source: DiscoverySource::Mdns,
                sender,
            })
        }
    }

    /// Race mDNS and BLE discovery. If one source fails, fall back to the other.
    #[cfg(feature = "transport-ble")]
    async fn discover_racing_ble(
        &self,
        code: &str,
        timeout: Duration,
    ) -> Result<DiscoveryResult> {
        use futures::future::{self, Either};

        let mdns_fut = Box::pin(self.mdns.discover_sender(code, timeout));
        let ble_fut = Box::pin(self.ble_discover(code, timeout));

        match future::select(mdns_fut, ble_fut).await {
            // mDNS finished first
            Either::Left((mdns_result, ble_fut)) => match mdns_result {
                Ok(sender) => {
                    // mDNS won — stop any in-flight BLE scan
                    self.ble_cleanup();
                    Ok(DiscoveryResult {
                        source: DiscoverySource::Mdns,
                        sender,
                    })
                }
                Err(mdns_err) => {
                    // mDNS failed, wait for BLE
                    log::debug!("mDNS discovery failed ({mdns_err}), waiting for BLE");
                    match ble_fut.await {
                        Ok(result) => Ok(result),
                        Err(ble_err) => {
                            Err(mdns_err.context(format!("BLE also failed: {ble_err}")))
                        }
                    }
                }
            },
            // BLE finished first
            Either::Right((ble_result, mdns_fut)) => match ble_result {
                Ok(result) => Ok(result),
                Err(ble_err) => {
                    // BLE failed (e.g. NotAvailable on desktop), wait for mDNS
                    log::debug!("BLE discovery failed ({ble_err}), waiting for mDNS");
                    let sender = mdns_fut.await.map_err(|mdns_err| {
                        mdns_err.context(format!("BLE also failed: {ble_err}"))
                    })?;
                    Ok(DiscoveryResult {
                        source: DiscoverySource::Mdns,
                        sender,
                    })
                }
            },
        }
    }

    /// Attempt BLE discovery: scan → wait for device-found event → GATT read → parse SenderInfo.
    #[cfg(feature = "transport-ble")]
    async fn ble_discover(&self, code: &str, timeout: Duration) -> Result<DiscoveryResult> {
        use tauri::Listener;
        use tauri_plugin_ble::{BleDeviceFoundEvent, BleExt, ReadSenderInfoRequest, StartScanningRequest};

        use crate::services::ble_protocol::compute_code_hash;

        let code_hash = compute_code_hash(code);
        let code_owned = code.to_string();

        // Start BLE scanning with the target code hash
        self.app
            .ble()
            .start_scanning(StartScanningRequest {
                target_code_hash: code_hash.to_vec(),
            })
            .map_err(|e| anyhow::anyhow!("BLE scan start failed: {e}"))?;

        // Channel to receive candidate device IDs from the event listener
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BleDeviceFoundEvent>(16);

        let listener_id = {
            let tx = tx.clone();
            self.app.listen("device-found", move |event| {
                if let Ok(found) =
                    serde_json::from_str::<BleDeviceFoundEvent>(event.payload())
                {
                    // Forward matched events (Android) or unverified events (iOS, empty code_hash)
                    if found.matched || found.code_hash.is_empty() {
                        let _ = tx.try_send(found);
                    }
                }
            })
        };
        // Drop our copy so the channel closes when the listener is removed
        drop(tx);

        let deadline = tokio::time::Instant::now() + timeout;
        let result = async {
            while let Ok(Some(found)) =
                tokio::time::timeout_at(deadline, rx.recv()).await
            {
                // Try GATT read to get full SenderInfo
                let app = self.app.clone();
                let device_id = found.device_id.clone();

                let read_result = tokio::task::spawn_blocking(move || {
                    app.ble().read_sender_info(ReadSenderInfoRequest { device_id })
                })
                .await;

                match read_result {
                    Ok(Ok(response)) => {
                        match crate::services::ble_protocol::decode_sender_info(
                            &response.sender_info_json,
                        ) {
                            Ok(sender_info) if sender_info.code == code_owned => {
                                return Ok(DiscoveryResult {
                                    source: DiscoverySource::Ble,
                                    sender: sender_info,
                                });
                            }
                            Ok(_) => {
                                log::debug!(
                                    "BLE device {} code mismatch, continuing scan",
                                    found.device_id
                                );
                            }
                            Err(e) => {
                                log::debug!(
                                    "BLE device {} sender info parse error: {e}",
                                    found.device_id
                                );
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        log::debug!("BLE device {} GATT read failed: {e}", found.device_id);
                    }
                    Err(e) => {
                        log::debug!("BLE GATT read task panicked: {e}");
                    }
                }
            }

            Err(anyhow::anyhow!("BLE discovery timed out"))
        }
        .await;

        // Cleanup: remove listener and stop scanning
        self.app.unlisten(listener_id);
        let _ = self.app.ble().stop_scanning();

        result
    }

    /// Stop any running BLE scan (best-effort, ignores errors).
    #[cfg(feature = "transport-ble")]
    fn ble_cleanup(&self) {
        use tauri_plugin_ble::BleExt;
        let _ = self.app.ble().stop_scanning();
    }

    pub async fn list_senders(&self, timeout: Duration) -> Result<Vec<DiscoveryResult>> {
        let list = self.mdns.list_senders(timeout).await?;
        Ok(list
            .into_iter()
            .map(|s| DiscoveryResult {
                source: DiscoverySource::Mdns,
                sender: s,
            })
            .collect())
    }
}
