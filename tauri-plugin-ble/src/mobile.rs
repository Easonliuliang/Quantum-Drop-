use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::{
    error::Result,
    models::*,
};

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_ble);

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "com.aetheros.quantumdrop.ble";

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> Result<Ble<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "BlePlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_ble)?;

    Ok(Ble(handle))
}

/// Mobile implementation — delegates to native code via `PluginHandle`.
pub struct Ble<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Ble<R> {
    pub fn start_advertising(&self, payload: StartAdvertisingRequest) -> Result<()> {
        self.0
            .run_mobile_plugin("startAdvertising", payload)
            .map_err(Into::into)
    }

    pub fn stop_advertising(&self) -> Result<()> {
        self.0
            .run_mobile_plugin("stopAdvertising", ())
            .map_err(Into::into)
    }

    pub fn start_scanning(&self, payload: StartScanningRequest) -> Result<()> {
        self.0
            .run_mobile_plugin("startScanning", payload)
            .map_err(Into::into)
    }

    pub fn stop_scanning(&self) -> Result<()> {
        self.0
            .run_mobile_plugin("stopScanning", ())
            .map_err(Into::into)
    }

    pub fn read_sender_info(
        &self,
        payload: ReadSenderInfoRequest,
    ) -> Result<ReadSenderInfoResponse> {
        self.0
            .run_mobile_plugin("readSenderInfo", payload)
            .map_err(Into::into)
    }
}
