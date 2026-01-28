use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::{
    error::{Error, Result},
    models::*,
};

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> Result<Ble<R>> {
    Ok(Ble(app.clone()))
}

/// Desktop stub — all methods return `Error::NotAvailable`.
pub struct Ble<R: Runtime>(AppHandle<R>);

impl<R: Runtime> Ble<R> {
    pub fn start_advertising(&self, _payload: StartAdvertisingRequest) -> Result<()> {
        Err(Error::NotAvailable)
    }

    pub fn stop_advertising(&self) -> Result<()> {
        Err(Error::NotAvailable)
    }

    pub fn start_scanning(&self, _payload: StartScanningRequest) -> Result<()> {
        Err(Error::NotAvailable)
    }

    pub fn stop_scanning(&self) -> Result<()> {
        Err(Error::NotAvailable)
    }

    pub fn read_sender_info(
        &self,
        _payload: ReadSenderInfoRequest,
    ) -> Result<ReadSenderInfoResponse> {
        Err(Error::NotAvailable)
    }
}
