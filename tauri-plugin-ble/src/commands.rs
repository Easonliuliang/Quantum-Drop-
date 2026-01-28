use tauri::{command, AppHandle, Runtime};

use crate::{
    error::Result,
    models::*,
    BleExt,
};

#[command]
pub(crate) async fn start_advertising<R: Runtime>(
    app: AppHandle<R>,
    payload: StartAdvertisingRequest,
) -> Result<()> {
    app.ble().start_advertising(payload)
}

#[command]
pub(crate) async fn stop_advertising<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.ble().stop_advertising()
}

#[command]
pub(crate) async fn start_scanning<R: Runtime>(
    app: AppHandle<R>,
    payload: StartScanningRequest,
) -> Result<()> {
    app.ble().start_scanning(payload)
}

#[command]
pub(crate) async fn stop_scanning<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.ble().stop_scanning()
}

#[command]
pub(crate) async fn read_sender_info<R: Runtime>(
    app: AppHandle<R>,
    payload: ReadSenderInfoRequest,
) -> Result<ReadSenderInfoResponse> {
    app.ble().read_sender_info(payload)
}
