use serde::{ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("BLE is not available on this platform")]
    NotAvailable,

    #[error("Bluetooth hardware is unavailable or powered off")]
    BluetoothUnavailable,

    #[error("Already advertising")]
    AlreadyAdvertising,

    #[error("Already scanning")]
    AlreadyScanning,

    #[error("GATT read failed: {0}")]
    GattReadFailed(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error(transparent)]
    Tauri(#[from] tauri::Error),

    #[cfg(mobile)]
    #[error("Plugin invoke error: {0}")]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
