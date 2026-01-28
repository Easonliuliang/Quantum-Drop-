use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use error::{Error, Result};
pub use models::*;

mod commands;
mod error;
mod models;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

#[cfg(desktop)]
use desktop::Ble;
#[cfg(mobile)]
use mobile::Ble;

/// Extensions to [`tauri::AppHandle`] providing convenient access to the BLE plugin.
pub trait BleExt<R: Runtime> {
    fn ble(&self) -> &Ble<R>;
}

impl<R: Runtime, T: Manager<R>> BleExt<R> for T {
    fn ble(&self) -> &Ble<R> {
        self.state::<Ble<R>>().inner()
    }
}

/// Initialise the BLE plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("ble")
        .invoke_handler(tauri::generate_handler![
            commands::start_advertising,
            commands::stop_advertising,
            commands::start_scanning,
            commands::stop_scanning,
            commands::read_sender_info,
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let ble = mobile::init(app, api)?;
            #[cfg(desktop)]
            let ble = desktop::init(app, api)?;
            app.manage(ble);
            Ok(())
        })
        .build()
}
