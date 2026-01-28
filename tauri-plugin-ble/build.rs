const COMMANDS: &[&str] = &[
    "start_advertising",
    "stop_advertising",
    "start_scanning",
    "stop_scanning",
    "read_sender_info",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
