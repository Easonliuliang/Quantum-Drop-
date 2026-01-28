use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartAdvertisingRequest {
    pub service_data: Vec<u8>,
    pub sender_info_json: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartScanningRequest {
    pub target_code_hash: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadSenderInfoRequest {
    pub device_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadSenderInfoResponse {
    pub sender_info_json: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BleDeviceFoundEvent {
    pub device_id: String,
    pub code_hash: Vec<u8>,
    pub rssi: i32,
    pub matched: bool,
}
