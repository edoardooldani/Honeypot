use serde::{Deserialize, Serialize};

use crate::database::models::devices::{Status, DeviceType};
pub mod create_device;

#[derive(Serialize, Deserialize)]
pub struct ResponseDataDevice {
    data: ResponseDevice,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseDevice {
    id: i32,
    device_type: DeviceType,
    status: Status,
    user_id: i32,
    user_email: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RequestCreateDevice {
    mac_address: String,
    device_type: i32,
    status: i32
}
