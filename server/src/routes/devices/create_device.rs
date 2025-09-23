use super::{RequestCreateDevice, ResponseDataDevice, ResponseDevice};
use crate::database::models::users;
use crate::queries::device_queries;
use crate::{
    database::models::devices,
    utilities::app_error::AppError
    
};
use axum::{extract::{State, Extension}, Json};
use sea_orm::{DatabaseConnection, Set};
use devices::{DeviceType, Status};

pub async fn create_device(
    State(db): State<DatabaseConnection>,
    //State(token_secret): State<TokenWrapper>,
    Extension(user): Extension<users::Model>,
    Json(request_device): Json<RequestCreateDevice>,
) -> Result<Json<ResponseDataDevice>, AppError> {
    let mut new_device = devices::ActiveModel {
        ..Default::default()
    };

    new_device.user_id = Set(user.id);
    new_device.mac_address = Set(request_device.mac_address.clone());
    new_device.device_type = Set(request_device.device_type.clone());
    new_device.status = Set(request_device.status.clone());
    let device = device_queries::save_active_device(&db, new_device).await?;

    Ok(Json(ResponseDataDevice {
        data: ResponseDevice {
            id: device.id,
            device_type: DeviceType::from(device.device_type),
            status: Status::from(device.status),
            user_id: user.id,
            user_email: user.email,
        },
    }))
}

