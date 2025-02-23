use crate::{
    database::{
        devices::Model as DeviceModel,
        devices::{self},
    },
    utilities::app_error::AppError,
};
use axum::http::StatusCode;
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, TryIntoModel,
};



pub async fn save_active_device(
    db: &DatabaseConnection,
    device: devices::ActiveModel,
) -> Result<DeviceModel, AppError> {
    let device = device.save(db).await.map_err(|error| {
        let error_message = error.to_string();

        if error_message
            .contains("duplicate key value violates unique constraint \"device_key\"")
        {
            AppError::new(
                StatusCode::BAD_REQUEST,
                "Device already registered",
            )
        } else {
            eprintln!("Error creating user: {:?}", error_message);
            AppError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong, please try again",
            )
        }
    })?;

    convert_active_to_model(device)
}

fn convert_active_to_model(active_device: devices::ActiveModel) -> Result<DeviceModel, AppError> {
    active_device.try_into_model().map_err(|error| {
        eprintln!("Error converting task active model to model: {:?}", error);
        AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    })
}

