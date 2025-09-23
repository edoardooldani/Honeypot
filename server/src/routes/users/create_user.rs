use super::{RequestCreateUser, ResponseDataUser, ResponseUser};
use crate::queries::user_queries;
use crate::{
    database::models::users,
    utilities::{
        app_error::AppError, hash::hash_password,
    },
};
use axum::{extract::State, Json};
use sea_orm::{DatabaseConnection, Set};

pub async fn create_user(
    State(db): State<DatabaseConnection>,
    Json(request_user): Json<RequestCreateUser>,
) -> Result<Json<ResponseDataUser>, AppError> {
    let mut new_user = users::ActiveModel {
        ..Default::default()
    };
    new_user.email = Set(request_user.email.clone());
    new_user.password = Set(hash_password(&request_user.password)?);
    let user = user_queries::save_active_user(&db, new_user).await?;

    Ok(Json(ResponseDataUser {
        data: ResponseUser {
            id: user.id,
            email: user.email,
            token: user.token.unwrap(),
        },
    }))
}

