use crate::database::models::users::{self, Entity as Users};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};

use crate::utilities::{app_error::AppError, jwt::validate_token, token_wrapper::TokenWrapper};

pub async fn require_authentication(
    State(db): State<DatabaseConnection>,
    State(token_secret): State<TokenWrapper>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    
    let header_token = if let Some(token) = headers.get("Authorization") {
        token.to_str().map_err(|error| {
            eprintln!("Error extracting token from headers: {:?}", error);
            AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Error reading token")
        })?
    } else {
        return Err(AppError::new(
            StatusCode::UNAUTHORIZED,
            "not authenticated!",
        ));
    };
    let access_token;
    if header_token.starts_with("Bearer ") {
        access_token = header_token.trim_start_matches("Bearer ").to_string();
    }else {
        access_token = header_token.to_string();
    }

    match validate_token(&token_secret.0, &access_token) {
        Ok(claims) => {
            let user = Users::find()
            .filter(users::Column::Id.eq(claims.id))
            .one(&db)
            .await
            .map_err(|error| {
                eprintln!("Error getting user by token: {:?}", error);
                AppError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "There was a problem getting your account",
                )
            })?;

            if let Some(user) = user {
                request.extensions_mut().insert(user);
            } else {
                return Err(AppError::new(
                    StatusCode::UNAUTHORIZED,
                    "You are not authorized for this",
                ));
            }
            Ok(next.run(request).await)
        }
        Err(err) => {
            return Err(err);
        }
    }   

    
}
