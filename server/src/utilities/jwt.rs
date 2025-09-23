use axum::http::StatusCode;
use chrono::Duration;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use super::app_error::AppError;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,
    pub id: i32,
}

pub fn create_token(secret: &str, id: i32) -> Result<String, AppError> {
    // add at least an hour for this timestamp
    let now = chrono::Utc::now();
    let expires_at = Duration::hours(24);
    let expires_at = now + expires_at;
    let exp = expires_at.timestamp() as usize;
    let claims = Claims { exp, id };
    let token_header = Header::default();
    let key = EncodingKey::from_secret(secret.as_bytes());

    encode(&token_header, &claims, &key).map_err(|error| {
        eprintln!("Error creating token: {:?}", error);
        AppError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "There was an error, please try again later",
        )
    })

}

pub fn validate_token(secret: &str, token: &str)  -> Result<Claims, AppError> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(jsonwebtoken::Algorithm::HS256);

    match decode::<Claims>(token, &key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(error) => {
            eprintln!("Error validating token: {:?}", error);

            let app_error = match error.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidToken
                | jsonwebtoken::errors::ErrorKind::InvalidSignature
                | jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::new(StatusCode::UNAUTHORIZED, "not authenticated!")
                }
                _ => AppError::new(StatusCode::INTERNAL_SERVER_ERROR, "Error validating token"),
            };

            Err(app_error)
        }
    }
}
