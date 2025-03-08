use axum::extract::FromRef;
use sea_orm::DatabaseConnection;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

use crate::utilities::token_wrapper::TokenWrapper;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: DatabaseConnection,
    pub jwt_secret: TokenWrapper,
}
/* 
#[derive(Clone, FromRef)]
pub struct WssAppState {
    pub device_name: String,
    pub session_id: u32,
}*/

#[derive(Clone)]
pub struct WssAppState {
    pub connections: Arc<Mutex<HashMap<String, u32>>>,
}
