use axum::extract::FromRef;
use influxdb2::Client;
use rdkafka::{consumer::StreamConsumer, producer::FutureProducer};
use sea_orm::DatabaseConnection;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
//use rdkafka::producer::FutureProducer;


use crate::utilities::token_wrapper::TokenWrapper;

#[derive(Clone, FromRef)]
pub struct ApiAppState {
    pub db: DatabaseConnection,
    pub jwt_secret: TokenWrapper,
}


#[derive(Clone)]
pub struct WssAppState {
    pub connections: Arc<Mutex<HashMap<String, u32>>>,
    pub influx_client: Client,
}