use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use diesel::mysql::MysqlConnection;

pub fn establish_connection() -> MysqlConnection {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL not found in .env");

    MysqlConnection::establish(&database_url)
        .expect(&format!("Database connection error {}", database_url))
}