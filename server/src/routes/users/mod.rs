use serde::{Deserialize, Serialize};

pub mod create_user;
pub mod login;
pub mod logout;

#[derive(Serialize, Deserialize)]
pub struct ResponseDataUser {
    data: ResponseUser,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseUser {
    id: i32,
    email: String,
    token: String,
}

#[derive(Serialize, Deserialize)]
pub struct RequestCreateUser {
    email: String,
    password: String,
}
