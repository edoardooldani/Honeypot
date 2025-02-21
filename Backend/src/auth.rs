use std::env;
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use axum::Json;
use crate::models::{User, NewUser};
use crate::conn::establish_connection;
use crate::schema::users::dsl::{users, email};
use diesel::prelude::*;

#[derive(Serialize, Deserialize)]

pub enum Role {
    User,
    Device,
}


#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub email: String,
    pub role: Role,
    pub exp: usize,
}


#[derive(Deserialize)]
pub struct LoginData {
    pub email: String,
    pub password: String,
}


pub fn generate_jwt(user: &User) -> String {
    let claims = Claims {
        email: user.email.clone(),
        role: Role::User,
        exp: 10000000000,
    };
    let secret_key = env::var("AUTH_SECRET_KEY").expect("AUTH_SECRET_KEY non trovata nel file .env");

    let encoding_key = EncodingKey::from_secret(secret_key.as_ref());
    encode(&Header::default(), &claims, &encoding_key).unwrap()

}

pub async fn register(Json(payload): Json<LoginData>) -> Result<String, &'static str> {

    let conn = establish_connection();
    let existing_user: Option<User> = users
        .filter(email.eq(&payload.email))
        .first(&conn)
        .optional()
        .expect("Errore nel recupero dell'utente");

    if let Some(_) = existing_user {
        return Err("This email is already in use!");
    }

    let new_user = NewUser::new(&payload.email, &payload.password);

    diesel::insert_into(users)
        .values(&new_user)
        .execute(&conn)
        .expect("Errore nell'inserimento del nuovo utente");

    Ok("User registered successfully".to_string())
}


pub async fn login(Json(payload): Json<LoginData>) -> Result<String, &'static str> {

    let conn = establish_connection();
    let user: Option<User> = users
        .filter(email.eq(&payload.email)) // Usa 'payload' invece di 'login'
        .first(&conn)
        .optional()
        .expect("Errore nel recupero dell'utente");

    match user {
        Some(user) if user.verify_password(&payload.password) => {
            Ok(generate_jwt(&user))
        }
        _ => Err("Wrong email or password"),
    }
}