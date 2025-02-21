use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST}; 
use diesel::Queryable; 
use diesel::Insertable;  
use crate::schema::users;


#[derive(Queryable, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct NewUser<'a> {
    pub email: &'a str,
    pub password_hash: String,
}

impl User {
    pub fn verify_password(&self, password: &str) -> bool {
        verify(password, &self.password_hash).unwrap_or(false)
    }
}

impl<'a> NewUser<'a> {
    pub fn new(email: &'a str, password: &'a str) -> NewUser<'a> {
        let password_hash = hash(password, DEFAULT_COST).unwrap();
        NewUser {
            email,
            password_hash,
        }
    }
}