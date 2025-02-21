diesel::table! {
    users (id) {
        id -> Integer,
        email -> Varchar,
        password_hash -> Varchar,
    }
}
