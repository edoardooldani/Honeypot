use crate::{
    app_state::AppState,
    middleware::require_authentication::require_authentication,
    routes::users::{create_user::create_user, login::login, logout::logout},
    routes::devices::create_device::create_device,

};
use axum::{
    middleware,
    routing::post,//{delete, get, patch, post, put},
    Router,
};

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/api/auth/logout", post(logout))
        .route("/api/device/register", post(create_device))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_authentication,
        ))
        .route("/api/auth/signup", post(create_user))
        .route("/api/auth/signin", post(login))
        .with_state(app_state)
}
