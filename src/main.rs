use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use axum_keycloak_auth::{
    decode::KeycloakToken,
    expect_role,
    instance::{KeycloakAuthInstance, KeycloakConfig},
    layer::KeycloakAuthLayer,
    PassthroughMode, Url,
};
use serde_json::json;
use tracing::info;
use tracing_subscriber::fmt::time::LocalTime;

#[tokio::main]
async fn main() -> Result<(), axum::BoxError> {
    dotenv::dotenv().ok();

    init_tracing();

    let keycloak_auth_instance = KeycloakAuthInstance::new(
        KeycloakConfig::builder()
            .server(Url::parse("http://localhost:8080/").unwrap())
            .realm(String::from("my_realm"))
            .build(),
    );
    let router = public_router().merge(protected_router(keycloak_auth_instance));

    let addr_and_port = String::from("0.0.0.0:4443");
    let socket_addr: std::net::SocketAddr = addr_and_port.parse().unwrap();

    info!("Listening on {}", addr_and_port);

    let tcp_listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();
    axum::serve(tcp_listener, router.into_make_service())
        .await
        .unwrap();

    Ok(())
}

fn init_tracing() {
    let local_timer = LocalTime::new(time::macros::format_description!(
        "[year]-[month]-[day] [hour]:[minute]:[second]"
    ));

    tracing_subscriber::fmt()
        .with_timer(local_timer)
        .with_target(true)
        .init();
}

pub fn public_router() -> Router {
    Router::new().route("/health", get(health))
}

pub fn protected_router(instance: KeycloakAuthInstance) -> Router {
    Router::new().route("/protected", get(protected)).layer(
        KeycloakAuthLayer::<String>::builder()
            .instance(instance)
            .passthrough_mode(PassthroughMode::Block)
            .persist_raw_claims(false)
            .expected_audiences(vec![String::from("account")])
            .required_roles(vec![String::from("read")])
            .build(),
    )
}

pub async fn health() -> impl IntoResponse {
    info!("Public Router Called");
    (
        StatusCode::OK,
        Json(json!({
            "status": 200,
            "ts": "11-12-2024"
        })),
    )
}

pub async fn protected(Extension(token): Extension<KeycloakToken<String>>) -> Response {
    expect_role!(&token, "read");

    tracing::info!("Token payload is {token:#?}");
    (
        StatusCode::OK,
        Json(json!({
            "roles": token.roles
        })),
    )
        .into_response()
}
