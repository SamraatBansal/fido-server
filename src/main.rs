//! FIDO Server Main Entry Point

mod simple_server;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    simple_server::create_simple_server().await
}
