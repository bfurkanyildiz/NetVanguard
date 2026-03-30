use axum::Router;
use std::net::SocketAddr;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    // static/ klasöründeki dosyaları sun
    let app = Router::new()
        .fallback_service(ServeDir::new("static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("══════════════════════════════════════════");
    println!("  🛡️  NetVanguard v1.0 — Web Paneli");
    println!("  🌐  http://{}", addr);
    println!("══════════════════════════════════════════");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Port 3000 bağlanamadı!");

    axum::serve(listener, app)
        .await
        .expect("Sunucu başlatılamadı!");
}
