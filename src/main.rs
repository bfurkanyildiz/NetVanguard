mod models;
mod intel;
mod scanner;
mod sniffer;
mod privesc;

use crate::scanner::{handle_scan, handle_stop, handle_wifi_scan, handle_wifi_status, handle_check_env};
use crate::intel::{handle_geolocation, handle_breach, handle_metadata};
use crate::sniffer::handle_sniffer;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use colored::Colorize;
use std::net::SocketAddr;
use std::process::Command;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let nmap_ver = Command::new("nmap")
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(2).map(|v| v.to_string()))
        .unwrap_or_else(|| "Bilinmiyor".to_string());

    let banner = r#"
███╗   ██╗███████╗████████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██║██║  ██║
██║ ╚████║███████╗   ██║    ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                        
    "#;

    println!("{}", banner.bright_cyan());
    println!("    {}", "═══════════════════════════════════════════════════════════════════════════".dimmed());
    println!("    {}  {}", "🛡️  Versiyon :".bright_white().bold(), "v1.0.1".bright_green().bold());
    println!("    {}  {}", "👨‍💻 Geliştirici:".bright_white().bold(), "Baha Furkan Yıldız".bright_magenta());
    println!("    {}  {}", "⚙️  Nmap Vers :".bright_white().bold(), nmap_ver.yellow());
    println!("    {}  {}", "📊 Durum    :".bright_white().bold(), "█ ONLINE".bright_green().bold());
    println!("    {}", "═══════════════════════════════════════════════════════════════════════════".dimmed());

    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);

    let app = Router::new()
        .route("/api/scan", post(handle_scan))
        .route("/api/stop", post(handle_stop))
        .route("/api/wifi_scan", get(handle_wifi_scan))
        .route("/api/wifi_status", get(handle_wifi_status))
        .route("/api/check_env", get(handle_check_env))
        .route("/api/v1/geolocation", get(handle_geolocation))
        .route("/api/metadata", post(handle_metadata))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024))
        .route("/api/sniff", get(handle_sniffer))
        .route("/api/breach_mock", post(handle_breach))
        .fallback_service(ServeDir::new("static"))
        .layer(cors);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("Port 8080 bağlanamadı!");

    println!("\n    {}  {}", "🌐 Web Panel :".bright_white().bold(), format!("http://{}", addr).bright_cyan().bold().underline());
    println!("    {}  {}", "📡 API       :".bright_white().bold(), format!("http://{}/api/scan", addr).bright_blue());
    println!("\n    {}\n", "🚀 Dashboard hazırlanıyor ve tarayıcıda açılıyor...".bright_yellow().bold());

    let url = format!("http://{}", addr);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = open::that(&url);
    });

    axum::serve(listener, app).await.expect("Sunucu başlatılamadı!");
}
