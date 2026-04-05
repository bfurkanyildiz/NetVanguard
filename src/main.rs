mod intel;
mod models;
mod privesc;
mod scanner;
mod sniffer;

use crate::intel::{handle_breach, handle_geolocation, handle_metadata};
use crate::scanner::{
    handle_check_env, handle_scan, handle_stop, handle_wifi_scan, handle_wifi_status,
};
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

/// # Summary
/// Entry point for the NetVanguard backend engine.
/// Initializes the Axum web server, configures CORS policies, registers API routes,
/// and orchestrates the lifecycle of background scanning tasks.
///
/// # Environment Setup
/// * Detects Nmap presence and version for the dashboard banner.
/// * Binds a TCP listener to address 0.0.0.0:8080 for cross-device access within the local mesh.
/// * Automatically launches the operator's browser to the dashboard URL.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ═══════════════════════════════════════════════════════════
    //  STEP 0: Port Protection & Cleanup
    // ═══════════════════════════════════════════════════════════
    ensure_port_is_free(8080).await;

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
    println!(
        "    {}",
        "═══════════════════════════════════════════════════════════════════════════".dimmed()
    );
    println!(
        "    {}  {}",
        "🛡️  Versiyon :".bright_white().bold(),
        "v1.0.1".bright_green().bold()
    );
    println!(
        "    {}  {}",
        "👨‍💻 Geliştirici:".bright_white().bold(),
        "Baha Furkan Yıldız".bright_magenta()
    );
    println!(
        "    {}  {}",
        "⚙️  Nmap Vers :".bright_white().bold(),
        nmap_ver.yellow()
    );
    println!(
        "    {}  {}",
        "📊 Durum    :".bright_white().bold(),
        "█ ONLINE".bright_green().bold()
    );
    println!(
        "    {}",
        "═══════════════════════════════════════════════════════════════════════════".dimmed()
    );

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

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

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!(
        "\n    {}  {}",
        "🌐 Web Panel :".bright_white().bold(),
        format!("http://{}", addr).bright_cyan().bold().underline()
    );
    println!(
        "    {}  {}",
        "📡 API       :".bright_white().bold(),
        format!("http://{}/api/scan", addr).bright_blue()
    );
    println!(
        "\n    {}\n",
        "🚀 Dashboard hazırlanıyor ve tarayıcıda açılıyor..."
            .bright_yellow()
            .bold()
    );

    let url = format!("http://{}", addr);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = open::that(&url);
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// # Summary
/// Detects if a specific TCP port is already in use by another process.
/// If a conflict is found, it automatically identifies the PID and terminates the process.
/// Supports both Windows (netstat/taskkill) and Linux (fuser) environments.
async fn ensure_port_is_free(port: u16) {
    println!(
        "    {} {}",
        "🔍".bright_yellow(),
        format!("Port {} kontrol ediliyor...", port).dimmed()
    );

    if cfg!(target_os = "windows") {
        // Windows: netstat -ano | findstr :8080
        let output = Command::new("cmd")
            .args([
                "/C",
                &format!("netstat -ano | findstr :{} | findstr LISTENING", port),
            ])
            .output();

        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(pid_str) = parts.last() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        println!(
                            "    {} {}",
                            "💀".bright_red(),
                            format!("Eski NetVanguard süreci (PID: {}) temizleniyor...", pid).red()
                        );
                        let _ = Command::new("taskkill")
                            .args(["/F", "/PID", &pid.to_string()])
                            .output();
                    }
                }
            }
        }
    } else {
        // Linux: fuser -k 8080/tcp
        let _ = Command::new("sudo")
            .args(["-n", "fuser", "-k", &format!("{}/tcp", port)])
            .output();
    }

    // Give the OS a moment to fully release the socket
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

/// # Summary
/// Listens for a termination signal (Ctrl+C).
/// Triggers a graceful shutdown sequence to ensure all scanning tasks are stopped properly.
async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Sinyal yakalayıcı başlatılamadı");

    println!(
        "\n    {} {}",
        "🛑".bright_red(),
        "Kapatma sinyali alındı. Süreçler sonlandırılıyor..."
            .bright_red()
            .bold()
    );

    // Call handle_stop logic indirectly or trigger global cleanup
    let _ = crate::scanner::handle_stop().await;
}
