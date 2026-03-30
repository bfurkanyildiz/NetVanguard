use axum::{routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::process::Command;
use tower_http::services::ServeDir;

// ═══════════════════════════════════════════════════════════
//  VERİ YAPILARI
// ═══════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct ScanRequest {
    target: String,
    #[serde(default)]
    port_scan: bool,
    #[serde(default)]
    vuln_scan: bool,
    #[serde(default)]
    os_detect: bool,
    #[serde(default)]
    dns_query: bool,
}

#[derive(Serialize)]
struct ScanResponse {
    success: bool,
    target: String,
    scan_type: String,
    output: String,
}

// ═══════════════════════════════════════════════════════════
//  GİRDİ DOĞRULAMA
// ═══════════════════════════════════════════════════════════

fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("Hedef adresi boş olamaz!".into());
    }
    for ch in [';', '&', '|', '`', '$', '\n', '\r', '(', ')', '{', '}'] {
        if target.contains(ch) {
            return Err(format!("Geçersiz karakter: '{}'", ch));
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  KOMUT ÇALIŞTIRICI
// ═══════════════════════════════════════════════════════════

fn run_command(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            (output.status.success(), combined)
        }
        Err(e) => (false, format!("'{}' çalıştırılamadı: {}\nProgram sisteminizde kurulu mu kontrol edin.", program, e)),
    }
}

// ═══════════════════════════════════════════════════════════
//  ANA API HANDLER
// ═══════════════════════════════════════════════════════════

async fn handle_scan(Json(body): Json<ScanRequest>) -> Json<ScanResponse> {
    let target = body.target.trim().to_string();

    if let Err(msg) = validate_target(&target) {
        return Json(ScanResponse {
            success: false,
            target,
            scan_type: "error".into(),
            output: msg,
        });
    }

    let mut all_output = String::new();
    let mut scan_types: Vec<&str> = Vec::new();
    let mut overall_success = true;
    let any_option = body.port_scan || body.vuln_scan || body.os_detect || body.dns_query;

    // ── Hiçbir şey seçilmediyse → Ping ──
    if !any_option {
        scan_types.push("ping");
        let ping_args = if cfg!(target_os = "windows") {
            vec!["-n", "4", &target]
        } else {
            vec!["-c", "4", &target]
        };
        let (ok, out) = run_command("ping", &ping_args);
        overall_success = ok;
        all_output.push_str(&out);
    }

    // ── Port Tarama → nmap -F ──
    if body.port_scan {
        scan_types.push("port_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-F", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Zafiyet Analizi → nmap --script vuln ──
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["--script", "vuln", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── İşletim Sistemi Tespiti → nmap -O ──
    if body.os_detect {
        scan_types.push("os_detect");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-O", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── DNS Sorgulama → nslookup ──
    if body.dns_query {
        scan_types.push("dns_query");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nslookup", &[&target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    Json(ScanResponse {
        success: overall_success,
        target,
        scan_type: scan_types.join(","),
        output: all_output,
    })
}

// ═══════════════════════════════════════════════════════════
//  SUNUCU
// ═══════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/scan", post(handle_scan))
        .fallback_service(ServeDir::new("static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("══════════════════════════════════════════");
    println!("  🛡️  NetVanguard v1.0 — Web Paneli");
    println!("  🌐  http://{}", addr);
    println!("  📡  API: http://{}/api/scan", addr);
    println!("══════════════════════════════════════════");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Port 3000 bağlanamadı!");

    axum::serve(listener, app)
        .await
        .expect("Sunucu başlatılamadı!");
}
