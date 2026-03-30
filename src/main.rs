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
    timing: String,
    #[serde(default)]
    port_scan: bool,
    #[serde(default)]
    vuln_scan: bool,
    #[serde(default)]
    os_detect: bool,
    #[serde(default)]
    dns_query: bool,
    #[serde(default)]
    version_detect: bool,
    #[serde(default)]
    aggressive_scan: bool,
    #[serde(default)]
    net_discover: bool,
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
    let mut cmd_args = vec!["/C", program];
    cmd_args.extend_from_slice(args);
    
    let mut cmd = Command::new("cmd");
    cmd.args(&cmd_args);

    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            
            if !output.status.success() {
                (false, format!("Hata: Sistem komutu yürütülemedi\n{}", combined))
            } else {
                (true, combined)
            }
        }
        Err(e) => (false, format!("Hata: Sistem komutu yürütülemedi\nDetay: {}\n'{}' programı sisteminizde kurulu mu?", e, program)),
    }
}

// ═══════════════════════════════════════════════════════════
//  ANA API HANDLER
// ═══════════════════════════════════════════════════════════

async fn handle_scan(Json(body): Json<ScanRequest>) -> Json<ScanResponse> {
    let mut target = body.target.trim().to_string();

    // ── Akıllı Ağ Keşfi Override ──
    if body.net_discover {
        target = "192.168.1.0/24".to_string();
    }

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
    let any_option = body.port_scan || body.vuln_scan || body.os_detect || body.dns_query || body.version_detect || body.aggressive_scan || body.net_discover;

    let timing_arg = match body.timing.as_str() {
        "T0" | "T1" | "T2" | "T3" | "T4" | "T5" => format!("-{}", body.timing),
        _ => "-T3".to_string(),
    };
    let t_arg = timing_arg.as_str();

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

    // ── Ağ Keşfi ──
    if body.net_discover {
        scan_types.push("net_discover");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sn", "-Pn", "--send-ip", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Port Tarama → nmap -F -Pn ──
    if body.port_scan {
        scan_types.push("port_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sT", "-F", "-Pn", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Zafiyet Analizi → nmap --script vuln -Pn ──
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sT", "--script", "vuln", "-Pn", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── İşletim Sistemi Tespiti ──
    if body.os_detect {
        scan_types.push("os_detect");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-O", "--osscan-guess", "-Pn", "--send-ip", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Servis Versiyon Tespiti → nmap -sV -Pn --disable-arp-ping ──
    if body.version_detect {
        scan_types.push("version_detect");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sV", "-Pn", "--disable-arp-ping", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Kapsamlı Agresif Tarama → nmap -A -Pn ──
    if body.aggressive_scan {
        scan_types.push("aggressive_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-A", "-Pn", t_arg, "--host-timeout", "120s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── DNS Sorgulama ──
    if body.dns_query {
        scan_types.push("dns_query");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        
        let is_ip = target.parse::<std::net::IpAddr>().is_ok() || target.contains('/');
        let is_valid_domain = target.contains('.') && !target.contains(' ');

        if !is_ip && !is_valid_domain {
            all_output.push_str("Hata: Geçerli bir domain veya IP girin\n");
            overall_success = false;
        } else {
            let (ok, out) = if is_ip {
                run_command("nmap", &["-sL", &target])
            } else {
                run_command("nslookup", &[&target])
            };
            overall_success = overall_success && ok;
            all_output.push_str(&out);
        }
    }

    Json(ScanResponse {
        success: overall_success,
        target,
        scan_type: scan_types.join(","),
        output: all_output,
    })
}

// ═══════════════════════════════════════════════════════════
//  DURDURMA İŞLEMİ (CANCEL)
// ═══════════════════════════════════════════════════════════

async fn handle_stop() -> Json<ScanResponse> {
    let mut cmd = Command::new("cmd");
    cmd.args(&["/C", "taskkill /F /IM nmap.exe /T"]);
    
    match cmd.output() {
        Ok(_) => Json(ScanResponse {
            success: true,
            target: "".into(),
            scan_type: "stop".into(),
            output: "Nmap işlemleri zorla durduruldu.".into(),
        }),
        Err(e) => Json(ScanResponse {
            success: false,
            target: "".into(),
            scan_type: "stop".into(),
            output: format!("Durdurma hatası: {}", e),
        })
    }
}

// ═══════════════════════════════════════════════════════════
//  SUNUCU
// ═══════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/scan", post(handle_scan))
        .route("/api/stop", post(handle_stop))
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
