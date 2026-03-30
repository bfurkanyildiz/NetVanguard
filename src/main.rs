use axum::{routing::{get, post}, Json, Router};
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

#[derive(Serialize)]
struct EnvCheckResponse {
    nmap: bool,
    version: Option<String>,
    root: bool,
    os: String,
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
//  PRE-CHECK SİSTEMİ
// ═══════════════════════════════════════════════════════════

async fn handle_check_env() -> Json<EnvCheckResponse> {
    let os_type = if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else {
        "Linux".to_string()
    };

    // Check if nmap is installed and get version
    let mut nmap_version = None;
    let nmap_installed = if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("cmd").args(&["/C", "nmap", "--version"]).output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    nmap_version = Some(line.replace("Nmap version ", "").to_string());
                }
                true
            } else { false }
        } else { false }
    } else {
        if let Ok(output) = Command::new("nmap").arg("--version").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    nmap_version = Some(line.replace("Nmap version ", "").to_string());
                }
                true
            } else { false }
        } else { false }
    };

    // Check if running as admin/root
    let is_admin = if cfg!(target_os = "windows") {
        // 'net session' only successful when run as Admin
        Command::new("cmd").args(&["/C", "net session"]).output()
            .map(|output| output.status.success()).unwrap_or(false)
    } else {
        // checking if uid is 0
        Command::new("id").arg("-u").output()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                stdout == "0"
            }).unwrap_or(false)
    };

    Json(EnvCheckResponse {
        nmap: nmap_installed,
        version: nmap_version,
        root: is_admin,
        os: os_type,
    })
}

// ═══════════════════════════════════════════════════════════
//  KOMUT ÇALIŞTIRICI
// ═══════════════════════════════════════════════════════════

fn run_command(program: &str, args: &[&str]) -> (bool, String) {
    let mut cmd;
    
    if cfg!(target_os = "windows") {
        cmd = Command::new("cmd");
        let mut cmd_args = vec!["/C", program];
        cmd_args.extend_from_slice(args);
        cmd.args(&cmd_args);
    } else {
        if program == "nmap" {
            cmd = Command::new("sudo");
            cmd.arg("-n");
            cmd.arg("/usr/bin/nmap");
        } else {
            cmd = Command::new(program);
        }
        cmd.args(args);
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }

    match cmd.output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
            
            if !output.status.success() {
                if program == "nmap" && combined.to_lowercase().contains("not found") {
                    (false, "Nmap bulunamadı! Lütfen sisteminize kurun ve PATH'e ekleyin".to_string())
                } else {
                    (false, format!("Hata: Sistem komutu yürütülemedi\n{}", combined))
                }
            } else {
                (true, combined)
            }
        }
        Err(e) => {
            if program == "nmap" {
                (false, "Nmap bulunamadı! Lütfen sisteminize kurun ve PATH'e ekleyin".to_string())
            } else {
                (false, format!("Hata: Sistem komutu yürütülemedi\nDetay: {}\n'{}' programı sisteminizde kurulu mu?", e, program))
            }
        }
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

    // ── Ağ Keşfi (Brute-Force Discovery) ──
    if body.net_discover {
        scan_types.push("net_discover");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sn", "-PS22,80,443", "--send-eth", "-T4", "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Port Tarama → nmap -F -Pn ──
    if body.port_scan {
        scan_types.push("port_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sT", "-F", "-Pn", "--send-eth", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Zafiyet Analizi → nmap --script vuln -Pn ──
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        
        let (ok, out) = run_command("nmap", &["-sT", "--script", "vuln", "-Pn", "--send-eth", "-T3", "--host-timeout", "15m", "--top-ports", "50", "--scan-delay", "1s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── İşletim Sistemi Tespiti ──
    if body.os_detect {
        scan_types.push("os_detect");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-O", "-Pn", "--osscan-limit", "--max-retries", "1", "-p", "22,80,443", "--privileged", "--send-eth", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Servis Versiyon Tespiti ──
    if body.version_detect {
        scan_types.push("version_detect");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-sV", "-Pn", "--privileged", "--send-eth", t_arg, "--host-timeout", "60s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Kapsamlı Agresif Tarama → nmap -A -Pn ──
    if body.aggressive_scan {
        scan_types.push("aggressive_scan");
        if !all_output.is_empty() { all_output.push_str("\n══════════════════════════════════════\n\n"); }
        let (ok, out) = run_command("nmap", &["-A", "-Pn", "--send-eth", t_arg, "--host-timeout", "120s", &target]);
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Alan Adı Sorgula ──
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
//  DURDURMA İŞLEMİ (CANCEL)
// ═══════════════════════════════════════════════════════════

async fn handle_stop() -> Json<ScanResponse> {
    let mut cmd = if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(&["/C", "taskkill /F /IM nmap.exe /T"]);
        c
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n");
        c.arg("killall");
        c.arg("nmap");
        c.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        c
    };
    
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
        .route("/api/check_env", get(handle_check_env))
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
