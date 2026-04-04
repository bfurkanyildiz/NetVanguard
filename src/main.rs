use axum::{
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use colored::Colorize;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tower_http::services::ServeDir;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use exif;
use std::fs::File;
use std::io::BufReader;

// Log Throttling for Interface Selector
static LAST_INTERFACE: Lazy<StdMutex<Option<String>>> = Lazy::new(|| StdMutex::new(None));

// ═══════════════════════════════════════════════════════════
//  İŞLEM YÖNETİCİSİ (PROCESS MANAGER)
// ═══════════════════════════════════════════════════════════

struct ScanManager {
    child: Mutex<Option<Child>>,
    cancel_token: Mutex<CancellationToken>,
}

static PROCESS_MANAGER: Lazy<Arc<ScanManager>> = Lazy::new(|| {
    Arc::new(ScanManager {
        child: Mutex::new(None),
        cancel_token: Mutex::new(CancellationToken::new()),
    })
});

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
    #[serde(default)]
    priv_esc: bool,
}

#[derive(Deserialize)]
struct MetadataRequest {
    path: String,
}

#[derive(Serialize)]
struct MetadataResponse {
    success: bool,
    data: std::collections::HashMap<String, String>,
    error: Option<String>,
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

#[derive(Serialize)]
struct PacketInfo {
    src: String,
    dest: String,
    proto: String,
    len: usize,
}

#[derive(Serialize)]
struct SnifferResponse {
    success: bool,
    packets: Vec<PacketInfo>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct BreachRequest {
    email: String,
}

#[derive(Serialize)]
struct BreachResponse {
    success: bool,
    found: bool,
    sources: Vec<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct WifiInfo {
    ssid: String,
    bssid: String,
    signal: u8,
    channel: u32,
}

#[derive(Serialize)]
struct WifiResponse {
    success: bool,
    data: Vec<WifiInfo>,
    error: Option<String>,
    active_interface: Option<String>,
}

#[derive(Serialize, Clone)]
struct WirelessInterface {
    name: String,
    is_up: bool,
    is_wireless: bool,
    reason: String,
}

#[derive(Serialize)]
struct WifiStatusResponse {
    interfaces: Vec<WirelessInterface>,
    selected: Option<String>,
    status: String,
    reason: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct GeoResponse {
    pub status: String,
    pub city: Option<String>,
    #[serde(rename = "district", alias = "regionName")]
    pub district: Option<String>,
    #[serde(rename = "country")]
    pub country: Option<String>,
    pub isp: Option<String>,
    pub org: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    #[serde(rename = "as")]
    pub as_info: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Deserialize)]
struct GeoParams {
    ip: String,
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
        if let Ok(output) = Command::new("cmd")
            .args(&["/C", "nmap", "--version"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    nmap_version = Some(line.replace("Nmap version ", "").to_string());
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        if let Ok(output) = Command::new("nmap").arg("--version").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = stdout.lines().next() {
                    nmap_version = Some(line.replace("Nmap version ", "").to_string());
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    };

    // Check if running as admin/root
    let is_admin = if cfg!(target_os = "windows") {
        // 'net session' only successful when run as Admin
        Command::new("cmd")
            .args(&["/C", "net session"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    } else {
        // checking if uid is 0
        Command::new("id")
            .arg("-u")
            .output()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                stdout == "0"
            })
            .unwrap_or(false)
    };

    Json(EnvCheckResponse {
        nmap: nmap_installed,
        version: nmap_version,
        root: is_admin,
        os: os_type,
    })
}

// ═══════════════════════════════════════════════════════════
//  KOMUT ÇALIŞTIRICI (ASYNCHRONOUS & CANCELLABLE)
// ═══════════════════════════════════════════════════════════

async fn run_command(program: &str, args: &[&str]) -> (bool, String) {
    let mut cmd;

    // Check for cancellation before starting
    if PROCESS_MANAGER.cancel_token.lock().await.is_cancelled() {
        return (false, "İşlem iptal edildi.".to_string());
    }

    if cfg!(target_os = "windows") {
        cmd = tokio::process::Command::new("cmd");
        let mut cmd_args = vec!["/C", program];
        cmd_args.extend_from_slice(args);
        cmd.args(&cmd_args);
    } else {
        if program == "nmap" {
            cmd = tokio::process::Command::new("sudo");
            cmd.arg("-n");
            cmd.arg("/usr/bin/nmap");
        } else {
            cmd = tokio::process::Command::new(program);
        }
        cmd.args(args);
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }

    // Kill existing child if any (cleanup)
    {
        let mut child_lock = PROCESS_MANAGER.child.lock().await;
        if let Some(mut old_child) = child_lock.take() {
            let _ = old_child.kill().await;
        }
    }

    match cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            // Store child handle
            {
                let mut child_lock = PROCESS_MANAGER.child.lock().await;
                *child_lock = Some(child);
            }

            // Wait for output or cancellation
            let token = PROCESS_MANAGER.cancel_token.lock().await.clone();

            let final_res: (bool, String) = tokio::select! {
                result = async {
                    let mut child_opt = PROCESS_MANAGER.child.lock().await;
                    if let Some(c) = child_opt.take() {
                        c.wait_with_output().await
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::Other, "İşlem zaten sonlandırılmış."))
                    }
                } => {
                    match result {
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
                        Err(e) => (false, format!("Hata: Komut çıktısı okunamadı: {}", e))
                    }
                }
                _ = token.cancelled() => {
                    let mut child_lock = PROCESS_MANAGER.child.lock().await;
                    if let Some(mut child) = child_lock.take() {
                        let _ = child.kill().await;
                    }
                    (false, "İşlem sonlandırıldı.".to_string())
                }
            };
            final_res
        }
        Err(e) => (false, format!("Hata: Komut başlatılamadı: {}", e)),
    }
}

// ═══════════════════════════════════════════════════════════
//  ANA API HANDLER
// ═══════════════════════════════════════════════════════════

async fn handle_scan(Json(body): Json<ScanRequest>) -> Json<ScanResponse> {
    // Reset cancellation token for a new scan (cancel old one first)
    {
        let mut token_lock = PROCESS_MANAGER.cancel_token.lock().await;
        token_lock.cancel(); // Abort any previous task using this manager
        *token_lock = CancellationToken::new();
    }
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
    let any_option = body.port_scan
        || body.vuln_scan
        || body.os_detect
        || body.dns_query
        || body.version_detect
        || body.aggressive_scan
        || body.net_discover;

    let mut timing_arg = match body.timing.as_str() {
        "T0" | "T1" | "T2" | "T3" | "T4" | "T5" => format!("-{}", body.timing),
        _ => "-T3".to_string(),
    };

    // RESTRICT SPEED: Zafiyet analizinde T4/T5 çok riskli ve agresif olduğu için backend T3 zorunlu
    if body.vuln_scan {
        timing_arg = "-T3".to_string();
    }

    let t_arg = timing_arg.as_str();

    // ── Hiçbir şey seçilmediyse → Ping ──
    if !any_option {
        scan_types.push("ping");
        let ping_args = if cfg!(target_os = "windows") {
            vec!["-n", "4", &target]
        } else {
            vec!["-c", "4", &target]
        };
        let (ok, out) = run_command("ping", &ping_args).await;
        overall_success = ok;
        all_output.push_str(&out);
    }

    // ── Ağ Keşfi (Brute-Force Discovery) ──
    if body.net_discover {
        if PROCESS_MANAGER.cancel_token.lock().await.is_cancelled() {
            return Json(ScanResponse {
                success: false,
                target: target.clone(),
                scan_type: "cancelled".into(),
                output: "İptal edildi.".into(),
            });
        }
        scan_types.push("net_discover");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }
        let (ok, out) = run_command(
            "nmap",
            &[
                "-sn",
                "-PS22,80,443",
                "--send-eth",
                "-T4",
                "--host-timeout",
                "60s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Port Tarama → nmap -F -Pn ──
    if body.port_scan {
        scan_types.push("port_scan");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }
        let (ok, out) = run_command(
            "nmap",
            &[
                "-sT",
                "-F",
                "-Pn",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "60s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Zafiyet Analizi → nmap --script vuln -Pn ──
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }

        let mut vuln_scripts = "vuln".to_string();
        if body.priv_esc {
            vuln_scripts.push_str(",linux-exploit-suggester,auth-owners");
        }

        let (ok, out) = run_command(
            "nmap",
            &[
                "-sT",
                "--script",
                &vuln_scripts,
                "-Pn",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "15m",
                "--top-ports",
                "50",
                "--scan-delay",
                "1s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── İşletim Sistemi Tespiti ──
    if body.os_detect {
        scan_types.push("os_detect");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }
        let (ok, out) = run_command(
            "nmap",
            &[
                "-O",
                "-Pn",
                "--osscan-limit",
                "--max-retries",
                "1",
                "-p",
                "22,80,443",
                "--privileged",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "60s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Servis Versiyon Tespiti ──
    if body.version_detect {
        scan_types.push("version_detect");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }
        let (ok, out) = run_command(
            "nmap",
            &[
                "-sV",
                "-Pn",
                "--privileged",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "60s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Kapsamlı Agresif Tarama → nmap -A -Pn ──
    if body.aggressive_scan {
        scan_types.push("aggressive_scan");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }
        let (ok, out) = run_command(
            "nmap",
            &[
                "-A",
                "-Pn",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "120s",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Alan Adı Sorgula (Rust Native with 5s Timeout) ──
    if body.dns_query {
        scan_types.push("dns_query");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }

        let mut dns_out = String::from("DNS SORGULAMA SONUCU:\n--------------------\n");
        let mut dns_success = false;

        let config = ResolverConfig::default();
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 1;

        let resolver = TokioAsyncResolver::tokio(config, opts);
        match resolver.lookup_ip(&target).await {
            Ok(lookup) => {
                dns_success = true;
                for ip in lookup.iter() {
                    dns_out.push_str(&format!("Found IP: {}\n", ip));
                }
            }
            Err(e) => {
                dns_out.push_str(&format!("Hata: Çözümlenemedi ({})\n", e));
            }
        }

        overall_success = overall_success && dns_success;
        all_output.push_str(&dns_out);
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

#[allow(dead_code)]
async fn handle_stop() -> Json<ScanResponse> {
    // 1. Trigger cancellation token
    PROCESS_MANAGER.cancel_token.lock().await.cancel();

    // 2. Kill the active process if any
    {
        let mut child_lock = PROCESS_MANAGER.child.lock().await;
        if let Some(mut child) = child_lock.take() {
            let _ = child.kill().await;
        }
    }

    // 3. Fallback: System-wide killall for nmap
    let _ = if cfg!(target_os = "windows") {
        tokio::process::Command::new("cmd")
            .args(&["/C", "taskkill /F /IM nmap.exe /T"]) // /F ve /T ile tree-SIGKILL gerçekleştirilir
            .output()
            .await
    } else {
        tokio::process::Command::new("sudo")
            .args(&["-n", "killall", "-9", "nmap"]) // Zorunlu SIGKILL
            .output()
            .await
    };

    Json(ScanResponse {
        success: true,
        target: "".into(),
        scan_type: "stop".into(),
        output: "İşlemler başarıyla durduruldu ve kaynaklar serbest bırakıldı.".into(),
    })
}

// ═══════════════════════════════════════════════════════════
//  WI-FI RADAR YARDIMCI FONKSİYONLAR
// ═══════════════════════════════════════════════════════════

fn get_wireless_interfaces() -> (Vec<WirelessInterface>, Option<String>, String) {
    let mut interfaces = Vec::new();
    let mut selected = None;
    let mut selection_reason = "No wireless interface found".to_string();

    // Windows / Fallback simulation
    if cfg!(target_os = "windows") {
        interfaces.push(WirelessInterface {
            name: "wlan0 (Simulated)".to_string(),
            is_up: true,
            is_wireless: true,
            reason: "Simulated Wireless Interface for Windows".to_string(),
        });
        selected = Some("wlan0 (Simulated)".to_string());
        selection_reason = "Simulated primary for development".to_string();
        return (interfaces, selected, selection_reason);
    }

    // Scan /sys/class/net/
    if let Ok(entries) = fs::read_dir("/sys/class/net/") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name == "lo"
                    || name.contains("vbox")
                    || name.contains("docker")
                    || name.contains("br-")
                {
                    continue;
                }

                let wireless_path = format!("/sys/class/net/{}/wireless", name);
                let operstate_path = format!("/sys/class/net/{}/operstate", name);

                let is_wireless = fs::metadata(&wireless_path).is_ok();
                let operstate = fs::read_to_string(&operstate_path)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();
                let is_up = operstate == "up";

                let reason = if is_wireless && is_up {
                    "Interface is UP and Wireless".to_string()
                } else if is_wireless {
                    "Wireless detected but DOWN".to_string()
                } else if name.starts_with('w') {
                    "Potential WiFi (Name starts with 'w')".to_string()
                } else {
                    "Standard Network Interface".to_string()
                };

                // Add to list
                let iface = WirelessInterface {
                    name: name.clone(),
                    is_up,
                    is_wireless,
                    reason: reason.clone(),
                };
                interfaces.push(iface);

                // Selection Logic (Strict: Only UP interfaces are candidates for 'selected')
                if selected.is_none() && is_up {
                    if is_wireless {
                        selected = Some(name.clone());
                        selection_reason = format!("Primary: {} is UP and Wireless", name);
                    } else if name.starts_with('w') {
                        selected = Some(name.clone());
                        selection_reason =
                            format!("Name Fallback: {} is UP (starts with 'w')", name);
                    }
                }
            }
        }
    }

    // Duplicate Log Fix: Only print if the selection or state has changed
    if let Ok(mut last_iface) = LAST_INTERFACE.lock() {
        if *last_iface != selected {
            *last_iface = selected.clone();
            if let Some(ref s) = selected {
                println!(
                    "{} [DEBUG] Interface Changed: {} chosen because: {}",
                    "⚡".yellow(),
                    s.cyan(),
                    selection_reason.white()
                );
            } else {
                println!(
                    "{} [DEBUG] Interface Lost: No active (UP) wireless interfaces found.",
                    "⚠️".yellow()
                );
            }
        }
    }

    (interfaces, selected, selection_reason)
}

fn find_wifi_interface() -> Option<String> {
    let (_, selected, _) = get_wireless_interfaces();
    selected
}

// ═══════════════════════════════════════════════════════════
//  WI-FI RADAR SİSTEMİ
// ═══════════════════════════════════════════════════════════

async fn handle_wifi_status() -> Json<WifiStatusResponse> {
    let (interfaces, selected, reason) = get_wireless_interfaces();
    Json(WifiStatusResponse {
        interfaces,
        selected,
        status: "ACTIVE".to_string(),
        reason,
    })
}

async fn handle_wifi_scan() -> Json<WifiResponse> {
    if cfg!(target_os = "windows") {
        return Json(WifiResponse {
            success: false,
            data: vec![],
            error: Some(
                "Wi-Fi Radar özelliği sadece Linux/Kali sistemlerde `nmcli` aracı ile çalışır."
                    .to_string(),
            ),
            active_interface: None,
        });
    }

    // 🔍 Dinamik Interface Tespiti
    let interface = match find_wifi_interface() {
        Some(i) => i,
        None => {
            return Json(WifiResponse {
                success: false,
                data: vec![],
                error: Some("Wi-Fi Adaptörü Bulunamadı! Lütfen cihazınızın takılı ve aktif olduğundan emin olun.".to_string()),
                active_interface: None,
            });
        }
    };

    // Rescan matches UI expectations for fresh data
    let _ = Command::new("nmcli")
        .args(&["dev", "wifi", "rescan"])
        .output();

    let output = match Command::new("nmcli")
        .args(&["-t", "-f", "SSID,BSSID,SIGNAL,CHAN", "dev", "wifi"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Json(WifiResponse {
                success: false,
                data: vec![],
                error: Some(format!("nmcli hatası: {}. Interface: {}", e, interface)),
                active_interface: Some(interface),
            })
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // FORMAT: SSID:BSSID:SIGNAL:CHAN
        // BSSID contains ':' (e.g. AA:BB:CC:DD:EE:FF)
        // nmcli -t uses ':' as delimiter but handles BSSID by escaping or consistent field count.
        // Actually, nmcli -t escapes ':' with '\:'. But we can also parse from the end for CHAN and SIGNAL.

        let parts: Vec<String> = line
            .replace("\\:", "##COLON##")
            .split(':')
            .map(|s| s.to_string())
            .collect();

        if parts.len() >= 4 {
            let ssid = parts[0].replace("##COLON##", ":").to_string();
            let bssid = parts[1].replace("##COLON##", ":").to_string();
            let signal = parts[2].parse::<u8>().unwrap_or(0);
            let channel = parts[3].parse::<u32>().unwrap_or(0);

            if !ssid.is_empty() {
                networks.push(WifiInfo {
                    ssid,
                    bssid,
                    signal,
                    channel,
                });
            }
        }
    }

    // Descending order by signal strength
    networks.sort_by(|a, b| b.signal.cmp(&a.signal));

    // Remove duplicates
    networks.dedup_by(|a, b| a.ssid == b.ssid);

    Json(WifiResponse {
        success: true,
        data: networks,
        error: None,
        active_interface: Some(interface),
    })
}

// ═══════════════════════════════════════════════════════════
//  SUNUCU
// ═══════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // 🔍 Nmap Versiyonunu Tespit Et
    let nmap_ver = Command::new("nmap")
        .arg("-V")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(2).map(|v| v.to_string()))
        .unwrap_or_else(|| "Bilinmiyor".to_string());

    // ═══ ASCII ART BANNER ═══
    let banner = r#"
███╗   ██╗███████╗████████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
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
        "v1.0.0".bright_green().bold()
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

    let app = Router::new()
        .route("/api/scan", post(handle_scan))
        .route("/api/stop", post(handle_stop))
        .route("/api/wifi_scan", get(handle_wifi_scan))
        .route("/api/wifi_status", get(handle_wifi_status))
        .route("/api/check_env", get(handle_check_env))
        .route("/api/v1/geolocation", get(handle_geolocation))
        .route("/api/metadata", post(handle_metadata))
        .route("/api/sniff", get(handle_sniffer))
        .route("/api/breach_mock", post(handle_breach))
        .fallback_service(ServeDir::new("static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Port 3000 bağlanamadı!");

    // Sunucu BIND edildikten sonra bilgileri ve browser'ı aç
    println!();
    println!(
        "    {}  {}",
        "🌐 Web Panel :".bright_white().bold(),
        format!("http://{}", addr).bright_cyan().bold().underline()
    );
    println!(
        "    {}  {}",
        "📡 API       :".bright_white().bold(),
        format!("http://{}/api/scan", addr).bright_blue()
    );
    println!(
        "    {}  {}",
        "🔒 Check Env :".bright_white().bold(),
        format!("http://{}/api/check_env", addr).bright_blue()
    );
    println!();
    println!(
        "    {}",
        "🚀 Dashboard hazırlanıyor ve tarayıcıda açılıyor..."
            .bright_yellow()
            .bold()
    );
    println!();

    // Varsayılan tarayıcıyı aç
    let url = format!("http://{}", addr);
    tokio::spawn(async move {
        // Kısa bir gecikme: sunucu tam hazır olsun
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        if let Err(e) = open::that(&url) {
            eprintln!(
                "    {} Tarayıcı açılamadı: {}",
                "⚠️".to_string().yellow(),
                e
            );
        }
    });

    axum::serve(listener, app)
        .await
        .expect("Sunucu başlatılamadı!");
}
async fn handle_geolocation(Query(params): Query<GeoParams>) -> impl IntoResponse {
    let target_ip = params.ip.trim();

    // Private IP Range Check (Minimal)
    if target_ip.starts_with("192.168.")
        || target_ip.starts_with("10.")
        || target_ip.starts_with("127.")
        || target_ip.starts_with("172.16.")
        || target_ip == "localhost"
    {
        return Json(GeoResponse {
            status: "fail".to_string(),
            city: Some("Yerel Ağ".to_string()),
            district: Some("Merkez".to_string()),
            country: Some("Yerel Arayüz".to_string()),
            isp: Some("Private Network".to_string()),
            org: Some("Local Host".to_string()),
            lat: Some(0.0),
            lon: Some(0.0),
            as_info: None,
            message: Some("Yerel/Özel IP adresleri için konum bilgisi sorgulanamaz.".to_string()),
        });
    }

    let url = format!("http://ip-api.com/json/{}?fields=status,message,country,city,regionName,lat,lon,isp,org,as", target_ip);

    match reqwest::get(&url).await {
        Ok(resp) => {
            if let Ok(geo_data) = resp.json::<GeoResponse>().await {
                Json(geo_data)
            } else {
                Json(GeoResponse {
                    status: "fail".to_string(),
                    lat: None,
                    lon: None,
                    city: None,
                    district: None,
                    country: None,
                    isp: None,
                    org: None,
                    as_info: None,
                    message: Some("Veri parse edilemedi.".to_string()),
                })
            }
        }
        Err(e) => Json(GeoResponse {
            status: "fail".to_string(),
            city: Some("Bilinmiyor".to_string()),
            district: Some("Merkez".to_string()),
            country: Some("Bilinmiyor".to_string()),
            isp: Some("Hata".to_string()),
            org: Some("Hata".to_string()),
            lat: Some(0.0),
            lon: Some(0.0),
            as_info: None,
            message: Some(format!("API Bağlantı Hatası: {}", e)),
        }),
    }
}

// ═══════════════════════════════════════════════════════════
//  RAPORLAMA YARDIMCISI
// ═══════════════════════════════════════════════════════════

#[allow(dead_code)]
fn write_report_to_file(target: &str, content: &str) -> std::io::Result<()> {
    let now = chrono::Local::now();
    let filename = format!(
        "reports/report_{}_{}.txt",
        target.replace(".", "_").replace("/", "_"),
        now.format("%Y%m%d_%H%M%S")
    );

    // Ensure reports directory exists
    let _ = std::fs::create_dir_all("reports");

    if let Ok(mut file) = std::fs::File::create(&filename) {
        let _ = file.write_all(content.as_bytes());
    }

    Ok(())
}

async fn handle_metadata(Json(body): Json<MetadataRequest>) -> Json<MetadataResponse> {
    let file_path = body.path.trim();
    let file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => return Json(MetadataResponse {
            success: false,
            data: std::collections::HashMap::new(),
            error: Some(format!("Dosya açılamadı: {}", e)),
        }),
    };

    let mut reader = BufReader::new(file);
    let exifreader = exif::Reader::new();
    let exif_data: exif::Exif = match exifreader.read_from_container(&mut reader) {
        Ok(exif) => exif,
        Err(e) => return Json(MetadataResponse {
            success: false,
            data: std::collections::HashMap::new(),
            error: Some(format!("EXIF verisi okunamadı: {}", e)),
        }),
    };

    let mut data = std::collections::HashMap::new();
    for field in exif_data.fields() {
        let tag_name = format!("{:?}", field.tag);
        let value = field.display_value().with_unit(&exif_data).to_string();
        data.insert(tag_name, value);
    }

    Json(MetadataResponse {
        success: true,
        data,
        error: None,
    })
}

async fn handle_sniffer() -> Json<SnifferResponse> {
    let device = match pcap::Device::lookup() {
        Ok(d_opt) => match d_opt {
            Some(d) => d,
            None => return Json(SnifferResponse { success: false, packets: vec![], error: Some("Ağ cihazı bulunamadı.".to_string()) }),
        },
        Err(e) => return Json(SnifferResponse { success: false, packets: vec![], error: Some(format!("Cihaz arama hatası: {}", e)) }),
    };

    let mut cap = match pcap::Capture::from_device(device)
        .and_then(|c| c.promisc(true).snaplen(65535).timeout(1000).open()) {
            Ok(c) => c,
            Err(e) => return Json(SnifferResponse { success: false, packets: vec![], error: Some(format!("Capture başlatılamadı: {}", e)) }),
        };

    let mut packets = Vec::new();
    let mut count = 0;
    let start_time = std::time::Instant::now();
    
    // Capture for approximately 5 seconds
    while start_time.elapsed().as_secs() < 5 && count < 50 {
        match cap.next_packet() {
            Ok(packet) => {
                let data = packet.data;
                if data.len() < 34 { continue; } // Basic Ethernet + IP header check
                
                // Extremely simple IPv4 extraction (assuming Ethernet II)
                // Eth: 14 bytes, IP: starts at 14
                // Prototol at 14 + 9
                // Src IP at 14 + 12
                // Dest IP at 14 + 16
                
                let proto = match data[23] {
                    1 => "ICMP",
                    6 => "TCP",
                    17 => "UDP",
                    _ => "OTHER",
                };
                
                let src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                let dest = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
                
                packets.push(PacketInfo {
                    src,
                    dest,
                    proto: proto.to_string(),
                    len: data.len(),
                });
                count += 1;
            }
            Err(pcap::Error::TimeoutExpired) => break,
            Err(_) => break,
        }
    }

    Json(SnifferResponse {
        success: true,
        packets,
        error: None,
    })
}

async fn handle_breach(Json(body): Json<BreachRequest>) -> Json<BreachResponse> {
    let email = body.email.trim().to_lowercase();
    
    // Simple validation
    if !email.contains('@') {
        return Json(BreachResponse {
            success: false,
            found: false,
            sources: vec![],
            error: Some("Geçersiz e-posta formatı.".to_string()),
        });
    }

    // REAL OSINT BREACH ENGINE: Querying XposedOrNot API
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    let url = format!("https://api.xposedornot.com/v1/check-email/{}", email);
    
    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(_) => return Json(BreachResponse {
            success: false,
            found: false,
            sources: vec![],
            error: Some("İstihbarat sunucularına ulaşılamıyor!".to_string()),
        }),
    };

    if response.status() == 404 {
        return Json(BreachResponse {
            success: true,
            found: false,
            sources: vec![],
            error: None,
        });
    }

    if !response.status().is_success() {
        return Json(BreachResponse {
            success: false,
            found: false,
            sources: vec![],
            error: Some(format!("API Hatası: {}", response.status())),
        });
    }

    // Parse the response
    // XposedOrNot returns a JSON with "breaches" array
    let data: serde_json::Value = response.json().await.unwrap_or_default();
    let mut sources = Vec::new();

    if let Some(breach_list) = data.get("breaches").and_then(|b| b.as_array()) {
        for b in breach_list {
            if let Some(name) = b.get(0).and_then(|n| n.as_str()) {
                let date = b.get(1).and_then(|d| d.as_str()).unwrap_or("Unknown");
                sources.push(format!("{} ({})", name, date));
            }
        }
    }

    let found = !sources.is_empty();

    Json(BreachResponse {
        success: true,
        found,
        sources,
        error: None,
    })
}
