use axum::{
    extract::{DefaultBodyLimit, Multipart, Query},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use colored::Colorize;
use exif;
use rand::Rng;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

// Log Throttling for Interface Selector
static LAST_INTERFACE: Lazy<StdMutex<Option<String>>> = Lazy::new(|| StdMutex::new(None));

// ═══════════════════════════════════════════════════════════
//  INTELLIGENCE & CACHE STORAGE
// ═══════════════════════════════════════════════════════════

static DNS_CACHE: Lazy<StdMutex<std::collections::HashMap<String, String>>> = Lazy::new(|| {
    StdMutex::new(std::collections::HashMap::new())
});

const META_GOOGLE_IPS: &[(&str, &str)] = &[
    ("31.13.", "META / INSTAGRAM"),
    ("157.240.", "META / FACEBOOK"),
    ("173.252.", "META / SERVICE"),
    ("142.250.", "GOOGLE SERVICE"),
    ("172.217.", "GOOGLE SERVICE"),
    ("8.8.8.8", "GOOGLE DNS"),
    ("1.1.1.1", "CLOUDFLARE DNS"),
];

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
    pub net_discover: bool,
    #[serde(default)]
    pub priv_esc: bool,
    #[serde(default)]
    pub shodan_enabled: bool,
}

#[derive(Serialize, Clone)]
pub struct ShodanData {
    pub city: String,
    pub isp: String,
    pub asn: String,
    pub ports: Vec<u16>,
    pub vulns: Vec<String>,
}

async fn get_shodan_intel(ip: &str) -> Option<ShodanData> {
    // 1. API Key Control
    let api_key = std::env::var("SHODAN_API_KEY").ok();
    
    if let Some(key) = api_key {
        // REAL SHODAN CALL
        let client = reqwest::Client::new();
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, key);
        
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(json) = resp.json::<Value>().await {
                let city = json["city"].as_str().unwrap_or("Unknown").to_string();
                let isp = json["isp"].as_str().unwrap_or("Unknown").to_string();
                let asn = json["asn"].as_str().unwrap_or("Unknown").to_string();
                
                let mut ports = Vec::new();
                if let Some(ports_arr) = json["ports"].as_array() {
                    for p in ports_arr {
                        if let Some(p_u64) = p.as_u64() {
                            ports.push(p_u64 as u16);
                        }
                    }
                }
                
                let mut vulns = Vec::new();
                if let Some(vulns_arr) = json["vulns"].as_array() {
                    for v in vulns_arr {
                        if let Some(v_str) = v.as_str() {
                            vulns.push(v_str.to_string());
                        }
                    }
                }
                
                return Some(ShodanData { city, isp, asn, ports, vulns });
            }
        }
    }

    // 2. FALLBACK: IP-API (For real City/ISP/ASN even without key)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
        
    let url = format!("http://ip-api.com/json/{}?fields=status,city,isp,as,query", ip);
    
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            if json["status"] == "success" {
                let city = json["city"].as_str().unwrap_or("Unknown").to_string();
                let isp = json["isp"].as_str().unwrap_or("Unknown").to_string();
                let asn = json["as"].as_str().unwrap_or("Unknown").to_string();
                
                return Some(ShodanData {
                    city,
                    isp,
                    asn,
                    ports: vec![80, 443], // Placeholder if no Shodan key
                    vulns: vec!["SHODAN API KEY GEREKLİ (Zafiyet Tespiti İçin)".to_string()],
                });
            }
        }
    }

    None
}

// Removed MetadataRequest/MetadataResponse as they are replaced by multipart and inline json!

#[derive(Serialize)]
struct ScanResponse {
    success: bool,
    target: String,
    scan_type: String,
    output: String,
    shodan_data: Option<ShodanData>,
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
    timestamp: String,
    src: String,
    dest: String,
    proto: String,
    len: usize,
    domain: Option<String>,
    risk_score: i32,
    threat_level: String, // "SAFE", "UNKNOWN", "SUSPICIOUS", "CRITICAL"
    reason: Option<String>,
}

#[derive(Serialize)]
struct SnifferResponse {
    success: bool,
    packets: Vec<PacketInfo>,
    active_threats: i32,
    top_domain: Option<String>,
    active_interface: Option<String>,
    is_simulated: bool,
    error: Option<String>,
}

fn parse_dns_name(payload: &[u8]) -> Option<String> {
    // Basic DNS Name Parser
    // DNS Header is 12 bytes
    if payload.len() < 13 { return None; }
    
    let mut pos = 12;
    let mut domain = String::new();
    let mut loop_protect = 0;

    while pos < payload.len() && loop_protect < 10 {
        let len = payload[pos] as usize;
        if len == 0 { break; }
        if len > 63 || pos + 1 + len > payload.len() { return None; }
        
        if !domain.is_empty() { domain.push('.'); }
        let part = String::from_utf8_lossy(&payload[pos+1..pos+1+len]);
        domain.push_str(&part);
        pos += 1 + len;
        loop_protect += 1;
    }
    
    if domain.is_empty() { None } else { Some(domain) }
}

fn parse_dns_answer(payload: &[u8]) -> Option<(String, String)> {
    if payload.len() < 12 { return None; }
    
    // 1. Skip Header (12 bytes)
    let mut pos = 12;
    
    // 2. Skip Question Section
    let q_count = u16::from_be_bytes([payload[4], payload[5]]);
    if q_count == 0 { return None; }
    
    let mut domain = String::new();
    // Parse name in question
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 { 
            pos += 1; 
            break; 
        }
        if len > 63 || pos + 1 + len > payload.len() { break; }
        if !domain.is_empty() { domain.push('.'); }
        domain.push_str(&String::from_utf8_lossy(&payload[pos+1..pos+1+len]));
        pos += 1 + len;
    }
    pos += 4; // Skip QType and QClass

    // 3. Parse Answer Section
    let ans_count = u16::from_be_bytes([payload[6], payload[7]]);
    if ans_count == 0 || pos >= payload.len() { return None; }

    for _ in 0..ans_count {
        if pos >= payload.len() { break; }
        // Name (usually a pointer 0xC0xx)
        if payload[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            // Skip variable name
            while pos < payload.len() && payload[pos] != 0 {
                pos += 1;
            }
            pos += 1;
        }

        if pos + 10 > payload.len() { break; }
        let a_type = u16::from_be_bytes([payload[pos], payload[pos+1]]);
        let rd_len = u16::from_be_bytes([payload[pos+8], payload[pos+9]]) as usize;
        pos += 10;

        if a_type == 1 && rd_len == 4 && pos + 4 <= payload.len() {
            // A Record (IPv4)
            let ip = format!("{}.{}.{}.{}", payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]);
            return Some((ip, domain));
        }
        pos += rd_len;
    }

    None
}

fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 11 { return None; }
    
    // TLS Record Header: [Type (1), Version (2), Length (2)]
    // Handshake Type: 0x16 (22) is Handshake
    if payload[0] != 0x16 { return None; }
    
    // Handshake starts after Record Header (5 bytes)
    // Handshake Type: 0x01 (1) is Client Hello
    if payload[5] != 0x01 { return None; }

    // Skip Handshake Header (4) + Version (2) + Random (32)
    let mut pos = 5 + 4 + 2 + 32;
    
    // Session ID
    if pos >= payload.len() { return None; }
    let session_id_len = payload[pos] as usize;
    pos += 1 + session_id_len;
    
    // Cipher Suites
    if pos + 2 > payload.len() { return None; }
    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2 + cipher_suites_len;
    
    // Compression Methods
    if pos >= payload.len() { return None; }
    let comp_methods_len = payload[pos] as usize;
    pos += 1 + comp_methods_len;
    
    // Extensions
    if pos + 2 > payload.len() { return None; }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    
    while pos + 4 <= extensions_end && pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos+1]]);
        let ext_len = u16::from_be_bytes([payload[pos+2], payload[pos+3]]) as usize;
        pos += 4;
        
        if ext_type == 0 { // Server Name Extension
            if pos + 2 > payload.len() { break; }
            let _list_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
            pos += 2;
            
            if pos + 3 > payload.len() { break; }
            let name_type = payload[pos]; // 0 is hostname
            let name_len = u16::from_be_bytes([payload[pos+1], payload[pos+2]]) as usize;
            pos += 3;
            
            if name_type == 0 && pos + name_len <= payload.len() {
                return Some(String::from_utf8_lossy(&payload[pos..pos+name_len]).to_string());
            }
        }
        pos += ext_len;
    }
    
    None
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
            shodan_data: None,
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
                shodan_data: None,
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

    // ── Shodan Global Intelligence (Intel Box) ──
    let mut shodan_data = None;
    if body.shodan_enabled {
        // Private IP Check (Shodan doesn't scan local networks)
        let is_private = target.starts_with("192.168.") 
            || target.starts_with("10.") 
            || target.starts_with("172.16.") 
            || target.starts_with("127.") 
            || target == "localhost";

        if !is_private {
            // REAL INTEL FETCH
            shodan_data = get_shodan_intel(&target).await;
        }
    }

    Json(ScanResponse {
        success: overall_success,
        target: target.clone(),
        scan_type: scan_types.join(","),
        output: all_output,
        shodan_data,
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
        shodan_data: None,
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

    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));

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

async fn handle_metadata(mut multipart: Multipart) -> impl IntoResponse {
    let mut metadata = std::collections::HashMap::new();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or_default().to_string();
        if name != "file" {
            continue;
        }

        let file_name = field.file_name().unwrap_or("unknown").to_string();
        let data = match field.bytes().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        let file_size = data.len();
        metadata.insert("Dosya Adı".to_string(), file_name);
        metadata.insert("Boyut".to_string(), format!("{:.2} MB", file_size as f64 / 1_048_576.0));

        let mut cursor = Cursor::new(data);
        let exifreader = exif::Reader::new();

        match exifreader.read_from_container(&mut cursor) {
            Ok(exif_data) => {
                let mut lat: Option<f64> = None;
                let mut lon: Option<f64> = None;
                let mut lat_ref = "N";
                let mut lon_ref = "E";

                for field in exif_data.fields() {
                    let tag = field.tag.to_string();
                    let val = field.display_value().with_unit(&exif_data).to_string();

                    // GPS Data Extraction
                    if tag == "GPSLatitude" {
                        if let exif::Value::Rational(r) = &field.value {
                            if r.len() >= 3 {
                                lat = Some(r[0].to_f64() + r[1].to_f64()/60.0 + r[2].to_f64()/3600.0);
                            }
                        }
                    } else if tag == "GPSLongitude" {
                        if let exif::Value::Rational(r) = &field.value {
                            if r.len() >= 3 {
                                lon = Some(r[0].to_f64() + r[1].to_f64()/60.0 + r[2].to_f64()/3600.0);
                            }
                        }
                    } else if tag == "GPSLatitudeRef" {
                        lat_ref = if val.contains('S') { "S" } else { "N" };
                    } else if tag == "GPSLongitudeRef" {
                        lon_ref = if val.contains('W') { "W" } else { "E" };
                    }

                    // Filter for interesting tags
                    if tag.contains("GPS")
                        || tag.contains("Date")
                        || tag.contains("Make")
                        || tag.contains("Model")
                        || tag.contains("Software")
                        || tag.contains("ImageWidth")
                        || tag.contains("ImageLength")
                    {
                        metadata.insert(tag, val);
                    }
                }

                // Generate Google Maps Link if both lat and lon are present
                if let (Some(mut lt), Some(mut ln)) = (lat, lon) {
                    if lat_ref == "S" { lt = -lt; }
                    if lon_ref == "W" { ln = -ln; }
                    let map_url = format!("https://www.google.com/maps?q={},{}", lt, ln);
                    metadata.insert("🎯 HEDEF KONUMU (HARİTA)".to_string(), map_url);
                }
            }
            Err(e) => {
                // If it's not a hard error (like missing EXIF), we still return the file info
                metadata.insert("Status".to_string(), format!("TEMİZ (Metadata Bulunamadı: {})", e));
            }
        }
    }

    if metadata.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "Dosya okunamadı veya geçersiz format."
        }));
    }

    Json(serde_json::json!({
        "success": true,
        "data": metadata
    }))
}

async fn handle_sniffer() -> Json<SnifferResponse> {
    use std::collections::HashMap;

    let devices = pcap::Device::list().unwrap_or_default();
    let device = devices.into_iter().find(|d| {
        !d.flags.is_loopback() && !d.addresses.is_empty()
    }).or_else(|| pcap::Device::lookup().ok().flatten());

    let mut packets = Vec::new();
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut domain_counts: HashMap<String, usize> = HashMap::new();
    let mut active_threats = 0;
    let mut active_interface = None;
    let mut is_simulated = false;

    if let Some(d) = device {
        active_interface = Some(d.name.clone());
        if let Ok(mut cap) = pcap::Capture::from_device(d)
            .and_then(|c| c.promisc(true).snaplen(65535).timeout(100).open())
        {
            let start_time = std::time::Instant::now();
            while start_time.elapsed().as_millis() < 1500 && packets.len() < 50 {
                if let Ok(packet) = cap.next_packet() {
                    let data = packet.data;
                    if data.len() < 34 { continue; }
                    
                    let proto_num = data[23];
                    let proto = match proto_num {
                        1 => "ICMP",
                        6 => "TCP",
                        17 => "UDP",
                        _ => "OTHER",
                    };

                    let src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                    let dest = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);
                    
                    // Track IP frequency (Only for Non-Local / Non-Multicast)
                    let is_multicast = dest.starts_with("239.255.") || dest.starts_with("224.0.");
                    let is_local = src.starts_with("192.168.");
                    
                    if !is_multicast && !is_local {
                        *ip_counts.entry(src.clone()).or_insert(0) += 1;
                    }

                    let mut p_info = PacketInfo {
                        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                        src: src.clone(),
                        dest: dest.clone(),
                        proto: proto.to_string(),
                        len: data.len(),
                        domain: None,
                        risk_score: 0,
                        threat_level: "UNKNOWN".to_string(),
                        reason: None,
                    };

                    // Intel Layer: Check for Multicast
                    if is_multicast {
                        p_info.threat_level = "SAFE".to_string();
                        p_info.risk_score = 0;
                        p_info.reason = Some("Local Discovery (SSDP/mDNS)".to_string());
                    }

                    // Intel Layer: ASN Identification (Meta/Google)
                    for (prefix, label) in META_GOOGLE_IPS {
                        if dest.starts_with(prefix) {
                            p_info.threat_level = "SAFE".to_string();
                            p_info.dest = format!("{} ({})", dest, label);
                            break;
                        }
                    }

                    // Intel Layer: DNS Cache Lookup
                    if let Ok(cache) = DNS_CACHE.lock() {
                        if let Some(domain) = cache.get(&dest) {
                            p_info.domain = Some(domain.clone());
                            p_info.dest = domain.clone();
                            p_info.threat_level = "SAFE".to_string();
                        }
                    }

                    // Deep Analysis
                    if data.len() >= 42 {
                        let s_port = u16::from_be_bytes([data[34], data[35]]);
                        let d_port = u16::from_be_bytes([data[36], data[37]]);
                        
                        // 1. DNS Analysis & Cache Update
                        if proto_num == 17 && (d_port == 53 || s_port == 53) {
                            if s_port == 53 {
                                // DNS Response - Learn IP->Domain
                                if let Some((ip, domain)) = parse_dns_answer(&data[42..]) {
                                    if let Ok(mut cache) = DNS_CACHE.lock() {
                                        cache.insert(ip, domain.clone());
                                    }
                                }
                            } else {
                                // DNS Query
                                if let Some(domain) = parse_dns_name(&data[42..]) {
                                    *domain_counts.entry(domain.clone()).or_insert(0) += 1;
                                    p_info.domain = Some(domain.clone());
                                    p_info.dest = format!("QUERY: {}", domain);
                                }
                            }
                        }

                        // 2. HTTPS (TLS SNI) Analysis
                        if proto_num == 6 && d_port == 443 {
                            // Find TCP payload start (usually 14 + 20 + 20 = 54)
                            // But IP header can be variable length
                            let ip_len = (data[14] & 0x0F) as usize * 4;
                            let tcp_len = ((data[14 + ip_len + 12] >> 4) & 0x0F) as usize * 4;
                            let payload_offset = 14 + ip_len + tcp_len;
                            
                            if data.len() > payload_offset + 10 {
                                if let Some(sni) = parse_tls_sni(&data[payload_offset..]) {
                                    p_info.domain = Some(sni.clone());
                                    p_info.dest = format!("{} [HTTPS]", sni);
                                    p_info.threat_level = "SAFE".to_string();
                                    
                                    // Also update cache for future packets to this IP
                                    if let Ok(mut cache) = DNS_CACHE.lock() {
                                        cache.insert(dest.clone(), sni);
                                    }
                                }
                            }
                        }

                        // 3. Threat Detection: Backdoor Ports
                        if d_port == 4444 || d_port == 31337 {
                            p_info.risk_score = 10;
                            p_info.threat_level = "CRITICAL".to_string();
                            p_info.reason = Some("BACKDOOR ACTIVITY DETECTED".to_string());
                            active_threats += 1;
                        }
                    }

                    // Threat Detection: High Frequency (Burst) - Only for WAN
                    if !is_multicast && !is_local {
                        if let Some(&count) = ip_counts.get(&p_info.src) {
                            if count > 15 && p_info.risk_score < 7 {
                                p_info.risk_score = 7;
                                p_info.threat_level = "SUSPICIOUS".to_string();
                                p_info.reason = Some("TRAFFIC BURST (SCAN/DDOS)".to_string());
                                active_threats += 1;
                            }
                        }
                    }

                    packets.push(p_info);
                }
            }
        }
    }

    // Simulation Fallback
    if packets.is_empty() {
        is_simulated = true;
        let mut rng = rand::thread_rng();
        for _ in 0..15 {
            let src = format!("192.168.1.{}", rng.gen_range(2..254));
            let (dest, level, domain) = if rng.gen_bool(0.2) {
                ("INSTAGRAM.COM [HTTPS]".to_string(), "SAFE", Some("instagram.com".to_string()))
            } else if rng.gen_bool(0.2) {
                ("239.255.255.250".to_string(), "SAFE", None)
            } else {
                ("8.8.8.8".to_string(), "SAFE", Some("google.com".to_string()))
            };

            packets.push(PacketInfo {
                timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                src,
                dest,
                proto: "TCP".to_string(),
                len: rng.gen_range(64..1500),
                domain,
                risk_score: 0,
                threat_level: level.to_string(),
                reason: if level == "SAFE" { None } else { Some("Simulated Traffic".to_string()) },
            });
        }
    }

    let top_domain = domain_counts.iter()
        .max_by_key(|entry| entry.1)
        .map(|(d, _)| d.clone());

    Json(SnifferResponse {
        success: true,
        packets,
        active_threats,
        top_domain,
        active_interface,
        is_simulated,
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
        Err(_) => {
            return Json(BreachResponse {
                success: false,
                found: false,
                sources: vec![],
                error: Some("İstihbarat sunucularına ulaşılamıyor!".to_string()),
            })
        }
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
