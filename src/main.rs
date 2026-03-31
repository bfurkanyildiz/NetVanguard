use axum::{
    extract::Query,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;
use tower_http::services::ServeDir;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

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

#[derive(Serialize)]
struct WifiInfo {
    ssid: String,
    signal: u8,
}

#[derive(Serialize)]
struct WifiResponse {
    success: bool,
    data: Vec<WifiInfo>,
    error: Option<String>,
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
            let combined = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\n{}", stdout, stderr)
            };

            if !output.status.success() {
                if program == "nmap" && combined.to_lowercase().contains("not found") {
                    (
                        false,
                        "Nmap bulunamadı! Lütfen sisteminize kurun ve PATH'e ekleyin".to_string(),
                    )
                } else {
                    (
                        false,
                        format!("Hata: Sistem komutu yürütülemedi\n{}", combined),
                    )
                }
            } else {
                (true, combined)
            }
        }
        Err(e) => {
            if program == "nmap" {
                (
                    false,
                    "Nmap bulunamadı! Lütfen sisteminize kurun ve PATH'e ekleyin".to_string(),
                )
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
    let any_option = body.port_scan
        || body.vuln_scan
        || body.os_detect
        || body.dns_query
        || body.version_detect
        || body.aggressive_scan
        || body.net_discover;

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
        );
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
        );
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }

    // ── Zafiyet Analizi → nmap --script vuln -Pn ──
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        if !all_output.is_empty() {
            all_output.push_str("\n══════════════════════════════════════\n\n");
        }

        let (ok, out) = run_command(
            "nmap",
            &[
                "-sT",
                "--script",
                "vuln",
                "-Pn",
                "--send-eth",
                "-T3",
                "--host-timeout",
                "15m",
                "--top-ports",
                "50",
                "--scan-delay",
                "1s",
                &target,
            ],
        );
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
        );
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
        );
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
        );
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
        }),
    }
}

// ═══════════════════════════════════════════════════════════
//  WI-FI RADAR SİSTEMİ
// ═══════════════════════════════════════════════════════════

async fn handle_wifi_scan() -> Json<WifiResponse> {
    if cfg!(target_os = "windows") {
        return Json(WifiResponse {
            success: false,
            data: vec![],
            error: Some(
                "Wi-Fi Radar özelliği sadece Linux/Kali sistemlerde `nmcli` aracı ile çalışır."
                    .to_string(),
            ),
        });
    }

    let output = match Command::new("nmcli")
        .args(&["-t", "-f", "SSID,SIGNAL", "dev", "wifi"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Json(WifiResponse {
                success: false,
                data: vec![],
                error: Some(format!("nmcli hatası: {}", e)),
            })
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 2 {
            let ssid = parts[0].to_string();
            let signal = parts[1].parse::<u8>().unwrap_or(0);
            if !ssid.is_empty() {
                networks.push(WifiInfo { ssid, signal });
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
    _   __     __ _   __                                    __
   / | / /__  / /| | / /___ _____  ____  __  ______  _______/ /
  /  |/ / _ \/ __/ |/ / __ `/ __ \/ __ `/ / / / __ `/ ___/ __  / 
 / /|  /  __/ /_/ /|  / /_/ / / / / /_/ / /_/ / /_/ / /  / /_/ /  
/_/ |_/\___/\__/_/ |_/\__,_/_/ /_/\__, /\__,_/\__,_/_/   \__,_/   
                                 /____/                           
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
        .route("/api/wifi", get(handle_wifi_scan))
        .route("/api/check_env", get(handle_check_env))
        .route("/api/v1/geolocation", get(handle_geolocation))
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
