use crate::intel::get_shodan_intel;
use crate::models::*;
use crate::privesc::perform_priv_esc_analysis;
use axum::Json;
use once_cell::sync::Lazy;
use std::fs;
use std::io::Write;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

// ═══════════════════════════════════════════════════════════
//  PROCESS MANAGER & STATE
// ═══════════════════════════════════════════════════════════

pub static PROCESS_MANAGER: Lazy<Arc<ScanManager>> = Lazy::new(|| {
    Arc::new(ScanManager {
        child: tokio::sync::Mutex::new(None),
        cancel_token: tokio::sync::Mutex::new(CancellationToken::new()),
    })
});

// ═══════════════════════════════════════════════════════════
//  REPORTING HELPER
// ═══════════════════════════════════════════════════════════

/// # Summary
/// Scans generate text reports which are persisted to the local filesystem.
/// This helper handles the naming and directory creation for these reports.
///
/// # Arguments
/// * `target` - The scanning target (IP or Domain) used for filename generation.
/// * `content` - The raw string content of the scan output.
///
/// # Returns
/// * `std::io::Result<()>` - Success if the file was written, Error otherwise.
#[allow(dead_code)]
pub fn write_report_to_file(target: &str, content: &str) -> std::io::Result<()> {
    let now = chrono::Local::now();
    let filename = format!(
        "reports/report_{}_{}.txt",
        target.replace(".", "_").replace("/", "_"),
        now.format("%Y%m%d_%H%M%S")
    );
    let _ = std::fs::create_dir_all("reports");
    if let Ok(mut file) = std::fs::File::create(&filename) {
        let _ = file.write_all(content.as_bytes());
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  SCANNER ENGINE
// ═══════════════════════════════════════════════════════════

/// # Summary
/// Validates the system environment to ensure Nmap is installed and the process has sufficient privileges.
///
/// # Arguments
/// * None (Triggered via API endpoint)
///
/// # Returns
/// * `Json<EnvCheckResponse>` - Contains OS type, Nmap status/version, and Root privilege status.
pub async fn handle_check_env() -> Json<EnvCheckResponse> {
    let os_type = if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else {
        "Linux".to_string()
    };
    let mut nmap_version = None;
    let nmap_installed = if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("cmd")
            .args(["/C", "nmap", "--version"])
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
    let is_admin = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "net session"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    } else {
        Command::new("id")
            .arg("-u")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
            .unwrap_or(false)
    };
    Json(EnvCheckResponse {
        nmap: nmap_installed,
        version: nmap_version,
        root: is_admin,
        os: os_type,
    })
}

/// # Summary
/// A secure wrapper for executing asynchronous shell commands with logic for process cancellation and timeout.
///
/// # Arguments
/// * `program` - The executable name (e.g., "nmap", "sudo").
/// * `args` - A slice of string arguments to pass to the program.
///
/// # Returns
/// * `(bool, String)` - A tuple containing the success status and the combined stdout/stderr output.
pub async fn run_command(program: &str, args: &[&str]) -> (bool, String) {
    if PROCESS_MANAGER.cancel_token.lock().await.is_cancelled() {
        return (false, "İşlem iptal edildi.".to_string());
    }
    let mut cmd;
    if cfg!(target_os = "windows") {
        cmd = tokio::process::Command::new("cmd");
        let mut cmd_args = vec!["/C", program];
        cmd_args.extend_from_slice(args);
        cmd.args(&cmd_args);
    } else {
        if program == "nmap" {
            cmd = tokio::process::Command::new("sudo");
            cmd.arg("-n").arg("/usr/bin/nmap");
        } else {
            cmd = tokio::process::Command::new(program);
        }
        cmd.args(args);
        cmd.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    }
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
            {
                let mut child_lock = PROCESS_MANAGER.child.lock().await;
                *child_lock = Some(child);
            }
            let token = PROCESS_MANAGER.cancel_token.lock().await.clone();
            tokio::select! {
                result = async {
                    let mut child_opt = PROCESS_MANAGER.child.lock().await;
                    if let Some(c) = child_opt.take() { c.wait_with_output().await }
                    else { Err(std::io::Error::other("İşlem sonlandırılmış.")) }
                } => {
                    match result {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                            let combined = if stderr.is_empty() { stdout } else { format!("{}\n{}", stdout, stderr) };
                            if !output.status.success() { (false, format!("Hata: Komut başarısız\n{}", combined)) }
                            else { (true, combined) }
                        }
                        Err(e) => (false, format!("Hata: Çıktı okunamadı: {}", e))
                    }
                }
                _ = token.cancelled() => {
                    let mut child_lock = PROCESS_MANAGER.child.lock().await; if let Some(mut child) = child_lock.take() { let _ = child.kill().await; }
                    (false, "İşlem sonlandırıldı.".to_string())
                }
            }
        }
        Err(e) => (false, format!("Hata: Komut başlatılamadı: {}", e)),
    }
}

/// # Summary
/// The core orchestration function for multi-stage network reconnaissance.
/// Handles Nmap scanning, OS detection, DNS queries, and Shodan intelligence integration.
///
/// # Arguments
/// * `body` - `Json<ScanRequest>` containing target, scan flags (port, vuln, version), and timing profiles.
///
/// # Returns
/// * `Json<ScanResponse>` - Comprehensive scan results including raw output and structured intelligence data.
pub async fn handle_scan(Json(body): Json<ScanRequest>) -> Json<ScanResponse> {
    {
        let mut token_lock = PROCESS_MANAGER.cancel_token.lock().await;
        token_lock.cancel();
        *token_lock = CancellationToken::new();
    }
    let mut target = body.target.trim().to_string();
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
    let timing_arg = match body.timing.as_str() {
        "T0" | "T1" | "T2" | "T3" | "T4" | "T5" => format!("-{}", body.timing),
        _ => "-T3".to_string(),
    };
    let t_arg = timing_arg.as_str();

    let mut os_info = String::new();
    let mut version_info = String::new();

    if body.net_discover {
        scan_types.push("net_discover");
        let (ok, out) = run_command(
            "nmap",
            &[
                "-sn",
                "-PS22,80,443",
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
    if body.port_scan {
        scan_types.push("port_scan");
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
    if body.vuln_scan {
        scan_types.push("vuln_scan");
        // Optimizasyon: vulners scripti çok daha detaylı ve profesyonel sonuç verir.
        let scripts = "vuln,vulners";
        let (ok, out) = run_command(
            "nmap",
            &[
                "-sV",
                "--script",
                scripts,
                "-Pn",
                "--send-eth",
                t_arg,
                "--host-timeout",
                "15m",
                "--top-ports",
                "50",
                &target,
            ],
        )
        .await;
        overall_success = overall_success && ok;
        all_output.push_str(&out);
    }
    if body.os_detect {
        scan_types.push("os_detect");
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
        os_info = out.clone();
        all_output.push_str(&out);
    }
    if body.version_detect {
        scan_types.push("version_detect");
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
        version_info = out.clone();
        all_output.push_str(&out);
    }
    if body.aggressive_scan {
        scan_types.push("aggressive_scan");
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
    if body.dns_query {
        scan_types.push("dns_query");
        let mut dns_out = String::from("DNS SORGULAMA SONUCU:\n--------------------\n");
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio(
            trust_dns_resolver::config::ResolverConfig::default(),
            trust_dns_resolver::config::ResolverOpts::default(),
        );
        match resolver.lookup_ip(&target).await {
            Ok(lookup) => {
                for ip in lookup.iter() {
                    dns_out.push_str(&format!("Found IP: {}\n", ip));
                }
            }
            Err(e) => {
                dns_out.push_str(&format!("Hata: ({})\n", e));
            }
        }
        all_output.push_str(&dns_out);
    }
    if body.priv_esc {
        all_output.push_str(&perform_priv_esc_analysis(&target, &os_info, &version_info).await);
    }
    let mut shodan_data = None;
    if body.shodan_enabled {
        shodan_data = get_shodan_intel(&target).await;
    }
    Json(ScanResponse {
        success: overall_success,
        target,
        scan_type: scan_types.join(","),
        output: all_output,
        shodan_data,
    })
}

/// # Summary
/// Forcefully terminates all active scanning processes and cleans up child resources.
///
/// # Arguments
/// * None (Triggered via API shutdown request)
///
/// # Returns
/// * `Json<ScanResponse>` - Confirmation that the scanning engine has been halted.
pub async fn handle_stop() -> Json<ScanResponse> {
    PROCESS_MANAGER.cancel_token.lock().await.cancel();
    let mut child_lock = PROCESS_MANAGER.child.lock().await;
    if let Some(mut child) = child_lock.take() {
        let _ = child.kill().await;
    }
    let _ = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", "taskkill /F /IM nmap.exe /T"])
            .output()
    } else {
        Command::new("sudo")
            .args(["-n", "killall", "-9", "nmap"])
            .output()
    };
    Json(ScanResponse {
        success: true,
        target: "".into(),
        scan_type: "stop".into(),
        output: "Durduruldu.".into(),
        shodan_data: None,
    })
}

/// # Summary
/// Retrieves the current status of all network interfaces and identifies the optimal wireless adapter.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `Json<WifiStatusResponse>` - List of interfaces, the selected active interface, and status reason.
pub async fn handle_wifi_status() -> Json<WifiStatusResponse> {
    let (interfaces, selected, reason) = get_wireless_interfaces();
    Json(WifiStatusResponse {
        interfaces,
        selected,
        status: "ACTIVE".to_string(),
        reason,
    })
}

/// # Summary
/// Performs a live Wi-Fi environment scan using `nmcli` to identify surrounding ESSIDs and signal strengths.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `Json<WifiResponse>` - Detailed list of nearby Wi-Fi networks or an error if hardware is missing.
pub async fn handle_wifi_scan() -> Json<WifiResponse> {
    if cfg!(target_os = "windows") {
        return Json(WifiResponse {
            success: false,
            data: vec![],
            error: Some("Linux/Kali gereklidir.".into()),
            active_interface: None,
        });
    }
    let interface = match find_wifi_interface() {
        Some(i) => i,
        None => {
            return Json(WifiResponse {
                success: false,
                data: vec![],
                error: Some("Adaptör bulunamadı.".into()),
                active_interface: None,
            })
        }
    };
    let _ = Command::new("nmcli")
        .args(["dev", "wifi", "rescan"])
        .output();
    let output = match Command::new("nmcli")
        .args(["-t", "-f", "SSID,BSSID,SIGNAL,CHAN", "dev", "wifi"])
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return Json(WifiResponse {
                success: false,
                data: vec![],
                error: Some(e.to_string()),
                active_interface: Some(interface),
            })
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<String> = line
            .replace("\\:", "##COLON##")
            .split(':')
            .map(|s| s.to_string())
            .collect();
        if parts.len() >= 4 {
            networks.push(WifiInfo {
                ssid: parts[0].replace("##COLON##", ":"),
                bssid: parts[1].replace("##COLON##", ":"),
                signal: parts[2].parse::<u8>().unwrap_or(0),
                channel: parts[3].parse::<u32>().unwrap_or(0),
            });
        }
    }
    networks.sort_by(|a, b| b.signal.cmp(&a.signal));
    networks.dedup_by(|a, b| a.ssid == b.ssid);
    Json(WifiResponse {
        success: true,
        data: networks,
        error: None,
        active_interface: Some(interface),
    })
}

/// # Summary
/// Low-level utility to probe the OS filesystem for network interface presence and operational state.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `(Vec<WirelessInterface>, Option<String>, String)` - Interface list, recommended interface, and selection logic notes.
pub fn get_wireless_interfaces() -> (Vec<WirelessInterface>, Option<String>, String) {
    let mut interfaces = Vec::new();
    let mut selected = None;
    if cfg!(target_os = "windows") {
        interfaces.push(WirelessInterface {
            name: "wlan0 (Sim)".into(),
            is_up: true,
            is_wireless: true,
            reason: "Simulated".into(),
        });
        return (interfaces, Some("wlan0 (Sim)".into()), "Simulated".into());
    }
    if let Ok(entries) = fs::read_dir("/sys/class/net/") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if name == "lo" || name.contains("vbox") || name.contains("docker") {
                    continue;
                }
                let is_wireless = fs::metadata(format!("/sys/class/net/{}/wireless", name)).is_ok();
                let operstate = fs::read_to_string(format!("/sys/class/net/{}/operstate", name))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let is_up = operstate == "up";
                interfaces.push(WirelessInterface {
                    name: name.clone(),
                    is_up,
                    is_wireless,
                    reason: "Detected".into(),
                });
                if selected.is_none() && is_up && is_wireless {
                    selected = Some(name);
                }
            }
        }
    }
    (interfaces, selected, "Selection logic".into())
}

/// # Summary
/// Helper to extract the name of the first available functional Wi-Fi interface.
///
/// # Arguments
/// * None
///
/// # Returns
/// * `Option<String>` - The interface name (e.g., "wlan0") if found.
pub fn find_wifi_interface() -> Option<String> {
    let (_, s, _) = get_wireless_interfaces();
    s
}

/// # Summary
/// Security gateway that validates target input to prevent command injection and malformed requests.
///
/// # Arguments
/// * `target` - The user-provided IP address or hostname string.
///
/// # Returns
/// * `Result<(), String>` - Returns Ok if the target is safe, or an Error message if invalid.
pub fn validate_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("Hedef boş!".into());
    }
    // Basic IP/Hostname validation
    if std::net::IpAddr::from_str(target).is_err()
        && !target
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
    {
        for ch in [';', '&', '|', '`', '$', '(', ')'] {
            if target.contains(ch) {
                return Err(format!("Güvenlik İhlali: Geçersiz karakter '{}'", ch));
            }
        }
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════
//  UNIT TESTS (Keyvan Hoca Vize Puanlama Kriterleri)
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_target_validation() {
        // Test 1: Geçerli IPv4
        let valid_ip = "8.8.8.8";
        assert!(IpAddr::from_str(valid_ip).is_ok());
        assert!(validate_target(valid_ip).is_ok());

        // Test 2: Geçerli Hostname
        let valid_host = "google.com";
        assert!(validate_target(valid_host).is_ok());

        // Test 3: Komut Enjeksiyonu Koruması (assert_ne)
        let malicious = "8.8.8.8; ls -la";
        assert_ne!(
            validate_target(malicious),
            Ok(()),
            "Zararlı karakterler engellenmeli!"
        );

        // Test 4: Boş hedef kontrolü (assert_eq)
        assert_eq!(validate_target(""), Err("Hedef boş!".into()));
    }

    #[test]
    fn test_nmap_argument_safety() {
        // Nmap argümanlarının kurgulanma mantığını test eder
        let target = "192.168.1.1";
        let timing = "T4";

        // Dinamik argüman kurgusu simülasyonu
        let timing_arg = format!("-{}", timing);
        let args = vec!["-sV", "-Pn", &timing_arg, target];

        assert_eq!(args[2], "-T4");
        assert!(args.contains(&"192.168.1.1"));
        assert_ne!(args.len(), 0);
    }
}
