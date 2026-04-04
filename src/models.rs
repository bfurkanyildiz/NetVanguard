use serde::{Deserialize, Serialize};
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ═══════════════════════════════════════════════════════════
//  PROCESS MANAGER MODELS
// ═══════════════════════════════════════════════════════════

pub struct ScanManager {
    pub child: Mutex<Option<Child>>,
    pub cancel_token: Mutex<CancellationToken>,
}

// ═══════════════════════════════════════════════════════════
//  SCANNER MODELS
// ═══════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    #[serde(default)]
    pub timing: String,
    #[serde(default)]
    pub port_scan: bool,
    #[serde(default)]
    pub vuln_scan: bool,
    #[serde(default)]
    pub os_detect: bool,
    #[serde(default)]
    pub dns_query: bool,
    #[serde(default)]
    pub version_detect: bool,
    #[serde(default)]
    pub aggressive_scan: bool,
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

#[derive(Serialize)]
pub struct ScanResponse {
    pub success: bool,
    pub target: String,
    pub scan_type: String,
    pub output: String,
    pub shodan_data: Option<ShodanData>,
}

#[derive(Serialize)]
pub struct EnvCheckResponse {
    pub nmap: bool,
    pub version: Option<String>,
    pub root: bool,
    pub os: String,
}

// ═══════════════════════════════════════════════════════════
//  SNIFFER MODELS
// ═══════════════════════════════════════════════════════════

#[derive(Serialize)]
pub struct PacketInfo {
    pub timestamp: String,
    pub src: String,
    pub dest: String,
    pub proto: String,
    pub len: usize,
    pub domain: Option<String>,
    pub risk_score: i32,
    pub threat_level: String, // "SAFE", "UNKNOWN", "SUSPICIOUS", "CRITICAL"
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct SnifferResponse {
    pub success: bool,
    pub packets: Vec<PacketInfo>,
    pub active_threats: i32,
    pub top_domain: Option<String>,
    pub active_interface: Option<String>,
    pub is_simulated: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════
//  INTEL & OSINT MODELS
// ═══════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct BreachRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct BreachResponse {
    pub success: bool,
    pub found: bool,
    pub sources: Vec<String>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GeoResponse {
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
pub struct GeoParams {
    pub ip: String,
}

// ═══════════════════════════════════════════════════════════
//  WIFI RADAR MODELS
// ═══════════════════════════════════════════════════════════

#[derive(Serialize)]
pub struct WifiInfo {
    pub ssid: String,
    pub bssid: String,
    pub signal: u8,
    pub channel: u32,
}

#[derive(Serialize)]
pub struct WifiResponse {
    pub success: bool,
    pub data: Vec<WifiInfo>,
    pub error: Option<String>,
    pub active_interface: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct WirelessInterface {
    pub name: String,
    pub is_up: bool,
    pub is_wireless: bool,
    pub reason: String,
}

#[derive(Serialize)]
pub struct WifiStatusResponse {
    pub interfaces: Vec<WirelessInterface>,
    pub selected: Option<String>,
    pub status: String,
    pub reason: String,
}
