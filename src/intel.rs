use crate::models::*;
use axum::{extract::{Query, Multipart}, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use std::io::Cursor;
use exif;

// ═══════════════════════════════════════════════════════════
//  INTELLIGENCE & CACHE STORAGE
// ═══════════════════════════════════════════════════════════

pub static DNS_CACHE: Lazy<StdMutex<HashMap<String, String>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

pub const META_GOOGLE_IPS: &[(&str, &str)] = &[
    ("31.13.", "META / INSTAGRAM"),
    ("157.240.", "META / FACEBOOK"),
    ("173.252.", "META / SERVICE"),
    ("142.250.", "GOOGLE SERVICE"),
    ("172.217.", "GOOGLE SERVICE"),
    ("8.8.8.8", "GOOGLE DNS"),
    ("1.1.1.1", "CLOUDFLARE DNS"),
];

// ═══════════════════════════════════════════════════════════
//  SHODAN & OSINT LOGIC
// ═══════════════════════════════════════════════════════════

pub async fn get_shodan_intel(ip: &str) -> Option<ShodanData> {
    let api_key = std::env::var("SHODAN_API_KEY").ok();
    if let Some(key) = api_key {
        let client = reqwest::Client::new();
        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, key);
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(json) = resp.json::<Value>().await {
                let city = json["city"].as_str().unwrap_or("Unknown").to_string();
                let isp = json["isp"].as_str().unwrap_or("Unknown").to_string();
                let asn = json["asn"].as_str().unwrap_or("Unknown").to_string();
                let mut ports = Vec::new();
                if let Some(ports_arr) = json["ports"].as_array() {
                    for p in ports_arr { if let Some(p_u64) = p.as_u64() { ports.push(p_u64 as u16); } }
                }
                let mut vulns = Vec::new();
                if let Some(vulns_arr) = json["vulns"].as_array() {
                    for v in vulns_arr { if let Some(v_str) = v.as_str() { vulns.push(v_str.to_string()); } }
                }
                return Some(ShodanData { city, isp, asn, ports, vulns });
            }
        }
    }

    let client = reqwest::Client::builder().timeout(Duration::from_secs(3)).build().ok()?;
    let url = format!("http://ip-api.com/json/{}?fields=status,city,isp,as,query", ip);
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<Value>().await {
            if json["status"] == "success" {
                let city = json["city"].as_str().unwrap_or("Unknown").to_string();
                let isp = json["isp"].as_str().unwrap_or("Unknown").to_string();
                let asn = json["as"].as_str().unwrap_or("Unknown").to_string();
                return Some(ShodanData { city, isp, asn, ports: vec![80, 443], vulns: vec!["SHODAN API KEY GEREKLİ".to_string()] });
            }
        }
    }
    None
}

pub async fn handle_geolocation(Query(params): Query<GeoParams>) -> impl IntoResponse {
    let target_ip = params.ip.trim();
    if target_ip.starts_with("192.168.") || target_ip.starts_with("10.") || target_ip.starts_with("127.") || target_ip.starts_with("172.16.") || target_ip == "localhost" {
        return Json(GeoResponse { status: "fail".to_string(), city: Some("Yerel Ağ".to_string()), district: Some("Merkez".to_string()), country: Some("Yerel Arayüz".to_string()), isp: Some("Private Network".to_string()), org: Some("Local Host".to_string()), lat: Some(0.0), lon: Some(0.0), as_info: None, message: Some("Yerel/Özel IP sorgulanamaz.".to_string()) });
    }
    let url = format!("http://ip-api.com/json/{}?fields=status,message,country,city,regionName,lat,lon,isp,org,as", target_ip);
    match reqwest::get(&url).await {
        Ok(resp) => { if let Ok(geo_data) = resp.json::<GeoResponse>().await { Json(geo_data) } else { Json(GeoResponse { status: "fail".to_string(), lat: None, lon: None, city: None, district: None, country: None, isp: None, org: None, as_info: None, message: Some("Parse hatası".to_string()) }) } }
        Err(e) => Json(GeoResponse { status: "fail".to_string(), city: Some("Bilinmiyor".to_string()), district: Some("Merkez".to_string()), country: Some("Bilinmiyor".to_string()), isp: Some("Hata".to_string()), org: Some("Hata".to_string()), lat: Some(0.0), lon: Some(0.0), as_info: None, message: Some(e.to_string()) }),
    }
}

pub async fn handle_breach(Json(body): Json<BreachRequest>) -> Json<BreachResponse> {
    let email = body.email.trim().to_lowercase();
    if !email.contains('@') { return Json(BreachResponse { success: false, found: false, sources: vec![], error: Some("Geçersiz e-posta".into()) }); }
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap_or_default();
    let url = format!("https://api.xposedornot.com/v1/check-email/{}", email);
    let response = match client.get(&url).send().await { Ok(resp) => resp, Err(_) => return Json(BreachResponse { success: false, found: false, sources: vec![], error: Some("API hatası".into()) }) };
    if response.status() == 404 { return Json(BreachResponse { success: true, found: false, sources: vec![], error: None }); }
    let data: Value = response.json().await.unwrap_or_default();
    let mut sources = Vec::new();
    if let Some(breach_list) = data.get("breaches").and_then(|b| b.as_array()) {
        for b in breach_list { if let Some(name) = b.get(0).and_then(|n| n.as_str()) { sources.push(name.to_string()); } }
    }
    Json(BreachResponse { success: true, found: !sources.is_empty(), sources, error: None })
}

pub async fn handle_metadata(mut multipart: Multipart) -> impl IntoResponse {
    let mut metadata = HashMap::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name().unwrap_or_default() != "file" { continue; }
        let file_name = field.file_name().unwrap_or("unknown").to_string();
        let data = match field.bytes().await { Ok(b) => b, Err(_) => continue };
        metadata.insert("Dosya Adı".to_string(), file_name);
        metadata.insert("Boyut".to_string(), format!("{:.2} MB", data.len() as f64 / 1_048_576.0));
        let mut cursor = Cursor::new(data);
        if let Ok(exif_data) = exif::Reader::new().read_from_container(&mut cursor) {
            for field in exif_data.fields() {
                metadata.insert(field.tag.to_string(), field.display_value().with_unit(&exif_data).to_string());
            }
        }
    }
    Json(json!({ "success": true, "data": metadata }))
}

// ═══════════════════════════════════════════════════════════
//  HELPER PARSERS (DNS/TLS)
// ═══════════════════════════════════════════════════════════

pub fn parse_dns_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 13 { return None; }
    let mut pos = 12;
    let mut domain = String::new();
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 { break; }
        if len > 63 || pos + 1 + len > payload.len() { return None; }
        if !domain.is_empty() { domain.push('.'); }
        domain.push_str(&String::from_utf8_lossy(&payload[pos + 1..pos + 1 + len]));
        pos += 1 + len;
    }
    if domain.is_empty() { None } else { Some(domain) }
}

pub fn parse_dns_answer(payload: &[u8]) -> Option<(String, String)> {
    if payload.len() < 12 { return None; }
    let mut pos = 12;
    let q_count = u16::from_be_bytes([payload[4], payload[5]]);
    if q_count == 0 { return None; }
    let mut domain = String::new();
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 { pos += 1; break; }
        if !domain.is_empty() { domain.push('.'); }
        domain.push_str(&String::from_utf8_lossy(&payload[pos + 1..pos + 1 + len]));
        pos += 1 + len;
    }
    pos += 4;
    let ans_count = u16::from_be_bytes([payload[6], payload[7]]);
    if ans_count == 0 || pos >= payload.len() { return None; }
    for _ in 0..ans_count {
        if pos >= payload.len() { break; }
        if payload[pos] & 0xC0 == 0xC0 { pos += 2; } else { while pos < payload.len() && payload[pos] != 0 { pos += 1; } pos += 1; }
        if pos + 10 > payload.len() { break; }
        let a_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rd_len = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if a_type == 1 && rd_len == 4 && pos + 4 <= payload.len() {
            return Some((format!("{}.{}.{}.{}", payload[pos], payload[pos+1], payload[pos+2], payload[pos+3]), domain));
        }
        pos += rd_len;
    }
    None
}

pub fn parse_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 11 || payload[0] != 0x16 || payload[5] != 0x01 { return None; }
    let mut pos = 5 + 4 + 2 + 32;
    if pos >= payload.len() { return None; }
    pos += 1 + payload[pos] as usize;
    if pos + 2 > payload.len() { return None; }
    pos += 2 + u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
    if pos >= payload.len() { return None; }
    pos += 1 + payload[pos] as usize;
    if pos + 2 > payload.len() { return None; }
    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    while pos + 4 <= extensions_end && pos + 4 <= payload.len() {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos+1]]);
        let ext_len = u16::from_be_bytes([payload[pos+2], payload[pos+3]]) as usize;
        pos += 4;
        if ext_type == 0 {
            pos += 2;
            let name_type = payload[pos];
            let name_len = u16::from_be_bytes([payload[pos+1], payload[pos+2]]) as usize;
            pos += 3;
            if name_type == 0 && pos + name_len <= payload.len() { return Some(String::from_utf8_lossy(&payload[pos..pos+name_len]).to_string()); }
        }
        pos += ext_len;
    }
    None
}
