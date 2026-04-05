use crate::intel::{parse_dns_answer, parse_dns_name, parse_tls_sni, DNS_CACHE, META_GOOGLE_IPS};
use crate::models::*;
use axum::Json;
use rand::Rng;
use std::collections::HashMap;

/// # Summary
/// Real-time Deep Packet Inspection (DPI) engine.
/// Orchestrates live traffic capture via libpcap/wpcap and performs heuristic threat analysis.
///
/// # Logic Flow
/// 1. Enumerates system network interfaces to identify a suitable capture point.
/// 2. Initializes a promiscuous mode capture stream (100ms timeout for non-blocking UI).
/// 3. Parses Layer 3/4 headers to extract IP protocols, ports, and metadata (DNS/SNI).
/// 4. If no hardware is present, transitions to High-Fidelity Traffic Simulation mode.
///
/// # Returns
/// * `Json<SnifferResponse>` - Vector of analyzed packets with associated risk scores and threat levels.
pub async fn handle_sniffer() -> Json<SnifferResponse> {
    let devices = pcap::Device::list().unwrap_or_default();
    let device = devices
        .into_iter()
        .find(|d| !d.flags.is_loopback() && !d.addresses.is_empty())
        .or_else(|| pcap::Device::lookup().ok().flatten());

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
                    if data.len() < 34 {
                        continue;
                    }

                    let proto_num = data[23];
                    let proto = match proto_num {
                        1 => "ICMP",
                        6 => "TCP",
                        17 => "UDP",
                        _ => "OTHER",
                    };

                    let src = format!("{}.{}.{}.{}", data[26], data[27], data[28], data[29]);
                    let dest = format!("{}.{}.{}.{}", data[30], data[31], data[32], data[33]);

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

                    if is_multicast {
                        p_info.threat_level = "SAFE".to_string();
                        p_info.risk_score = 0;
                        p_info.reason = Some("Local Discovery (SSDP/mDNS)".to_string());
                    }

                    for (prefix, label) in META_GOOGLE_IPS {
                        if dest.starts_with(prefix) {
                            p_info.threat_level = "SAFE".to_string();
                            p_info.dest = format!("{} ({})", dest, label);
                            break;
                        }
                    }

                    if let Ok(cache) = DNS_CACHE.lock() {
                        if let Some(domain) = cache.get(&dest) {
                            p_info.domain = Some(domain.clone());
                            p_info.dest = domain.clone();
                            p_info.threat_level = "SAFE".to_string();
                        }
                    }

                    if data.len() >= 42 {
                        let s_port = u16::from_be_bytes([data[34], data[35]]);
                        let d_port = u16::from_be_bytes([data[36], data[37]]);

                        if proto_num == 17 && (d_port == 53 || s_port == 53) {
                            if s_port == 53 {
                                if let Some((ip, domain)) = parse_dns_answer(&data[42..]) {
                                    if let Ok(mut cache) = DNS_CACHE.lock() {
                                        cache.insert(ip, domain);
                                    }
                                }
                            } else {
                                if let Some(domain) = parse_dns_name(&data[42..]) {
                                    *domain_counts.entry(domain.clone()).or_insert(0) += 1;
                                    p_info.domain = Some(domain.clone());
                                    p_info.dest = format!("QUERY: {}", domain);
                                }
                            }
                        }

                        if proto_num == 6 && d_port == 443 {
                            let ip_len = (data[14] & 0x0F) as usize * 4;
                            let tcp_len = ((data[14 + ip_len + 12] >> 4) & 0x0F) as usize * 4;
                            let payload_offset = 14 + ip_len + tcp_len;

                            if data.len() > payload_offset + 10 {
                                if let Some(sni) = parse_tls_sni(&data[payload_offset..]) {
                                    p_info.domain = Some(sni.clone());
                                    p_info.dest = format!("{} [HTTPS]", sni);
                                    p_info.threat_level = "SAFE".to_string();
                                    if let Ok(mut cache) = DNS_CACHE.lock() {
                                        cache.insert(dest.clone(), sni);
                                    }
                                }
                            }
                        }

                        if d_port == 4444 || d_port == 31337 {
                            p_info.risk_score = 10;
                            p_info.threat_level = "CRITICAL".to_string();
                            p_info.reason = Some("BACKDOOR ACTIVITY DETECTED".to_string());
                            active_threats += 1;
                        }
                    }

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

    if packets.is_empty() {
        is_simulated = true;
        let mut rng = rand::thread_rng();
        for _ in 0..15 {
            let src = format!("192.168.1.{}", rng.gen_range(2..254));
            let (dest, level, domain) = if rng.gen_bool(0.2) {
                (
                    "INSTAGRAM.COM [HTTPS]".to_string(),
                    "SAFE",
                    Some("instagram.com".to_string()),
                )
            } else if rng.gen_bool(0.2) {
                ("239.255.255.250".to_string(), "SAFE", None)
            } else {
                (
                    "8.8.8.8".to_string(),
                    "SAFE",
                    Some("google.com".to_string()),
                )
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
                reason: if level == "SAFE" {
                    None
                } else {
                    Some("Simulated Traffic".to_string())
                },
            });
        }
    }

    let top_domain = domain_counts
        .iter()
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
