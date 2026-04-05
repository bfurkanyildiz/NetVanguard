use crate::scanner::run_command;

/// # Summary
/// Keyvan Hoca Evaluation Requirement: Dynamic Privilege Escalation Analysis.
/// Performs local system analysis (SUID/Kernel) or remote "Exploit Suggestions" based on target info.
pub async fn perform_priv_esc_analysis(target: &str, os_info: &str, version_info: &str) -> String {
    let mut report = String::from("\n[#PR01] YETKİ YÜKSELTME VE EXPLOIT ANALİZİ\n");
    report.push_str("══════════════════════════════════════════════\n\n");

    let is_local = target == "127.0.0.1" || target == "localhost";

    if is_local {
        report.push_str("> [YEREL] Sistem Yetki Matrisi Analiz Ediliyor...\n");

        // 1. SUID Check (Kritik Yetkilendirme Hataları)
        let (_, suid_out) = run_command(
            "find",
            &["/", "-perm", "-4000", "-type", "f", "-ls", "2>/dev/null"],
        )
        .await;
        let suid_count = suid_out.lines().count();
        report.push_str(&format!(
            "- Tespit Edilen SUID Dosyası: {} (Potansiyel vektörler)\n",
            suid_count
        ));

        // 2. Kernel Version & Exploit Mapping
        let (_, kernel) = run_command("uname", &["-rv"]).await;
        let k_str = kernel.trim().to_lowercase();
        report.push_str(&format!("- Mevcut Kernel: {}\n", k_str));

        if k_str.contains("dirty") || k_str.contains("4.4.0") {
            report.push_str("! UYARI: Olası DirtyCow (CVE-2016-5195) Tespiti!\n");
        }
        if k_str.contains("5.8") {
            report.push_str("! UYARI: Olası DirtyPipe (CVE-2022-0847) Tespiti!\n");
        }
    } else {
        report.push_str(&format!(
            "> [UZAK] Hedef Üzerinde Akıllı Analiz: {}\n",
            target
        ));
        report.push_str("> Tespit Edilen Verilere Göre Olası Sızma Yolları:\n\n");

        let combined = format!("{} {}", os_info.to_lowercase(), version_info.to_lowercase());
        let mut suggestions_found = false;

        if combined.contains("windows") {
            report.push_str("- [Kritik] MS17-010 (EternalBlue) Kontrol Edilmelidir.\n");
            report.push_str("- [Kritik] CVE-2022-26923 (Active Directory Domain PrivEsc).\n");
            suggestions_found = true;
        } else if combined.contains("linux") {
            report.push_str(
                "- [Önemli] Kernel Exploit Suggester üzerinden 2024-LTS verileri incelenmeli.\n",
            );
            report.push_str("- [Önemli] Sudo v1.8.x (CVE-2021-3156 Baron Samedit) olasılığı.\n");
            suggestions_found = true;
        }

        if combined.contains("ssh") {
            report.push_str("- [Servis] SSH Brute-Force veya LibSSH Zafiyeti (CVE-2018-10933).\n");
            suggestions_found = true;
        }
        if combined.contains("apache") || combined.contains("httpd") {
            report.push_str("- [Web] Apache Path Traversal (CVE-2021-41773).\n");
            suggestions_found = true;
        }

        // FALLBACK: Eğer veri çok azsa genel sızma önerilerini bas
        if !suggestions_found {
            report.push_str("! UYARI: Hedef OS tam olarak belirlenemedi (Genel Analiz Devrede):\n");
            report.push_str("- [Genel] Kernel Exploit (PwnKit/DirtyPipe) kontrol edilmeli.\n");
            report.push_str("- [Genel] Yanlış Yapılandırılmış Sudo/Setuid dosyaları aranmalı.\n");
            report.push_str("- [Genel] Servis versiyonları için 'searchsploit' kullanılmalı.\n");
        }

        report.push_str(
            "\n! NOT: Tam analiz için hedef üzerinde 'NetVanguard Agent' çalıştırılmalıdır.\n",
        );
    }

    report.push_str("\nAnaliz Matrisi Tamamlandı.\n");
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_priv_esc_logic_branching() {
        // Yerel analiz başlığı kontrolü
        let report = perform_priv_esc_analysis("127.0.0.1", "", "").await;
        assert!(report.contains("[YEREL]"));

        // Uzak analiz öneri mantığı kontrolü
        let remote_report =
            perform_priv_esc_analysis("8.8.8.8", "Windows Server 2016", "IIS 10.0").await;
        assert!(remote_report.contains("[UZAK]"));
        assert!(remote_report.contains("EternalBlue"));
    }
}
