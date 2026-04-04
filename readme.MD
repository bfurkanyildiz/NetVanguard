<p align="center">
  <img src="static/img/banner.png" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.0.1-cyan?style=for-the-badge&logo=github" alt="Version">
  <img src="https://img.shields.io/badge/Rust-ASYNCHRONOUS-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-blue?style=for-the-badge" alt="Platform">
</p>

---

# 🛡️ NetVanguard v1.0.1
### *Hybrid Intelligence & Attack Surface Analyzer*

**NetVanguard**, modern siber güvenlik ihtiyaçları için geliştirilmiş, yüksek performanslı bir **Hibrit İstihbarat ve Saldırı Yüzeyi Analizörüdür**. Sadece bir ağ tarayıcısı değil, aynı zamanda pasif istihbarat (OSINT), aktif trafik analizi (Sniffing) ve yetki yükseltme (PrivEsc) vektörlerini tek bir çatı altında toplayan endüstriyel bir güvenlik paketidir.

---

## 🚀 Ana Modüller ve Kabiliyetler

### 1. 🔍 Gelişmiş Ağ Tarama (Nmap Engine)
NetVanguard, Nmap'in gücünü modern bir arayüzle birleştirir.
- **Hız Seçenekleri (Timing):** Gizlilik odaklı `T0` (Paranoid) modundan, agresif `T5` (Insane) moduna kadar tam kontrol.
- **Servis & Versiyon Tespiti:** Açık portların arkasındaki servislerin gerçek sürümlerini tespit eder.
- **İşletim Sistemi Analizi:** Hedef cihazın OS parmak izini çıkarır.
- **Vulnerability (Zafiyet) Taraması:** Nmap Scripting Engine (NSE) kullanarak bilinen açıkları otomatik tarar.

### 2. 🌐 Global Intelligence (OSINT & Geo)
Hedefi sadece IP olarak değil, bir kimlik olarak analiz eder.
- **Shodan Entegrasyonu:** Hedef IP'nin internet üzerindeki geçmişi, açık portları ve bilinen zaafları (CVE).
- **Coğrafi Konum:** IP tabanlı konum tespiti (Şehir, ISP, ASN bilgileri).
- **DNS & TLS Analizi:** Pasif DNS sorguları ve HTTPS sertifikalarından SNI ayrıştırma.

### 3. 📂 Metadata & Sızıntı Analizi (Advanced Intel)
- **Metadata (EXIF) Analizörü:** Görsel ve döküman dosyalarındaki gizli meta verileri (GPS, cihaz bilgisi, yazılım sürümü) milisaniyeler içinde ortaya çıkarır.
- **Sızıntı Tespiti (Breach Detection):** *XposedOrNot* API entegrasyonu ile e-posta adreslerinin geçmiş veri sızıntılarında yer alıp almadığını kontrol eder.

### 4. ⚔️ #L10 Yetki Yükseltme Analizörü (PrivEsc)
Sistem sızma sonrası aşamalar için özel olarak tasarlanmıştır.
- **SUID/GUID Kontrolü:** Yanlış yapılandırılmış kritik sistem dosyalarını tespit eder.
- **Kernel Exploit Suggester:** İşletim sistemi çekirdek sürümüne göre potansiyel exploitleri raporlar.
- **Capability Analizi:** Linux yeteneklerini (capabilities) tarayarak yetki yükseltme yollarını bulur.

### 5. 📡 Network Radar & Sniffer
- **Real-Time Sniffer:** L2/L3 seviyesinde paket yakalama ve TLS SNI üzerinden alan adı tespiti.
- **Wi-Fi Radar:** Çevredeki tüm kablosuz ağları ve sinyal güçlerini haritalandırır.

---

## 📸 Demo
![NetVanguard Demo](demo.gif)
*Not: Demo GIF placeholder'ıdır.*

---

## 🏛️ Mimari Yapı (Modular Refactor)

```mermaid
graph TD
    A[main.rs] --> B[models.rs]
    A --> C[intel.rs]
    A --> D[scanner.rs]
    A --> E[sniffer.rs]
    A --> F[privesc.rs]
    
    subgraph "Intel Module"
    C --> C1(Shodan / Geo)
    C --> C2(Metadata / EXIF)
    C --> C3(Breach Check)
    end
```

---

## 🛠️ Kurulum (Installation)

```bash
# Kurulum ve Hazırlık
chmod +x setup.sh
./setup.sh

# Çalıştırma
sudo cargo run
```

---

## ⚖️ Yasal Uyarı (Legal Disclaimer)

> [!CAUTION]
> NetVanguard, yalnızca **eğitim** ve **etik sızma testi** amaçlıdır. Yetkisiz kullanım yasal sorumluluk doğurur.

---

<p align="center">
  Developed with ❤️ by <b>Baha Furkan Yıldız</b> | v1.0.1
</p>
