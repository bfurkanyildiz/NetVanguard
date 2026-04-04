<p align="center">
  <a href="#-türkçe-versiyon">
    <img src="https://img.shields.io/badge/TÜRKÇE-red?style=for-the-badge" alt="Türkçe">
  </a>
  <a href="#-english-version">
    <img src="https://img.shields.io/badge/ENGLISH-blue?style=for-the-badge" alt="English">
  </a>
</p>

# 🛡️ NetVanguard v1.0.1
### *Hybrid Intelligence & Attack Surface Analyzer*

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.0.1-cyan?style=for-the-badge&logo=github" alt="Version">
  <img src="https://img.shields.io/badge/Rust-ASYNCHRONOUS-orange?style=for-the-badge&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Docker-READY-blue?style=for-the-badge&logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-green?style=for-the-badge&logo=kali-linux" alt="Platform">
</p>

---

<div id="turkish-version"></div>

## 🇹🇷 Türkçe Versiyon

**NetVanguard**, modern siber güvenlik ihtiyaçları için geliştirilmiş, yüksek performanslı bir **Hibrit İstihbarat ve Saldırı Yüzeyi Analizörüdür**. Sadece bir ağ tarayıcısı değil, aynı zamanda pasif istihbarat (OSINT), aktif trafik analizi (Sniffing) ve yetki yükseltme (PrivEsc) vektörlerini tek bir çatı altında toplayan endüstriyel bir güvenlik paketidir.

### 🚀 Ana Modüller ve Kabiliyetler

#### 1. 🔍 Gelişmiş Ağ Tarama (Nmap Engine)
- **Hız Seçenekleri (Timing):** Gizlilik odaklı `T0` modundan, agresif `T5` moduna kadar tam kontrol.
- **Vulnerability Taraması:** NSE kullanarak bilinen açıkları otomatik tarar.

#### 2. 🌐 Global Intelligence (OSINT & Geo)
- **Shodan Entegrasyonu:** Hedef IP'nin internet geçmişi ve bilinen zaafları (CVE).
- **DNS & TLS Analizi:** Pasif DNS sorguları ve HTTPS sertifikalarından SNI ayrıştırma.

#### 3. 📂 Metadata & Sızıntı Analizi
- **Metadata (EXIF) Analizörü:** Görsel ve dökümanlardaki gizli meta verileri ortaya çıkarır.
- **Sızıntı Tespiti:** *XposedOrNot* API ile e-posta sızıntı kontrolü.

#### 4. ⚔️ Yetki Yükseltme Analizörü (PrivEsc)
- **SUID/GUID Kontrolü:** Yanlış yapılandırılmış kritik sistem dosyalarını tespit eder.
- **Kernel Exploit Suggester:** Çekirdek sürümüne göre potansiyel exploitleri raporlar.

### ⚡ Akıllı Kurulum (Smart Setup)
Kali Linux üzerinde projeyi tek komutla kurmak ve başlatmak için (Docker veya Yerel otomatik seçilir):
```bash
git clone https://github.com/bfurkanyildiz/NetVanguard.git && cd NetVanguard
chmod +x setup.sh && sudo ./setup.sh
```

### 📸 Demo
![NetVanguard Demo](demo.gif)

### 🏛️ Mimari Yapı
```mermaid
graph TD
    A[main.rs] --> B[models.rs]
    A --> C[intel.rs]
    A --> D[scanner.rs]
    A --> E[sniffer.rs]
    A --> F[privesc.rs]
```

### ⚖️ Yasal Uyarı
> [!CAUTION]
> NetVanguard, yalnızca **eğitim** ve **etik sızma testi** amaçlıdır.

---

<div id="english-version"></div>

## 🇺🇸 English Version

**NetVanguard** is an industrial-grade **Hybrid Intelligence and Attack Surface Analyzer**. It consolidates advanced Nmap orchestration, real-time sniffing, and OSINT capabilities into a unified platform.

### 🚀 Core Modules
- **Scanning:** Advanced Nmap timing and script orchestration.
- **OSINT:** Shodan, Geo-IP, and DNS/TLS profiling.
- **Analysis:** Document metadata extraction and breach detection.
- **Security:** Privilege escalation vectors and kernel auditing.

### ⚡ Rapid Deployment (One-Liner)
Run the following command on a Kali Linux machine to clone, setup, and launch (Automated Docker/Local detection):
```bash
git clone https://github.com/bfurkanyildiz/NetVanguard.git && cd NetVanguard
chmod +x setup.sh && sudo ./setup.sh
```

### 🏛️ Architecture
```mermaid
graph TD
    A[main.rs] --> B[models.rs]
    A --> C[intel.rs]
    A --> D[scanner.rs]
    A --> E[sniffer.rs]
    A --> F[privesc.rs]
```

### ⚖️ Legal Disclaimer
> [!CAUTION]
> NetVanguard is intended for **educational** purposes only.

---

<p align="center">
  Developed with ❤️ by <b>Baha Furkan Yıldız</b> | v1.0.1
</p>
