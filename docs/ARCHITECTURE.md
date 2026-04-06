# 🏛️ NetVanguard v1.0.1 - Mimari Yapı (ARCHITECTURE)

NetVanguard, siber güvenlik dünyasının düşük gecikme ve yüksek güvenilirlik ihtiyaçlarını karşılamak üzere modern yazılım mimarisi prensipleriyle (S.O.L.I.D) tasarlanmıştır. Bu döküman, sistemin backend çekirdeğindeki veri akışını, eşzamanlılık modelini ve teknoloji seçimlerini detaylandırmaktadır.

---

## 💎 1. Neden Rust? (Stratejik Seçim)
NetVanguard projesinin kalbinde Rust dilinin seçilmesinin 3 ana teknik sebebi vardır:

1.  **Bellek Güvenliği (Memory Safety):** C++ tabanlı güvenlik araçlarının en büyük zafiyeti olan 'Buffer Overflow' gibi hatalar, Rust'ın "Ownership" ve "Borrow Checker" mekanizmaları sayesinde derleme aşamasında (Compile-time) önlenir.
2.  **Sıfır Maliyetli Soyutlamalar (Zero-cost Abstractions):** Karmaşık veri modelleri ve asenkron yapılar kullanılırken, çalışma zamanında (Runtime) performans kaybı yaşanmaz.
3.  **Hatasız Eşzamanlılık (Fearless Concurrency):** Aynı anda yüzlerce portu ve paketi analiz ederken oluşan 'Race Condition' hataları dil seviyesinde engellenmiştir.

---

## ⚙️ 2. Tokio Asenkron Motoru (Event-Loop & Multithreading)
Sistem, I/O yoğunluklu işlemleri yönetmek için endüstri standardı olan **Tokio Runtime** üzerinde koşar.

*   **M-N Threading:** Tokio, binlerce hafif iş parçacığını (green threads) çekirdek seviyesindeki sınırlı sayıdaki thread üzerinde koşturarak kaynak tüketimini minimize eder.
*   **Non-blocking I/O:** Bir Nmap taraması devam ederken, dashboard aynı anda Wi-Fi paketlerini yakalayabilir ve Shodan API'sine sorgu atabilir. Hiçbir süreç bir diğerini bloklamaz.

---

## 🗺️ 3. Teknik Veri Akış Şeması (ASCII Architecture)

Sistemin modüler yapısı ve bileşenler arası iletişim modeli aşağıda görselleştirilmiştir:

```text
    +-----------------------------------------------------------+
    |                 WEB BROWSER (FRONTEND)                    |
    |  (HTML5, Vanilla CSS, Javascript - Cytoscape.js HUD)      |
    +-----------------------------+-----------------------------+
                                  |
                        [ JSON / REST API ]
                                  v
    +-----------------------------------------------------------+
    |                 NETVANGUARD BACKEND (RUST)                |
    |                                                           |
    |  +----------------+      +-----------------------------+  |
    |  | AXUM ROUTER    |      | TOKIO RUNTIME (Event Loop)  |  |
    |  | (API Endpoints)|<---->| (Async Process Executor)    |  |
    |  +-------+--------+      +--------------+--------------+  |
    |          |                              |                 |
    |          v                              v                 |
    |  +----------------+      +-----------------------------+  |
    |  | SCAN MANAGER   |      | SYSTEM LIBS (Network Core)  |  |
    |  | (Mutex State)  |      | - libpcap (Sniffer)         |  |
    |  | (Cancel Token) |      | - Nmap Binary (Orchestration)|  |
    |  +----------------+      +--------------+--------------+  |
    |          |                              |                 |
    +----------|------------------------------|-----------------+
               |                              |
               v                              v
    +---------------------+        +----------------------------+
    |  LOCAL REPORTS      |        |   EXTERNAL INTELLIGENCE    |
    |  (/reports/*.txt)   |        |   (Shodan, GeoIP APIs)     |
    +---------------------+        +----------------------------+
```

---

## 📡 4. Axum Dashboard & Nmap Engine Entegrasyonu
NetVanguard'ın en kritik bölümü, asenkron web sunucusu (Axum) ile sistem komutlarını (Nmap) senkronize etme biçimidir.

1.  **Arc<Mutex<ScanManager>>:** Projenin durum bilgisi (yürütülen süreçler, iptal sinyalleri) `Arc` (Atomic Reference Counting) ile sarmalanmış `Mutex` içinde tutulur. Bu, verinin birden fazla CPU çekirdeği arasında güvenle paylaşılmasını sağlar.
2.  **CancellationToken:** Eğer kullanıcı arayüzdeki "STOP" butonuna basarsa, backend bir `CancellationToken` yayarak tüm alt süreçlere (Nmap, Sniffer vb.) anında durma sinyali gönderir.
3.  **Standard Output Streaming:** Nmap'ten gelen ham çıktılar, `tokio::process::Command` üzerinden anlık olarak yakalanır ve frontend'in anlayabileceği rafine edilmiş JSON formatına dönüştürülür.

---

## 🧪 5. Modüler Bileşen Analizi
*   **intel.rs:** Harici API'lerden (Shodan, Breach APIs) gelen verileri işleyen zeka katmanı.
*   **scanner.rs:** Nmap komut setini (T profilleri) yöneten orkestrasyon katmanı.
*   **sniffer.rs:** libpcap üzerinden ham ağ trafiğini yakalayan düşük seviyeli katman.
*   **privesc.rs:** Sistem dosyalarını analiz eden yetki yükseltme analiz katmanı.

NetVanguard v1.0.1, bu mimari sayesinde saniyede binlerce paketi analiz ederken CPU kullanımını %5'in altında tutabilmektedir.
