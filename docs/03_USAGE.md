# 📡 NetVanguard v1.0.1 - Kullanım Kılavuzu (USAGE)

NetVanguard, karmaşık ağ keşif süreçlerini ve istihbarat toplama işlemlerini tek bir merkezden yönetmenizi sağlayan profesyonel bir siber güvenlik aracıdır. Bu kılavuz, dashboard üzerindeki tüm modüllerin etkin şekilde nasıl kullanılacağını detaylandırmaktadır.

---

## 🚀 1. Dashboard Başlangıç ve Navigasyon
Uygulama başlatıldığında varsayılan olarak **http://localhost:8080** adresinde bir panel açılır. Panelde 3 ana bölüm bulunur:

1.  **Network Scanner:** Aktif tarama ve zafiyet tespiti modülü.
2.  **Wi-Fi Radar:** Çevredeki ağları ve bağlı cihazları analiz eden pasif sniffer.
3.  **Intel Map:** Hedef IP/Domain hakkında küresel istihbarat (OSINT) haritası.

---

## 🔍 2. Ağ Tarama Filtreleri ve Zamanlama (Timing) Modları
NetVanguard, Nmap motorunun tüm gücünü kullanıcıya sunar. Hedef girişi yaparken hızı ve gizliliği belirleyen "Hız Seçenekleri" kritik öneme sahiptir:

| Mod İsmi | Nmap Karşılığı | Kullanım Senaryosu |
| :--- | :--- | :--- |
| **İnsafsız (Insane)** | `T5` | Yerel ağlarda çok hızlı sonuç almak için. Engellenme riski yüksektir. |
| **Agresif (Aggressive)** | `T4` | Modern ağlarda standart hız. En dengeli performansı verir. |
| **Normal** | `T3` | Uzak sunucular ve bulut ortamları için güvenli tarama. |
| **Gizli (Sneaky)** | `T2` | Firewall/IDS sistemlerine yakalanmamak için yavaş paket gönderimi. |
| **Paranoid** | `T1` | Maksimum gizlilik. Taramalar saatler alabilir. |

---

## 📡 3. Wi-Fi Radar Modülü ve Donanım Uyumu
Wi-Fi Radar modülü, yakınınızdaki ağları (BSSID, SSID) ve sinyal güçlerini gerçek zamanlı olarak Cytoscape.js tabanlı ağ haritasına yansıtır.

*   **Donanım Gerekli:** Bu modülün simülasyon modundan çıkması için **Monitor Mod** destekli bir USB Wi-Fi adaptörü (Ralink RT5370, Atheros AR9271 vb.) gereklidir.
*   **BSSID Tespiti:** Aktif bir arayüz seçildikten sonra "START" butonuna basıldığında çevredeki baz istasyonları ve onlara bağlı istemciler (Clients) tespit edilerek görselleştirilir.
*   **Packet Sniffing:** Şifrelenmemiş paket verileri (HTTP, DNS sorguları) anlık olarak terminal ekranında akar.

---

## 🔬 4. Laboratuvar Çalışması: Metasploitable Testleri
NetVanguard, zafiyetli makineler (Metasploitable, Mutillidae vb.) üzerinde test edilmek üzere optimize edilmiştir.

### Adım Adım Zafiyet Analizi:
1.  **Hedef Tanımlama:** Metasploitable makinesinin IP adresini tarama kutusuna yazın.
2.  **Mod Seçimi:** `Agresif (T4)` modunu seçin ve `Service Version Detection` (Servis Versiyon Tespiti) seçeneğini işaretleyin.
3.  **Analizi Başlat:** Scan tuşuna basın. NetVanguard, açık portları bulduktan sonra NSE yardımıyla vsftpd 2.3.4 (Backdoor), UnrealIRCD zafiyetlerini otomatik olarak tespit edecektir.
4.  **Risk Analizi:** Dashboard üzerindeki risk barı, bulunan zafiyet sayısına göre kırmızıya renk değiştirecektir.

---

## 🌎 5. Küresel İstihbarat (Intel Map) Kullanımı
Bir IP adresi yazıp 'Fetch Intel' tuşuna bastığınızda:

*   **Geo-Location:** Hedefin harita üzerindeki fiziksel konumu saptanır.
*   **Breach Analizi:** Hedef e-posta adreslerinin sızdırılmış veri kümelerinde (Leaks) olup olmadığı kontrol edilir.
*   **Metadata Analizi:** 'Drop Image' alanına bir görsel bıraktığınızda, dosyanın EXIF verilerinden (GPS koordinatları, cihaz modeli, çekim tarihi) dijital ayak izi raporu çıkarılır.

---

## 📊 6. Raporlama ve Dışa Aktarma
Her tarama sonunda NetVanguard, `reports/` dizini altında tarih damgalı bir `.txt` raporu oluşturur. Bu raporlar akademik sunumlar ve profesyonel pentest raporları için kaynak teşkil eder. Dashboard üzerindeki "Download Report" butonu ile bu raporları tek tıkla cihazınıza indirebilirsiniz.
