# 🛠️ NetVanguard v1.0.1 - Kurulum Rehberi (INSTALLATION)

Bu döküman, NetVanguard hibrit güvenlik analizörünün Kali Linux ve benzeri Debian tabanlı dağıtımlar üzerinde sıfırdan nasıl kurulacağını, sistem gereksinimlerini ve karşılaşılabilecek olası sorunların çözümlerini detaylandırmaktadır.

---

## 📋 1. Sistem Gereksinimleri
NetVanguard, performansı maksimize etmek için Rust dilinin düşük seviyeli imkanlarını kullanır. Stabil bir çalışma için aşağıdaki donanım ve yazılım bileşenleri önerilir:

*   **İşletim Sistemi:** Kali Linux (Önerilen), Debian 11+, Ubuntu 22.04+ veya Arch Linux.
*   **İşlemci:** 2+ Çekirdek (Asenkron tarama süreçleri için paralel işleme kapasitesi önemlidir).
*   **Bellek (RAM):** Minimum 2 GB (Nmap NSE scriptleri ve yoğun trafik analizi için).
*   **Ağ**: Monitor mod destekleyen Wi-Fi adaptörü (Sadece Wi-Fi Radar modülü için gereklidir).

---

## 🛠️ 2. Temel Bağımlılıkların Kurulması

### 2.1. Sistem Paketleri
Öncelikle sistem depolarını güncelleyin ve projenin ihtiyaç duyduğu ağ kitaplıklarını kurun:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential libpcap-dev nmap curl git pkg-config libssl-dev
```

*   **libpcap-dev:** Ham paket yakalama (Sniffing) işlemleri için gereklidir.
*   **nmap:** Tüm aktif tarama motorunun kalbinde yer alır.
*   **pkg-config / libssl-dev:** HTTPS sorguları ve güvenli bağlantılar için derleme aşamasında gereklidir.

### 2.2. Rust Toolchain Kurulumu
NetVanguard, Rust 2021 Edition kullanmaktadır. `rustup` aracılığıyla en güncel stabil sürümü kurun:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Kurulum bittikten sonra mevcut terminal oturumuna path bilgilerini ekleyin:
```bash
source $HOME/.cargo/env
```

Doğrulamak için: `rustc --version` komutunu çalıştırın.

---

## 🚀 3. Projenin Derlenmesi ve Başlatılması

Proje dizinine gidin ve bağımlılıkları indirerek release modunda derleyin:

```bash
git clone https://github.com/bfurkanyildiz/NetVanguard.git
cd NetVanguard
cargo build --release
```

**Not:** İlk derleme, tüm asenkron kütüphanelerin (Tokio, Axum vb.) indirilmesi nedeniyle birkaç dakika sürebilir. Derleme bittikten sonra çalıştırılabilir dosya `target/release/netvanguard` dizininde oluşacaktır.

Sistemi otomatik başlatmak için hazırlanan scripti kullanmanız önerilir:
```bash
sudo chmod +x setup.sh
sudo ./setup.sh
```

---

## 🔍 4. Hata Giderme (Troubleshooting)

### 4.1. Permission Denied (Yetki Hatası)
Nmap ham paket gönderimi yaptığı için genellikle 'root' yetkisi ister. Eğer hata alıyorsanız `setup.sh` scriptini `sudo` ile çalıştırdığınızdan emin olun. Ayrıca `libpcap` için yetki atamak gerekebilir:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/netvanguard
```

### 4.2. Port 8080 Meşgul Hatası
Eğer `Address already in use` hatası alıyorsanız, önceki bir NetVanguard süreci açık kalmış olabilir. 
**Çözüm:**
```bash
sudo fuser -k 8080/tcp
```
*(NetVanguard v1.0.1 bu işlemi başlangıçta otomatik yapacak şekilde güncellenmiştir.)*

### 4.3. Cargo Lock / Komut Bulunamadı
Eğer `cargo: command not found` hatası alıyorsanız, Rust path bilgileri `~/.bashrc` veya `~/.zshrc` dosyanıza eklenmemiş demektir. Manuel eklemek için:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

---

## 🛡️ 5. Güvenlik Notu
NetVanguard'ı kurduğunuz makine üzerinde internete açık port bırakmamaya dikkat edin. Dashboard varsayılan olarak `0.0.0.0` üzerinde dinler, bu da yerel ağdaki herkesin erişebileceği anlamına gelir. İzole edilmiş bir pentest ortamı şiddetle tavsiye edilir.
