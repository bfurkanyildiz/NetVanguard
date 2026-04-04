#!/bin/bash

# =================================================================
# 🛡️ NetVanguard v1.0.1 - Başlatıcı Script (Launcher)
# Geliştirici: Baha Furkan Yıldız
# =================================================================

# 1. Root Yetkisi Kontrolü
if [[ $EUID -ne 0 ]]; then
   echo -e "\e[1;33m[!] Bu program ağ paketlerini yakalamak için ROOT yetkisi gerektirir.\e[0m"
   echo -e "\e[1;32m[*] Sudo isteniyor...\e[0m"
   sudo "$0" "$@"
   exit $?
fi

# 2. Rust/Cargo Ortam Değişkenlerini Yükle
# Kullanıcının home dizinini sudo altındayken bile doğru bulmak için:
ORIGINAL_USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)

if [ -f "$ORIGINAL_USER_HOME/.cargo/env" ]; then
    source "$ORIGINAL_USER_HOME/.cargo/env"
elif [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi

# Standart yolu her ihtimale karşı PATH'e ekle
export PATH="$ORIGINAL_USER_HOME/.cargo/bin:$HOME/.cargo/bin:$PATH"

# 3. Derleme Kontrolü (Binary var mı?)
if [ ! -f "./target/debug/netvanguard" ]; then
    echo -e "\e[1;34m[*] Uygulama henüz derlenmemiş. İlk derleme başlatılıyor...\e[0m"
    cargo build
    
    if [ $? -ne 0 ]; then
        echo -e "\e[1;31m[!] Derleme hatası! Lütfen 'setup.sh' dosyasını çalıştırdığınızdan emin olun.\e[0m"
        exit 1
    fi
fi

# 4. Uygulamayı Başlat
echo -e "\e[1;32m[+] NetVanguard başlatılıyor...\e[0m"
./target/debug/netvanguard
