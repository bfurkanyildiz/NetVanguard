#!/bin/bash

# ==============================================================================
# NetVanguard v1.0.1 - Smart Orchestration & Setup Script (Hybrid Edition)
# ==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print Banner
echo -e "${CYAN}"
echo "███╗   ██╗███████╗████████╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ "
echo "████╗  ██║██╔════╝╚══██╔══╝██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
echo "██╔██╗ ██║█████╗     ██║   ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
echo "██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
echo "██║ ╚████║███████╗   ██║    ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
echo "╚═╝  ╚═══╝╚══════╝   ╚═╝     ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ "
echo -e "${NC}"
echo -e "${YELLOW}>>> NetVanguard v1.0.1 Akıllı Kurulum Sistemi Başlatılıyor...${NC}\n"

# 1. Root Control
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] HATA: Bu betik sudo yetkisi ile çalıştırılmalıdır.${NC}" 
   exit 1
fi

# 2. System Intelligence (Docker vs Native)
echo -e "${BLUE}[*] Sistem Analizi Yapılıyor...${NC}"

# Check for Docker
DOCKER_READY=false
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    echo -e "${GREEN}[+] Docker Tespit Edildi.${NC}"
    DOCKER_READY=true
else
    echo -e "${YELLOW}[!] Docker Bulunamadı. Otomatik Kurulum Deneniyor...${NC}"
    apt-get update -y
    apt-get install -y docker.io docker-compose-v2
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Docker Başarıyla Kuruldu.${NC}"
        systemctl start docker
        DOCKER_READY=true
    else
        echo -e "${RED}[!] Docker Kurulumu Başarısız. Yerel Kuruluma (Native) Dönülüyor...${NC}"
    fi
fi

# ==============================================================================
# 0. HELPER: Detect Cargo Path
# ==============================================================================
get_cargo_bin() {
    if command -v cargo &> /dev/null; then
        echo "cargo"
    elif [ -x "$HOME/.cargo/bin/cargo" ]; then
        echo "$HOME/.cargo/bin/cargo"
    elif [ -x "/home/kali/.cargo/bin/cargo" ]; then
        echo "/home/kali/.cargo/bin/cargo"
    elif [ -x "/root/.cargo/bin/cargo" ]; then
        echo "/root/.cargo/bin/cargo"
    else
        echo ""
    fi
}

# ==============================================================================
# PATH & ENVIRONMENT FIX
# ==============================================================================
export PATH="$HOME/.cargo/bin:/home/kali/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
source "$HOME/.cargo/env" 2>/dev/null
source "/home/kali/.cargo/env" 2>/dev/null

# ==============================================================================
# 3. HELPER: Auto-Launch Dashboard
# ==============================================================================
launch_dashboard() {
    echo -e "${BLUE}[*] Dashboard'ın hazır olması bekleniyor (3 sn)...${NC}"
    sleep 3
    
    # Check if graphical interface is available
    if [ -n "$DISPLAY" ]; then
        echo -e "${GREEN}[+] Tarayıcı otomatik olarak açılıyor...${NC}"
        xdg-open "http://localhost:8080" > /dev/null 2>&1 &
    else
        echo -e "${YELLOW}[!] Grafik arayüzü bulunamadı. Lütfen manuel bağlanın: http://localhost:8080${NC}"
    fi
}

# ==============================================================================
# PATH A: DOCKER DEPLOYMENT
# ==============================================================================
if [ "$DOCKER_READY" = true ]; then
    echo -e "${CYAN}>>> Docker Üzerinden Yayına Geçiliyor (Host Mode)...${NC}"
    docker-compose up --build -d || docker compose up --build -d
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✅ NetVanguard Konteyner İçinde Başarıyla Başlatıldı!${NC}"
        echo -e "${BLUE}Dashboard Adresi:${NC} ${YELLOW}http://localhost:8080${NC}"
        launch_dashboard
        exit 0
    else
        echo -e "${RED}[!] Docker Başlatma Hatası. Yerel Kuruluma Deneniyor...${NC}"
    fi
fi

# ==============================================================================
# PATH B: LOCAL (NATIVE) DEPLOYMENT
# ==============================================================================
echo -e "${CYAN}>>> Yerel (Native) Kurulum Hazırlanıyor...${NC}"

# Dependencies
DEPENDENCIES=("build-essential" "pkg-config" "libssl-dev" "libpcap-dev" "nmap" "curl" "docker.io" "docker-compose")
for pkg in "${DEPENDENCIES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] $pkg kuruluyor...${NC}"
        apt-get install -y "$pkg"
    fi
done

# Rust Check
CARGO_PATH=$(get_cargo_bin)
if [ -z "$CARGO_PATH" ]; then
    echo -e "${YELLOW}[!] Rust bulunamadı, kuruluyor...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
    source "$HOME/.cargo/env" 2>/dev/null
    CARGO_PATH=$(get_cargo_bin)
fi

echo -e "${BLUE}[*] Proje Derleniyor (Cargo Build)...${NC}"
# Use detected cargo path
if [ -n "$CARGO_PATH" ]; then
    $CARGO_PATH build --release
else
    cargo build --release
fi

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✅ NetVanguard Yerel Olarak Derlendi!${NC}"
    echo -e "${YELLOW}[*] Program Otomatik Olarak Başlatılıyor...${NC}"
    
    # Run in the background to keep the script finished and show message
    nohup ./target/release/netvanguard > netvanguard.log 2>&1 &
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Uygulama Arka Planda Başlatıldı (PID: $!).${NC}"
        echo -e "${BLUE}Dashboard Adresi:${NC} ${YELLOW}http://localhost:8080${NC}"
        launch_dashboard
    else
        echo -e "${RED}[!] Başlatma Hatası! Manuel Komut: sudo ./target/release/netvanguard${NC}"
    fi
else
    echo -e "${RED}[!] Derleme Hatası. Lütfen logları kontrol edin.${NC}"
fi

exit 0
