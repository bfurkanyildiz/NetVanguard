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

# ==============================================================================
# STOP ARGUMENT CONTROL
# ==============================================================================
if [ "$1" == "--stop" ]; then
    echo -e "${RED}[!] NetVanguard Durduruluyor...${NC}"
    sudo pkill -9 netvanguard 2>/dev/null || true
    if command -v fuser &> /dev/null; then
        sudo fuser -k 8080/tcp 2>/dev/null || true
    fi
    echo -e "${GREEN}[+] Tüm süreçler temizlendi.${NC}"
    exit 0
fi

# ==============================================================================
# PRE-CLEANUP (Kurşun Geçirmez Port Temizliği)
# ==============================================================================
echo -e "${YELLOW}[*] Eski NetVanguard süreçleri ve port 8080 temizleniyor...${NC}"

# 1. Kill by name
sudo pkill -9 netvanguard 2>/dev/null || true

# 2. Kill by port (The nuclear option for 8080)
if command -v fuser &> /dev/null; then
    sudo fuser -k 8080/tcp 2>/dev/null || true
elif command -v lsof &> /dev/null; then
    sudo lsof -t -i:8080 | xargs sudo kill -9 2>/dev/null || true
fi

sleep 1

# 1. Root Control
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] HATA: Bu betik sudo yetkisi ile çalıştırılmalıdır.${NC}" 
   exit 1
fi

# 2. System Intelligence (Docker vs Native)
echo -e "${BLUE}[*] Sistem Analizi Yapılıyor...${NC}"

# Check for Docker
DOCKER_READY=false
if command -v docker &> /dev/null && (command -v docker-compose &> /dev/null || docker compose version &> /dev/null); then
    echo -e "${GREEN}[+] Docker Tespit Edildi.${NC}"
    DOCKER_READY=true
else
    echo -e "${YELLOW}[!] Docker Bulunamadı. Yerel Kuruluma (Native) Geçiliyor...${NC}"
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
# PATH A: DOCKER DEPLOYMENT
# ==============================================================================
if [ "$DOCKER_READY" = true ]; then
    echo -e "${CYAN}>>> Docker Üzerinden Yayına Geçiliyor (Host Mode)...${NC}"
    docker-compose up --build -d || docker compose up --build -d
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✅ NetVanguard Konteyner İçinde Başarıyla Başlatıldı!${NC}"
        echo -e "${BLUE}Dashboard Adresi:${NC} ${YELLOW}http://localhost:8080${NC}"
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
DEPENDENCIES=("build-essential" "pkg-config" "libssl-dev" "libpcap-dev" "nmap" "curl")
for pkg in "${DEPENDENCIES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] $pkg kuruluyor...${NC}"
        apt-get install -y "$pkg"
    fi
done

echo -e "${BLUE}[*] Nmap script veritabanı senkronize ediliyor...${NC}"
sudo nmap --script-updatedb > /dev/null 2>&1

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
        APP_PID=$!
        echo -e "${GREEN}[+] Uygulama Arka Planda Başlatıldı (PID: $APP_PID).${NC}"
        echo -e "${BLUE}Dashboard Adresi:${NC} ${YELLOW}http://localhost:8080${NC}"
        
        echo -e "\n${YELLOW}══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}[!] NetVanguard Arka Planda Çalışıyor.${NC} ${WHITE}Terminali kapatmanız uygulamayı durdurmaz.${NC}"
        echo -e "${YELLOW}[!] Uygulamayı tamamen kapatmak için:${NC} ${CYAN}./setup.sh --stop${NC} ${YELLOW}veya${NC} ${CYAN}Ctrl+C${NC} ${WHITE}(bu script içindeyken).${NC}"
        echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}\n"

        # Signal Handler for Ctrl+C
        trap "echo -e '\n${RED}[!] Durduruluyor...${NC}'; kill $APP_PID 2>/dev/null; exit" INT
        
        # Keep terminal open
        echo -e "${CYAN}[*] İzleme başlatılıyor (Logs)... Durdurmak için [Enter] veya Ctrl+C yapın.${NC}"
        tail -f netvanguard.log & 
        LOG_TAIL_PID=$!
        
        read -p ""
        kill $APP_PID $LOG_TAIL_PID 2>/dev/null
        echo -e "${GREEN}[+] Temizlendi ve Kapatıldı.${NC}"
    else
        echo -e "${RED}[!] Başlatma Hatası! Manuel Komut: sudo ./target/release/netvanguard${NC}"
    fi
else
    echo -e "${RED}[!] Derleme Hatası. Lütfen logları kontrol edin.${NC}"
fi

exit 0
