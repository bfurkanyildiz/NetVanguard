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
# PATH A: DOCKER DEPLOYMENT
# ==============================================================================
if [ "$DOCKER_READY" = true ]; then
    echo -e "${CYAN}>>> Docker Üzerinden Yayına Geçiliyor (Host Mode)...${NC}"
    docker compose up --build -d
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}✅ NetVanguard Konteyner İçinde Başarıyla Başlatıldı!${NC}"
        echo -e "${BLUE}Panel Adresi:${NC} ${YELLOW}http://localhost:8080${NC}"
        echo -e "${BLUE}Durdurmak İçin:${NC} docker compose down"
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

# Rust Check
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}[!] Rust bulunamadı, kuruluyor...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo -e "${BLUE}[*] Proje Derleniyor (Cargo Build)...${NC}"
cargo build --release

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✅ NetVanguard Yerel Olarak Derlendi!${NC}"
    echo -e "${YELLOW}Başlatmak İçin:${NC} sudo ./target/release/netvanguard veya ./run.sh"
    echo -e "${BLUE}Panel Adresi:${NC} http://localhost:8080"
else
    echo -e "${RED}[!] Derleme Hatası. Lütfen logları kontrol edin.${NC}"
fi

exit 0
