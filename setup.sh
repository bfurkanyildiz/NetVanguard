#!/bin/bash

# ==============================================================================
# NetVanguard v1.0.1 - Automated Setup Script (Intelligence Edition)
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
echo -e "${YELLOW}>>> NetVanguard v1.0.1 Kurulumu Başlatılıyor...${NC}\n"

# Root Control
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] HATA: Bu betik sudo yetkisi ile çalıştırılmalıdır.${NC}" 
   exit 1
fi

# 1. System Check
echo -e "${BLUE}[*] İşletim sistemi kontrol ediliyor...${NC}"
if ! grep -qiE 'debian|ubuntu|kali' /etc/os-release 2>/dev/null; then
    echo -e "${RED}[!] Desteklenmeyen İşletim Sistemi. Bu araç Debian, Ubuntu veya Kali Linux gerektirir.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Sistem uygun.${NC}\n"

# 2. Smart Dependency Check & Installation
echo -e "${BLUE}[*] Paket listesi tazeleniyor...${NC}"
sudo apt-get update -y

DEPENDENCIES=("build-essential" "pkg-config" "libssl-dev" "libpcap-dev" "nmap")

check_and_install() {
    local pkg=$1
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo -e "${GREEN}[+] $pkg zaten yüklü.${NC}"
    else
        echo -e "${YELLOW}[!] $pkg kuruluyor...${NC}"
        sudo apt install -y "$pkg"
        if [ $? -ne 0 ]; then
            echo -e "${RED}[!] HATA: $pkg kurulamadı!${NC}"
            exit 1
        fi
    fi
}

echo -e "${BLUE}[*] Gerekli bağımlılıklar kontrol ediliyor...${NC}"
for pkg in "${DEPENDENCIES[@]}"; do
    check_and_install "$pkg"
done
echo -e "${GREEN}[+] Tüm bağımlılıklar hazır.${NC}\n"

# 3. Rust/Cargo Check & Auto-Install
echo -e "${BLUE}[*] Rust geliştirme ortamı kontrol ediliyor...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}[!] Cargo (Rust) bulunamadı. Kurulum başlatılıyor...${NC}"
    
    # Ensure curl is installed for rustup
    if ! command -v curl &> /dev/null; then
        sudo apt-get install -y curl
    fi

    # Install Rust via rustup (Non-interactive)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Source environment
    source "$HOME/.cargo/env"
    
    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}[!] HATA: Rust kurulumu başarısız oldu.${NC}"
        echo -e "${YELLOW}[*] Lütfen manuel kurun: ${CYAN}https://rustup.rs${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Rust başarıyla kuruldu.${NC}"
else
    echo -e "${GREEN}[+] Rust/Cargo zaten yüklü.${NC}"
    echo -e "${CYAN}Rust Versiyon:${NC} $(rustc --version | awk '{print $2}')"
fi

# 4. Outro
echo -e "\n${CYAN}================================================================${NC}"
echo -e "${GREEN}   ✅ NetVanguard v1.0.1 Kurulumu Tamamlandı!   ${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "\nUygulamayı başlatmak için:"
echo -e "${YELLOW}sudo cargo run${NC}\n"
