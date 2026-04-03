#!/bin/bash

# ==============================================================================
# NetVanguard v1.1.0 - Automated Setup Script
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
echo -e "${YELLOW}>>> Setup Initializing...${NC}\n"

# 1. System Check
echo -e "${BLUE}[*] Checking operating system...${NC}"
if ! grep -qiE 'debian|ubuntu|kali' /etc/os-release 2>/dev/null; then
    echo -e "${RED}[!] Unsupported Operating System. This framework requires Debian, Ubuntu, or Kali Linux.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] System check passed.${NC}\n"

# 2. Dependencies (APT)
echo -e "${BLUE}[*] Updating package list and installing dependencies...${NC}"
sudo apt update -y
sudo apt install -y build-essential pkg-config libssl-dev libpcap-dev nmap tshark
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to install APT dependencies. Please check your internet connection and try again.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Dependencies installed successfully.${NC}\n"

# 3. Tshark Permissions (debconf silent settings)
echo -e "${BLUE}[*] Configuring tshark permissions...${NC}"
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo dpkg-reconfigure -f noninteractive wireshark-common
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Tshark permissions could not be configured automatically.${NC}"
else
    echo -e "${GREEN}[+] Tshark configured for non-root users.${NC}\n"
fi

# 4. Rust Check & Installation
echo -e "${BLUE}[*] Checking Rust installation...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${YELLOW}[!] Cargo not found. Installing Rust silently...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Check if rustup was successful
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to install Rust!${NC}"
        exit 1
    fi
    
    # Explicitly source the environment locally for this script session
    source "$HOME/.cargo/env"
    echo -e "${GREEN}[+] Rust installed successfully.${NC}\n"
else
    echo -e "${GREEN}[+] Cargo is already installed.${NC}\n"
fi

# 5. Build Project
echo -e "${BLUE}[*] Building NetVanguard optimized release...${NC}"
cargo build --release
if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Failed to build the project. Please check the compilation errors above.${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Project built successfully.${NC}\n"

# 6. Outro / Installation Details
echo -e "${CYAN}======================================================${NC}"
echo -e "${GREEN}   ✅ NETVANGUARD v1.0.0 SETUP COMPLETED SUCCESSFULLY   ${NC}"
echo -e "${CYAN}======================================================${NC}"
echo -e "\nTo start the application, navigate to the project directory and run:"
echo -e "${YELLOW}sudo ./target/release/netvanguard${NC}\n"
