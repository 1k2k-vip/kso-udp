#!/bin/bash

# Color Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

clear
echo -e "${CYAN}=====================================${NC}"
echo -e "${GREEN}    KSO UDP CUSTOM INSTALLER         ${NC}"
echo -e "${CYAN}=====================================${NC}"

# 1. ပထမဆုံး လိုအပ်တာတွေ အရင်သွင်းမယ်
echo -e "${CYAN}[1/3] Installing Dependencies...${NC}"
apt update -y && apt upgrade -y
apt install python3 wget -y

# 2. အကောင့်သစ် ဖွင့်ခြင်း အပိုင်း
echo -e "${CYAN}[2/3] User Account Creation${NC}"
read -p "ဘယ်နှစ်ယောက်စာ ဖွင့်ချင်လဲ (ဥပမာ- 5): " count
read -p "Password ဘာပေးမလဲ: " pass

for ((i=1; i<=count; i++))
do
    user="KSO-$i"
    useradd -e $(date -d "30 days" +"%Y-%m-%d") -s /bin/false $user
    echo "$user:$pass" | chpasswd
    echo -e "${GREEN}Created:${NC} $user | ${GREEN}Pass:${NC} $pass"
done

# 3. UDP Custom Server ကို မောင်းနှင်ခြင်း
echo -e "${CYAN}[3/3] Starting UDP Server...${NC}"
# ဒီနေရာမှာ သင့်ရဲ့ UDP Binary link ကို ထည့်ပါ (ဥပမာ)
# wget -O /usr/bin/udp-custom https://github.com/Anubis-Hacker/UDP-Custom/raw/main/udp-custom-linux-amd64
# chmod +x /usr/bin/udp-custom
# nohup udp-custom server > /dev/null 2>&1 &

echo -e "${CYAN}=====================================${NC}"
echo -e "${GREEN} INSTALLATION COMPLETE! ${NC}"
echo -e "Script Name: kso-udp.sh"
echo -e "All accounts are valid for 30 Days"
echo -e "${CYAN}=====================================${NC}"
