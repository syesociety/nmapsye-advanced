#!/bin/bash

# Renk Kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

# Ekranı temizle
clear

# Nmap yüklü mü kontrol
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}Nmap sistemi üzerinde yüklü değil.${NC}"
    echo -e "${YELLOW}Kurulum için aşağıdaki komutu çalıştırabilirsiniz:${NC}"
    echo -e "${GREEN}sudo apt update && sudo apt install nmap${NC}"
    exit 1
fi

# Log klasörü ve dosyası oluşturma
mkdir -p logs
LOG_FILE="logs/nmap_log_$(date +'%Y-%m-%d_%H-%M-%S').txt"

ana_menu() {
    clear
    # ▒ SYE Nmap Açılış Görseli ▒
    echo -e "${MAGENTA}"
    echo "   ▄▄▄▄▄ ▀▄    ▄ ▄███▄              ▄   █▀▄▀█ ██   █ ▄▄  "
    echo "  █     ▀▄ █  █  █▀   ▀              █  █ █ █ █ █  █   █ "
    echo "▄  ▀▀▀▀▄    ▀█   ██▄▄            ██   █ █ ▄ █ █▄▄█ █▀▀▀  "
    echo " ▀▄▄▄▄▀     █    █▄   ▄▀         █ █  █ █   █ █  █ █     "
    echo "          ▄▀     ▀███▀           █  █ █    █     █  █    "
    echo "                                 █   ██   ▀     █    ▀   "
    echo "                                               ▀         "
    echo -e "${CYAN}"
    echo "        |\\___/|        "
    echo "       (= o.o =)       "
    echo "        > ^ <          "
    echo -e "${NC}"
    echo -e "${CYAN}🔍 SYE NMAP Ana Menü - Bir kategori seçin (1-10)${NC}"
    echo -e "${YELLOW}Her kategori 10 detaylı seçenek içerir. Tüm fonksiyonlarıyla 100 komut!${NC}"
    echo -e "${GREEN}"
    echo "1) Port Taramaları"
    echo "2) Servis & Versiyon Bilgisi"
    echo "3) OS Tespiti"
    echo "4) Firewall ve Filtre Kontrolleri"
    echo "5) NSE Script Taramaları"
    echo "6) Ağ Keşfi ve Topoloji"
    echo "7) Hız & Zamanlama Ayarları"
    echo "8) Hedef Belirleme Teknikleri"
    echo "9) Spoofing / Fragmentation Teknikleri"
    echo "10) Kombinasyon Örnekleri"
    echo "99) Çıkış"
    echo -e "${NC}"
    read -p "Seçiminizi yapın (1-10 | 99): " secim

    case $secim in
        1) kategori1 ;;
        2) kategori2 ;;
        3) kategori3 ;;
        4) kategori4 ;;
        5) kategori5 ;;
        6) kategori6 ;;
        7) kategori7 ;;
        8) kategori8 ;;
        9) kategori9 ;;
        10) kategori10 ;;
        99) echo "Görüşürüz!" && exit 0 ;;
        *) echo "Geçersiz seçim"; sleep 1; ana_menu ;;
    esac
}

# Kategori 1: Port Taramaları
kategori1() {
    clear
    echo -e "${BLUE}Port Taramaları - Bir işlem seçin:${NC}"
    echo "1) Hızlı tarama (-F)"
    echo "2) Belirli portları tara (-p)"
    echo "3) Tüm portları tara (-p-)"
    echo "4) TCP SYN taraması (-sS)"
    echo "5) TCP connect taraması (-sT)"
    echo "6) UDP taraması (-sU)"
    echo "7) Xmas taraması (-sX)"
    echo "8) Null taraması (-sN)"
    echo "9) ACK taraması (-sA)"
    echo "10) Window taraması (-sW)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) nmap -F "$hedef" | tee -a "$LOG_FILE" ;;
        2) read -p "Port(lar): " port; nmap -p "$port" "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -p- "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap -sS "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -sT "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap -sU "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -sX "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap -sN "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -sA "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -sW "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori1
}

# Kategori 2: Servis & Versiyon Bilgisi
kategori2() {
    clear
    echo -e "${BLUE}Servis & Versiyon Bilgisi - Bir işlem seçin:${NC}"
    echo "1) Versiyon bilgisi (-sV)"
    echo "2) Scriptlerle versiyon tespiti (-sC -sV)"
    echo "3) Belirli portlarda versiyon tespiti"
    echo "4) SSL versiyon taraması"
    echo "5) Detaylı banner bilgisi"
    echo "6) Versiyon bilgisi + OS tespiti"
    echo "7) Tüm servis bilgileri (-A -sV)"
    echo "8) Versiyon tespiti + NSE script"
    echo "9) Versiyon bilgilerini loga kaydet"
    echo "10) Hedef sistemdeki servisleri listele"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) nmap -sV "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap -sC -sV "$hedef" | tee -a "$LOG_FILE" ;;
        3) read -p "Port(lar): " port; nmap -sV -p "$port" "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap --script ssl-enum-ciphers -p 443 "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap --script=banner "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap -sV -O "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -A -sV "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap -sV --script=default "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -sV "$hedef" -oN "$LOG_FILE" ;;
        10) nmap -sV "$hedef" | grep open | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori2
}

# Kategori 3: OS Tespiti
kategori3() {
    clear
    echo -e "${BLUE}İşletim Sistemi Tespiti - Bir işlem seçin:${NC}"
    echo "1) OS tespiti (-O)"
    echo "2) Aggressive tarama ile OS tespiti (-A)"
    echo "3) TCP/IP stack analizine dayalı OS tespiti (--osscan-guess)"
    echo "4) Belirli port üzerinden OS analizi"
    echo "5) OS tespiti + traceroute (--traceroute)"
    echo "6) OS tespiti + versiyon tespiti (-O -sV)"
    echo "7) Güvenlik duvarı altındaki OS tespiti (fragmentation) (-f)"
    echo "8) ICMP ile OS tespiti (--script=icmp-* )"
    echo "9) OS tespitini loga yaz"
    echo "10) Tüm bilgileri detaylı al (-A -O -sV -sC)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) nmap -O "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap -A "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -O --osscan-guess "$hedef" | tee -a "$LOG_FILE" ;;
        4) read -p "Port numarası: " port; nmap -O -p "$port" "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -O --traceroute "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap -O -sV "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -O -f "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap --script=icmp-* "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -O "$hedef" -oN "$LOG_FILE" ;;
        10) nmap -A -O -sV -sC "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori3
}

# Kategori 4: Firewall ve Filtre Kontrolleri
kategori4() {
    clear
    echo -e "${BLUE}Firewall ve Filtre Kontrolleri - Bir işlem seçin:${NC}"
    echo "1) ACK Taraması (stateful FW tespiti)"
    echo "2) Null Taraması (filtre kontrolü)"
    echo "3) XMAS Taraması (FW tespiti)"
    echo "4) FIN Taraması"
    echo "5) Fragmented paket ile FW atlatma"
    echo "6) IP ID farkı ile FW analizi"
    echo "7) ICMP response kontrolü"
    echo "8) Port durumu: filtered/unfiltered"
    echo "9) Traceroute ile filtre analizi"
    echo "10) Aggressive FW bypass taraması"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) nmap -sA "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap -sN "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -sX "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap -sF "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -f "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap --ip-options "-" "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -PE "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap -sS "$hedef" | grep -i filtered | tee -a "$LOG_FILE" ;;
        9) nmap --traceroute "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -A -f -sX "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori4
}

# Kategori 5: NSE Script Taramaları
kategori5() {
    clear
    echo -e "${BLUE}NSE Script Taramaları - Bir işlem seçin:${NC}"
    echo "1) Genel script taraması (-sC)"
    echo "2) Güvenlik açıkları taraması (vuln kategorisi)"
    echo "3) HTTP ile ilgili scriptler (http-*)"
    echo "4) SSL/TLS güvenliği analizi (ssl-*)"
    echo "5) SSH güvenlik kontrolleri (ssh-*)"
    echo "6) FTP zafiyet taraması (ftp-*)"
    echo "7) Exploit scriptleri ile tarama"
    echo "8) Brute-force testleri (brute-*)"
    echo "9) Auth (kimlik doğrulama) kontrol scriptleri"
    echo "10) Script taramasını loga yaz"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP veya Alan Adı: " hedef
    fi

    case $secim in
        1) nmap -sC "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap --script vuln "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap --script "http-*" "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap --script "ssl-*" "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap --script "ssh-*" "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap --script "ftp-*" "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap --script "vuln" "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap --script "brute-*" "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap --script "auth" "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -sC "$hedef" -oN "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _    kategori5
}

# Kategori 6: Ağ Keşfi ve Topoloji
kategori6() {
    clear
    echo -e "${BLUE}Ağ Keşfi ve Topoloji - Bir işlem seçin:${NC}"
    echo "1) Ping Scan (aktif hostları bul)"
    echo "2) ARP Scan (LAN için hızlı tarama)"
    echo "3) Traceroute (yol analizi)"
    echo "4) ICMP Echo Scan"
    echo "5) TCP SYN Ping Scan"
    echo "6) UDP Ping Scan"
    echo "7) IP Protokol Scan"
    echo "8) Tüm ağ bloğunu tara (/24)"
    echo "9) DNS reverse lookup ile keşif"
    echo "10) Ağ haritasını çıkart (topology)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP veya Ağ (örn: 192.168.1.0/24): " hedef
    fi

    case $secim in
        1) nmap -sn "$hedef" | tee -a "$LOG_FILE" ;;
        2) sudo nmap -sn -PR "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap --traceroute "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap -PE "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -PS "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap -PU "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -PO "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap -sP "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -sL "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -sn --traceroute "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori6
}

# Kategori 7: Hız ve Zamanlama Ayarları
kategori7() {
    clear
    echo -e "${BLUE}Hız ve Zamanlama Ayarları - Bir işlem seçin:${NC}"
    echo "1) En yavaş ve stealth (T0)"
    echo "2) Çok yavaş ama güvenli (T1)"
    echo "3) Dengeli tarama (T3)"
    echo "4) Hızlı (T4) - varsayılan"
    echo "5) En hızlı (T5) - ağ çökebilir"
    echo "6) Timeout ayarlarını düşür (daha hızlı)"
    echo "7) Parallelism ayarla (eş zamanlılık)"
    echo "8) Max RTT azalt (gecikme limiti)"
    echo "9) Tüm zamanlama custom (manuel parametre)"
    echo "10) Zamanlama + Port taraması birleşik"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) nmap -T0 "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap -T1 "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -T3 "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap -T4 "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -T5 "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap --host-timeout 30s "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap --min-parallelism 10 "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap --max-rtt-timeout 100ms "$hedef" | tee -a "$LOG_FILE" ;;
        9) read -p "Manuel parametre gir: " param; nmap $param "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -sS -T4 -p- "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori7
}

# Kategori 8: Hedef Belirleme Teknikleri
kategori8() {
    clear
    echo -e "${BLUE}Hedef Belirleme Teknikleri - Bir işlem seçin:${NC}"
    echo "1) Tek IP tarama"
    echo "2) IP Aralığı (192.168.1.1-10)"
    echo "3) CIDR bloğu (192.168.1.0/24)"
    echo "4) IP listesi dosyasından oku"
    echo "5) Domain adı ile tarama"
    echo "6) Hedef exclude (belirli IP’leri dışla)"
    echo "7) IPv6 hedef tarama"
    echo "8) DNS isimlerini çözmeden tarama"
    echo "9) Random IP taraması"
    echo "10) Birden fazla hedef (virgüllü)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim

    case $secim in
        1) read -p "IP gir: " ip; nmap "$ip" | tee -a "$LOG_FILE" ;;
        2) read -p "IP aralığı gir (örn: 192.168.1.1-20): " ip; nmap "$ip" | tee -a "$LOG_FILE" ;;
        3) read -p "CIDR gir (örn: 192.168.1.0/24): " ip; nmap "$ip" | tee -a "$LOG_FILE" ;;
        4) read -p "Dosya adı gir (örn: hedefler.txt): " dosya; nmap -iL "$dosya" | tee -a "$LOG_FILE" ;;
        5) read -p "Domain gir (örn: example.com): " domain; nmap "$domain" | tee -a "$LOG_FILE" ;;
        6) read -p "IP gir: " ip; read -p "Exclude IP gir: " ex; nmap "$ip" --exclude "$ex" | tee -a "$LOG_FILE" ;;
        7) read -p "IPv6 adresi gir: " ip6; nmap -6 "$ip6" | tee -a "$LOG_FILE" ;;
        8) read -p "IP gir: " ip; nmap -n "$ip" | tee -a "$LOG_FILE" ;;
        9) nmap -iR 5 | tee -a "$LOG_FILE" ;;
        10) read -p "IP'leri virgülle ayırarak yaz: " hedefler; nmap $hedefler | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori8
}

# Spoofing / Fragmentation Teknikleri
kategori9() {
    clear
    echo -e "${BLUE}Spoofing / Fragmentation Teknikleri - Bir işlem seçin:${NC}"
    echo "1) IP Spoof (sahte kaynak IP)"
    echo "2) MAC adresi spoof (random MAC)"
    echo "3) Fragmented paketlerle tarama"
    echo "4) MTU değiştir (belirli boyutta paket)"
    echo "5) TTL spoof (zıplama gizleme)"
    echo "6) Decoy tarama (kamuflaj IP'lerle)"
    echo "7) Source port spoof (örn: 53 DNS)"
    echo "8) Bad checksum gönder"
    echo "9) Komple stealth (fragment+spoof+mac)"
    echo "10) TCP/IP fingerprint zorlama (--fuzzy)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP: " hedef
    fi

    case $secim in
        1) read -p "Sahte IP gir: " fake; nmap -S "$fake" "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap --spoof-mac 0 "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -f "$hedef" | tee -a "$LOG_FILE" ;;
        4) read -p "MTU değeri gir (örn: 24): " mtu; nmap --mtu "$mtu" "$hedef" | tee -a "$LOG_FILE" ;;
        5) read -p "TTL değeri gir (örn: 42): " ttl; nmap --ttl "$ttl" "$hedef" | tee -a "$LOG_FILE" ;;
        6) read -p "Decoy IP'leri virgüllü gir: " d; nmap -D "$d" "$hedef" | tee -a "$LOG_FILE" ;;
        7) read -p "Kaynak port gir (örn: 53): " port; nmap --source-port "$port" "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap --badsum "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -f -D RND:5 --spoof-mac 0 "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap --fuzzy "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori9
}

# Kombinasyon
kategori10() {
    clear
    echo -e "${BLUE}Kombinasyon Örnekleri - Bir işlem seçin:${NC}"
    echo "1) Full port + service + version (detaylı)"
    echo "2) Stealth + fragmented + MAC spoof"
    echo "3) Hızlı port tarama + versiyon kontrol"
    echo "4) Aggressive OS + traceroute + script"
    echo "5) UDP + Servis versiyonu"
    echo "6) Web server analizi (port 80/443)"
    echo "7) DNS hedefi analizi (port 53)"
    echo "8) Script + T5 hız + Decoy IP"
    echo "9) IPv6 full tarama"
    echo "10) Tüm saldırı parametreleri (canavar)"
    echo "99) Ana Menü"
    read -p "Seçim: " secim
    if [[ "$secim" != "99" ]]; then
        read -p "Hedef IP veya domain: " hedef
    fi

    case $secim in
        1) nmap -p- -sV -sS -T4 "$hedef" | tee -a "$LOG_FILE" ;;
        2) nmap -sS -f --spoof-mac 0 "$hedef" | tee -a "$LOG_FILE" ;;
        3) nmap -F -sV "$hedef" | tee -a "$LOG_FILE" ;;
        4) nmap -A --traceroute "$hedef" | tee -a "$LOG_FILE" ;;
        5) nmap -sU -sV "$hedef" | tee -a "$LOG_FILE" ;;
        6) nmap -p 80,443 -sV --script=http-enum "$hedef" | tee -a "$LOG_FILE" ;;
        7) nmap -p 53 -sU -sV --script=dns-zone-transfer "$hedef" | tee -a "$LOG_FILE" ;;
        8) nmap -sC -T5 -D RND:5 "$hedef" | tee -a "$LOG_FILE" ;;
        9) nmap -6 -sS -sV "$hedef" | tee -a "$LOG_FILE" ;;
        10) nmap -A -T5 -f -sS -D RND:5 --spoof-mac 0 "$hedef" | tee -a "$LOG_FILE" ;;
        99) ana_menu ;;
        *) echo "Geçersiz seçim"; sleep 1 ;;
    esac
    read -p "Devam etmek için Enter'a bas..." _
    kategori10
}

ana_menu
