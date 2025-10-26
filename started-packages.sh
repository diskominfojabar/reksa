#!/bin/bash

set -e

echo "=== [1] Mendeteksi OS dan manajer paket ==="
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID=$ID
  OS_VERSION=$VERSION_ID
else
  echo "Tidak dapat mendeteksi OS. Pastikan file /etc/os-release tersedia."
  exit 1
fi

echo "Ditemukan OS: $NAME $VERSION_ID"

# Tentukan manajer paket
case "$OS_ID" in
  rocky|rhel|centos)
    PKG_MANAGER="dnf"
    UPDATE_CMD="sudo dnf update -y"
    INSTALL_CMD="sudo dnf install -y"
    ;;
  debian|ubuntu)
    PKG_MANAGER="apt"
    UPDATE_CMD="sudo apt update -y && sudo apt upgrade -y"
    INSTALL_CMD="sudo apt install -y"
    ;;
  *)
    echo "OS $OS_ID belum didukung oleh skrip ini."
    exit 1
    ;;
esac

echo "Menggunakan manajer paket: $PKG_MANAGER"

echo "=== [2] Memperbarui repository ==="
eval "$UPDATE_CMD"

echo "=== [3] Menyusun daftar paket penting ==="
# Daftar paket dan fungsinya
PACKAGES=(
  git            # Version control system
  vim            # Editor teks
  curl           # Transfer data via URL
  wget           # Unduh file dari web
  net-tools      # Alat jaringan legacy (ifconfig, netstat)
  lsof           # Menampilkan file yang terbuka oleh proses
  tcpdump        # Sniffer paket jaringan
  btop           # Monitoring proses interaktif
  strace         # Debug proses dan syscall
  sysstat        # Statistik sistem (iostat, mpstat)
  ncdu           # Analisis penggunaan disk
  unzip          # Ekstrak file zip
  rsync          # Sinkronisasi file
  traceroute     # Lacak rute jaringan
  dnsutils       # DNS tools (dig, nslookup) - Ubuntu/Debian
  bind-utils     # DNS tools (dig, nslookup) - RHEL/Rocky
  nmap           # Scanner jaringan
  telnet         # Tes koneksi TCP
  iperf3         # Tes bandwidth jaringan
  whois          # Informasi domain
  gnupg          # Enkripsi dan tanda tangan digital
  openssh-client # SSH client tools
  policycoreutils # Manajemen SELinux (RHEL-based)
  setools        # Analisis kebijakan SELinux (RHEL-based)
  auditd         # Audit sistem
  aide           # Pemeriksa integritas file
  logwatch       # Ringkasan log harian
  fail2ban       # Perlindungan brute-force
  firewalld      # Manajemen firewall
  clamav         # Antivirus open source
  clamav-freshclam # Update definisi virus
  lynis          # Audit keamanan sistem
  python3-pip    # PIP3
)

# Penyesuaian nama paket per OS
if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
  PACKAGES=("${PACKAGES[@]/bind-utils/}") # hapus bind-utils
  PACKAGES=("${PACKAGES[@]/policycoreutils/}")
  PACKAGES=("${PACKAGES[@]/setools/}")
  PACKAGES=("${PACKAGES[@]/clamav-update/clamav-freshclam}")
elif [[ "$OS_ID" == "rocky" || "$OS_ID" == "rhel" || "$OS_ID" == "centos" ]]; then
  PACKAGES=("${PACKAGES[@]/dnsutils/}") # hapus dnsutils
  PACKAGES=("${PACKAGES[@]/gnupg/gnupg2}")
  PACKAGES=("${PACKAGES[@]/openssh-client/openssh-clients}")
fi

echo "=== [4] Instalasi paket ==="
for pkg in "${PACKAGES[@]}"; do
  echo "Menginstal: $pkg"
  if ! $INSTALL_CMD "$pkg"; then
    echo "⚠️  Gagal menginstal $pkg"
  fi
done

echo "=== [5] Checklist hasil instalasi ==="
for pkg in "${PACKAGES[@]}"; do
  if command -v "$pkg" &>/dev/null || dpkg -s "$pkg" &>/dev/null || rpm -q "$pkg" &>/dev/null; then
    echo "[✔] $pkg terinstal"
  else
    echo "[✘] $pkg tidak ditemukan"
  fi
done

echo "✅ Instalasi selesai. Silakan konfigurasi masing-masing tool sesuai kebutuhan."
