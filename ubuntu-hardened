#!/bin/bash

################################################################################
# Ubuntu LTS Enhanced Hardening Script v3.0
# Compatible with: Ubuntu 22.04 LTS (Jammy) & 24.04 LTS (Noble)
# Features:
# - SSH dengan port custom 1022 + IP whitelist + AppArmor
# - Malware scanner: ClamAV + Maldet (mengganti rkhunter)
# - Fail2ban untuk proteksi brute force
# - USB storage protection
# - Compiler restriction
# Target: Lynis Index 65 → 85+
################################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script metadata
SCRIPT_VERSION="3.0-Ubuntu"
SCRIPT_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/root/hardening-backup/${SCRIPT_DATE}"
LOG_FILE="/var/log/hardening-${SCRIPT_DATE}.log"

# SSH Configuration - CUSTOMIZE THESE
SSH_PORT=1022
ALLOWED_SSH_IPS=(
    "202.58.242.254"
    "10.110.16.60"
    "10.110.16.61"
    "10.110.16.58"
)

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Script ini harus dijalankan sebagai root atau dengan sudo"
    echo "Gunakan: sudo bash $0"
    exit 1
fi

# Create directories
mkdir -p "$BACKUP_DIR"
mkdir -p /var/log

# Logging function
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
    
    case $level in
        INFO)
            echo -e "${GREEN}[✓]${NC} ${message}"
            ;;
        WARN)
            echo -e "${YELLOW}[!]${NC} ${message}"
            ;;
        ERROR)
            echo -e "${RED}[✗]${NC} ${message}"
            ;;
        SECTION)
            echo -e "\n${BLUE}[#]${NC} ${message}"
            ;;
    esac
}

# Backup function
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp -p "$file" "$BACKUP_DIR/" 2>/dev/null && \
        log INFO "Backed up: $file" || \
        log WARN "Failed to backup: $file"
    else
        log WARN "File not found for backup: $file"
    fi
    return 0
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs 2>/dev/null || echo "unknown")

# Banner
clear
echo "================================================================================"
echo "              Ubuntu LTS Enhanced Security Hardening Script"
echo "                         Version: $SCRIPT_VERSION"
echo "================================================================================"
echo ""
echo "Detected OS: Ubuntu $UBUNTU_VERSION"
echo "Compatible with: Ubuntu 22.04 LTS & 24.04 LTS"
echo ""
echo "Current Status:"
echo "  - Hardening Index: 65 (typical)"
echo "  - Target Index: 85+"
echo "  - New Features: SSH Port ${SSH_PORT}, ClamAV, Maldet, Fail2ban"
echo ""
echo "Backup Directory: $BACKUP_DIR"
echo "Log File: $LOG_FILE"
echo ""
echo -e "${YELLOW}WARNING:${NC} SSH will be moved to port ${SSH_PORT}"
echo "Allowed IPs: ${ALLOWED_SSH_IPS[@]}"
echo ""
read -p "Press Enter to continue or Ctrl+C to abort..."

################################################################################
# SECTION 1: CRITICAL FILE BACKUP
################################################################################

log SECTION "SECTION 1: BACKING UP CRITICAL CONFIGURATION FILES"

backup_file /etc/ssh/sshd_config
backup_file /etc/sysctl.conf
backup_file /etc/security/limits.conf
backup_file /etc/login.defs
backup_file /etc/security/pwquality.conf
backup_file /etc/audit/rules.d/audit.rules
backup_file /etc/ufw/ufw.conf
backup_file /etc/modprobe.d/hardening.conf

# Backup audit rules directory
if [ -d "/etc/audit/rules.d" ]; then
    cp -r /etc/audit/rules.d "$BACKUP_DIR/audit.rules.d.backup"
    log INFO "Backed up audit rules directory"
fi

################################################################################
# SECTION 2: UPDATE SYSTEM
################################################################################

log SECTION "SECTION 2: UPDATING SYSTEM PACKAGES"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
log INFO "System packages updated"

################################################################################
# SECTION 3: FIREWALL CONFIGURATION WITH UFW
################################################################################

log SECTION "SECTION 3: CONFIGURING FIREWALL WITH SSH RESTRICTIONS"

# UFW should be pre-installed on Ubuntu, but check anyway
if ! command_exists ufw; then
    apt-get install -y ufw -qq
    log INFO "UFW installed"
fi

# Reset UFW to default
ufw --force reset >/dev/null 2>&1

# Set default policies
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1

# Allow SSH from specific IPs only
log INFO "Adding SSH port ${SSH_PORT} with IP whitelist..."
for ip in "${ALLOWED_SSH_IPS[@]}"; do
    ufw allow from "$ip" to any port "$SSH_PORT" proto tcp >/dev/null 2>&1
    log INFO "Added SSH access for IP: ${ip}"
done

# Enable UFW
ufw --force enable >/dev/null 2>&1
log INFO "Firewall configured with restricted SSH access on port ${SSH_PORT}"

################################################################################
# SECTION 4: ADVANCED SSH HARDENING
################################################################################

log SECTION "SECTION 4: ADVANCED SSH SECURITY HARDENING"

# Backup original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-hardening

# Apply SSH hardening
log INFO "Applying comprehensive SSH hardening..."

# Change SSH port
sed -i "s/^#*Port.*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
grep -q "^Port" /etc/ssh/sshd_config || echo "Port ${SSH_PORT}" >> /etc/ssh/sshd_config

# Security settings
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*MaxSessions.*/MaxSessions 2/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#*LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*TCPKeepAlive.*/TCPKeepAlive no/' /etc/ssh/sshd_config
sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#*PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
sed -i 's/^#*StrictModes.*/StrictModes yes/' /etc/ssh/sshd_config
sed -i 's/^#*MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config

# Add if not exists
grep -q "^Protocol" /etc/ssh/sshd_config || echo "Protocol 2" >> /etc/ssh/sshd_config
grep -q "^HostbasedAuthentication" /etc/ssh/sshd_config || echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
grep -q "^IgnoreRhosts" /etc/ssh/sshd_config || echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config

# Strong ciphers
grep -q "^Ciphers" /etc/ssh/sshd_config || echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
grep -q "^MACs" /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
grep -q "^KexAlgorithms" /etc/ssh/sshd_config || echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

log INFO "SSH configuration hardened with port ${SSH_PORT}"

# Test SSH config
if sshd -t 2>/dev/null; then
    systemctl restart ssh
    log INFO "SSH service restarted successfully on port ${SSH_PORT}"
    log WARN "Test SSH connection on port ${SSH_PORT} before closing this session!"
else
    log ERROR "SSH configuration test failed, reverting..."
    cp /etc/ssh/sshd_config.pre-hardening /etc/ssh/sshd_config
    systemctl restart ssh
fi

################################################################################
# SECTION 5: FAIL2BAN INSTALLATION
################################################################################

log SECTION "SECTION 5: INSTALLING FAIL2BAN FOR BRUTE FORCE PROTECTION"

if ! command_exists fail2ban-server; then
    apt-get install -y fail2ban -qq
    log INFO "Fail2ban installed"
fi

# Configure fail2ban for SSH
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 3
EOF

systemctl enable fail2ban >/dev/null 2>&1
systemctl restart fail2ban >/dev/null 2>&1
log INFO "Fail2ban installed and configured for SSH on port ${SSH_PORT}"

################################################################################
# SECTION 6: KERNEL HARDENING
################################################################################

log SECTION "SECTION 6: KERNEL AND NETWORK HARDENING"

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Ubuntu Security Hardening - Kernel Parameters

# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ICMP Redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Send Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source Packet Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ICMP Settings
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP Hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_rfc1337 = 1

# IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Kernel Security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1

# File System Hardening
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Network Core
net.core.bpf_jit_harden = 2

# ASLR
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1
log INFO "Kernel security parameters applied"

################################################################################
# SECTION 7: DISABLE UNCOMMON PROTOCOLS
################################################################################

log SECTION "SECTION 7: DISABLING UNCOMMON NETWORK PROTOCOLS"

cat > /etc/modprobe.d/hardening.conf << 'EOF'
# Disable uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true

# Disable uncommon filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true

# Disable USB storage
install usb-storage /bin/true
EOF

log INFO "Uncommon protocols and USB storage disabled"

################################################################################
# SECTION 8: COMPILER RESTRICTION
################################################################################

log SECTION "SECTION 8: RESTRICTING COMPILER ACCESS"

groupadd -f compilers 2>/dev/null

if [ -f /usr/bin/gcc ]; then
    chmod 750 /usr/bin/gcc
    chown root:compilers /usr/bin/gcc
    log INFO "GCC access restricted to compilers group"
fi

if [ -f /usr/bin/g++ ]; then
    chmod 750 /usr/bin/g++
    chown root:compilers /usr/bin/g++
    log INFO "G++ access restricted to compilers group"
fi

################################################################################
# SECTION 9: PASSWORD POLICY
################################################################################

log SECTION "SECTION 9: CONFIGURING STRONG PASSWORD POLICY"

# Install libpam-pwquality if not present
apt-get install -y libpam-pwquality -qq

cat > /etc/security/pwquality.conf << 'EOF'
# Password quality requirements
minlen = 14
minclass = 4
maxrepeat = 2
maxclassrepeat = 4
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF

# Login.defs hardening
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Set umask
sed -i 's/umask 022/umask 027/' /etc/bash.bashrc
grep -q "umask 027" /etc/profile || echo "umask 027" >> /etc/profile

log INFO "Strong password policy configured"

################################################################################
# SECTION 10: ACCOUNT LOCKOUT POLICY
################################################################################

log SECTION "SECTION 10: CONFIGURING ACCOUNT LOCKOUT"

# Configure pam_faillock
if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    sed -i '/pam_unix.so/i auth    required    pam_faillock.so preauth silent deny=3 unlock_time=900' /etc/pam.d/common-auth
    sed -i '/pam_unix.so/a auth    [default=die]    pam_faillock.so authfail deny=3 unlock_time=900' /etc/pam.d/common-auth
    sed -i '/pam_permit.so/i account required    pam_faillock.so' /etc/pam.d/common-account
    log INFO "Account lockout policy configured"
fi

################################################################################
# SECTION 11: AUDITD CONFIGURATION
################################################################################

log SECTION "SECTION 11: CONFIGURING COMPREHENSIVE AUDITING"

if ! command_exists auditctl; then
    apt-get install -y auditd audispd-plugins -qq
    log INFO "Auditd installed"
fi

systemctl enable auditd >/dev/null 2>&1
systemctl start auditd >/dev/null 2>&1

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all previous rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Audit logs
-w /var/log/audit/ -k auditlog

# Auditd config
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig

# Audit tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# System calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# User/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network changes
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/netplan/ -p wa -k network

# System mount
-a always,exit -F arch=b64 -S mount -S umount2 -k mount

# File deletion
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Sudoers
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH config
-w /etc/ssh/sshd_config -p wa -k sshd

# Kernel modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Login events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Process execution
-a always,exit -F arch=b64 -S execve -k exec

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make immutable
-e 2
EOF

augenrules --load >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1
log INFO "Comprehensive audit rules applied"

################################################################################
# SECTION 12: APPARMOR ENFORCEMENT
################################################################################

log SECTION "SECTION 12: ENSURING APPARMOR ENFORCEMENT"

# AppArmor should be pre-installed on Ubuntu
if ! command_exists aa-status; then
    apt-get install -y apparmor apparmor-utils -qq
    log INFO "AppArmor installed"
fi

systemctl enable apparmor >/dev/null 2>&1
systemctl start apparmor >/dev/null 2>&1

# Ensure AppArmor profiles are enforced
aa-enforce /etc/apparmor.d/* 2>/dev/null || true

log INFO "AppArmor enabled and enforcing"

################################################################################
# SECTION 13: CLAMAV INSTALLATION
################################################################################

log SECTION "SECTION 13: INSTALLING CLAMAV (ANTIVIRUS SCANNER)"

if ! command_exists clamscan; then
    apt-get install -y clamav clamav-daemon clamav-freshclam -qq
    log INFO "ClamAV installed"
fi

# Stop freshclam service to update manually
systemctl stop clamav-freshclam >/dev/null 2>&1

log INFO "Updating ClamAV virus definitions..."
freshclam >/dev/null 2>&1 &
FRESHCLAM_PID=$!

# Start services
systemctl enable clamav-daemon >/dev/null 2>&1
systemctl start clamav-freshclam >/dev/null 2>&1

# Create daily scan script
cat > /etc/cron.daily/clamav-scan << 'EOF'
#!/bin/bash
SCAN_DIR="/"
LOG_FILE="/var/log/clamav/daily-scan-$(date +%Y%m%d).log"
EXCLUDE_DIRS="--exclude-dir=/sys --exclude-dir=/proc --exclude-dir=/dev --exclude-dir=/snap"

mkdir -p /var/log/clamav
/usr/bin/clamscan -r -i ${EXCLUDE_DIRS} ${SCAN_DIR} >> ${LOG_FILE} 2>&1

if grep -q "Infected files: [1-9]" ${LOG_FILE}; then
    mail -s "VIRUS ALERT on $(hostname)" root < ${LOG_FILE}
fi
EOF

chmod +x /etc/cron.daily/clamav-scan
log INFO "ClamAV configured with daily scanning"

################################################################################
# SECTION 14: MALDET INSTALLATION
################################################################################

log SECTION "SECTION 14: INSTALLING MALDET (LINUX MALWARE DETECT)"

if ! command_exists maldet; then
    log INFO "Installing Maldet..."
    cd /tmp
    wget -q https://www.rfxn.com/downloads/maldetect-current.tar.gz 2>/dev/null
    if [ -f maldetect-current.tar.gz ]; then
        tar -xzf maldetect-current.tar.gz
        cd maldetect-*
        ./install.sh >/dev/null 2>&1
        cd /tmp
        rm -rf maldetect*
        log INFO "Maldet installed"
        
        /usr/local/sbin/maldet -u >/dev/null 2>&1
        
        sed -i 's/email_alert=0/email_alert=1/' /usr/local/maldetect/conf.maldet
        sed -i 's/email_addr="you@domain.com"/email_addr="root@localhost"/' /usr/local/maldetect/conf.maldet
        
        cat > /etc/cron.weekly/maldet-scan << 'EOF'
#!/bin/bash
/usr/local/sbin/maldet -a /home >> /var/log/maldet-scan.log 2>&1
EOF
        chmod +x /etc/cron.weekly/maldet-scan
        log INFO "Maldet configured with weekly scanning"
    else
        log WARN "Failed to download Maldet"
    fi
fi

################################################################################
# SECTION 15: PROCESS ACCOUNTING
################################################################################

log SECTION "SECTION 15: ENABLING PROCESS ACCOUNTING"

if ! command_exists ac; then
    apt-get install -y acct -qq
    log INFO "Process accounting installed"
fi

systemctl enable acct >/dev/null 2>&1
systemctl start acct >/dev/null 2>&1
log INFO "Process accounting enabled"

################################################################################
# SECTION 16: SYSTEM STATISTICS
################################################################################

log SECTION "SECTION 16: ENABLING SYSTEM STATISTICS"

if ! command_exists sar; then
    apt-get install -y sysstat -qq
    log INFO "Sysstat installed"
fi

systemctl enable sysstat >/dev/null 2>&1
systemctl start sysstat >/dev/null 2>&1
log INFO "System statistics collection enabled"

################################################################################
# SECTION 17: AUTOMATIC SECURITY UPDATES
################################################################################

log SECTION "SECTION 17: CONFIGURING AUTOMATIC SECURITY UPDATES"

apt-get install -y unattended-upgrades apt-listchanges -qq

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable unattended-upgrades >/dev/null 2>&1
systemctl restart unattended-upgrades >/dev/null 2>&1
log INFO "Automatic security updates configured"

################################################################################
# SECTION 18: ENHANCED LOGGING
################################################################################

log SECTION "SECTION 18: ENHANCING LOGGING CONFIGURATION"

cat >> /etc/rsyslog.conf << 'EOF'

# Enhanced security logging
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
*.emerg                         :omusrmsg:*
EOF

systemctl restart rsyslog >/dev/null 2>&1

cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log
/var/log/kern.log
{
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

log INFO "Enhanced logging configured"

################################################################################
# SECTION 19: AIDE (FILE INTEGRITY MONITORING)
################################################################################

log SECTION "SECTION 19: INSTALLING FILE INTEGRITY MONITORING (AIDE)"

if ! command_exists aide; then
    apt-get install -y aide aide-common -qq
    log INFO "AIDE installed"
fi

log INFO "Initializing AIDE database (may take several minutes)..."
aideinit >/dev/null 2>&1 &
AIDE_PID=$!

timeout=300
while kill -0 $AIDE_PID 2>/dev/null && [ $timeout -gt 0 ]; do
    sleep 5
    timeout=$((timeout-5))
    echo -n "."
done
echo ""

if [ -f "/var/lib/aide/aide.db.new" ]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    log INFO "AIDE database initialized"
    
    cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    chmod +x /etc/cron.weekly/aide-check
    log INFO "Weekly AIDE checks scheduled"
else
    log WARN "AIDE database initialization incomplete"
fi

################################################################################
# SECTION 20: DISABLE UNNECESSARY SERVICES
################################################################################

log SECTION "SECTION 20: DISABLING UNNECESSARY SERVICES"

services_to_disable=(
    "telnet"
    "rsh-server"
    "rlogin"
    "rexec"
    "tftp"
    "talk"
)

for service in "${services_to_disable[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        systemctl disable --now "${service}.service" >/dev/null 2>&1
        log INFO "Disabled: ${service}"
    fi
done

################################################################################
# SECTION 21: ADDITIONAL HARDENING
################################################################################

log SECTION "SECTION 21: ADDITIONAL SECURITY MEASURES"

# Disable core dumps
cat >> /etc/security/limits.conf << 'EOF'
* hard core 0
EOF

# Disable ctrl+alt+del
systemctl mask ctrl-alt-del.target >/dev/null 2>&1
log INFO "Ctrl+Alt+Del disabled"

# Restrict cron
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
log INFO "Cron access restricted to root"

# Secure shared memory
if ! grep -q "/run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
    log INFO "Shared memory secured"
fi

################################################################################
# FINAL VERIFICATION
################################################################################

log SECTION "FINAL SYSTEM VERIFICATION"

wait $FRESHCLAM_PID 2>/dev/null

echo ""
echo "================================================================"
echo "                 HARDENING VERIFICATION REPORT"
echo "================================================================"
echo ""

# Check Firewall
if ufw status | grep -q "Status: active"; then
    echo -e "${GREEN}[✓]${NC} Firewall (UFW): Active"
    echo "         SSH Port: ${SSH_PORT}"
    echo "         Allowed IPs: ${ALLOWED_SSH_IPS[@]}"
else
    echo -e "${RED}[✗]${NC} Firewall: Inactive"
fi

# Check AppArmor
if command_exists aa-status && aa-status --enabled 2>/dev/null; then
    echo -e "${GREEN}[✓]${NC} AppArmor: Enabled"
    profile_count=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
    echo "         Enforced profiles: ${profile_count}"
else
    echo -e "${YELLOW}[!]${NC} AppArmor: Not enabled"
fi

# Check SSH
if systemctl is-active --quiet ssh; then
    echo -e "${GREEN}[✓]${NC} SSH: Active on port ${SSH_PORT}"
else
    echo -e "${RED}[✗]${NC} SSH: Inactive"
fi

# Check Fail2ban
if systemctl is-active --quiet fail2ban; then
    echo -e "${GREEN}[✓]${NC} Fail2ban: Active"
else
    echo -e "${YELLOW}[!]${NC} Fail2ban: Inactive"
fi

# Check Audit
if systemctl is-active --quiet auditd; then
    echo -e "${GREEN}[✓]${NC} Audit: Active"
    rules_count=$(auditctl -l 2>/dev/null | grep -c "^-" || echo "0")
    echo "         Audit rules loaded: ${rules_count}"
else
    echo -e "${RED}[✗]${NC} Audit: Inactive"
fi

# Check Scanners
if command_exists clamscan; then
    echo -e "${GREEN}[✓]${NC} Antivirus: Installed (ClamAV)"
else
    echo -e "${RED}[✗]${NC} Antivirus: Not Installed"
fi

if command_exists maldet; then
    echo -e "${GREEN}[✓]${NC} Malware Scanner: Installed (Maldet)"
else
    echo -e "${YELLOW}[!]${NC} Malware Scanner: Not Installed"
fi

if command_exists aide; then
    echo -e "${GREEN}[✓]${NC} File Integrity: Installed (AIDE)"
else
    echo -e "${RED}[✗]${NC} File Integrity: Not Installed"
fi

# Check Process Accounting
if systemctl is-active --quiet acct; then
    echo -e "${GREEN}[✓]${NC} Process Accounting: Active"
else
    echo -e "${YELLOW}[!]${NC} Process Accounting: Inactive"
fi

# Check Sysstat
if systemctl is-active --quiet sysstat; then
    echo -e "${GREEN}[✓]${NC} System Statistics: Active"
else
    echo -e "${YELLOW}[!]${NC} System Statistics: Inactive"
fi

echo ""
echo "================================================================"
echo "                    HARDENING COMPLETED"
echo "================================================================"
echo ""
echo "Summary:"
echo "  - Ubuntu Version: $UBUNTU_VERSION"
echo "  - Backup Location: $BACKUP_DIR"
echo "  - Log File: $LOG_FILE"
echo "  - Changes Applied: 21+ major security improvements"
echo ""
echo "Expected Score Improvement:"
echo "  - Previous Index: ~65"
echo "  - Expected Index: 85-90+"
echo "  - Improvement: +20-25 points"
echo ""
echo -e "${YELLOW}CRITICAL NEXT STEPS:${NC}"
echo "  1. ${RED}TEST SSH CONNECTION NOW in a new terminal:${NC}"
echo "     ssh -p ${SSH_PORT} your_user@your_server_ip"
echo "  2. Review log: cat $LOG_FILE"
echo "  3. Reboot system: reboot"
echo "  4. Run Lynis: lynis audit system"
echo ""
echo -e "${RED}SSH CONFIGURATION CHANGED:${NC}"
echo "  - Port: 22 → ${SSH_PORT}"
echo "  - IP whitelist: ${ALLOWED_SSH_IPS[@]}"
echo "  - Root login: DISABLED"
echo "  - Fail2ban: ENABLED"
echo ""
echo "If SSH access lost, use console:"
echo "  sudo cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config"
echo "  sudo systemctl restart ssh"
echo "  sudo ufw allow 22/tcp"
echo ""
echo "================================================================"
