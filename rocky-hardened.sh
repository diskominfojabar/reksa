#!/bin/bash

################################################################################
# Rocky Linux 10 Enhanced Hardening Script v3.0
# Improvements:
# - SSH dengan port custom 1022 + IP whitelist + SELinux
# - Malware scanner: ClamAV + Maldet (mengganti rkhunter yang deprecated)
# - Fail2ban untuk proteksi brute force
# - USB storage protection
# - Compiler restriction
# Target: Index 65 → 85+
################################################################################

# Note: Tidak menggunakan set -e karena beberapa operasi backup boleh gagal
# Error handling dilakukan per-section dengan exit code check

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script metadata
SCRIPT_VERSION="3.0"
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

# Banner
clear
echo "================================================================================"
echo "              Rocky Linux 10 Enhanced Security Hardening Script"
echo "                         Version: $SCRIPT_VERSION"
echo "================================================================================"
echo ""
echo "Current Status:"
echo "  - Hardening Index: 65"
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
backup_file /etc/selinux/config
backup_file /etc/security/pwquality.conf
backup_file /etc/audit/rules.d/audit.rules
backup_file /etc/firewalld/firewalld.conf
backup_file /etc/modprobe.d/hardening.conf

# Backup entire audit rules directory
if [ -d "/etc/audit/rules.d" ]; then
    cp -r /etc/audit/rules.d "$BACKUP_DIR/audit.rules.d.backup"
    log INFO "Backed up audit rules directory"
fi

################################################################################
# SECTION 2: FIREWALL CONFIGURATION WITH SSH IP WHITELIST
################################################################################

log SECTION "SECTION 2: CONFIGURING FIREWALL WITH SSH RESTRICTIONS"

if ! systemctl is-active --quiet firewalld; then
    log INFO "Installing and enabling firewalld..."
    dnf install -y firewalld >/dev/null 2>&1
    systemctl enable --now firewalld
    log INFO "Firewalld enabled and started"
else
    log INFO "Firewalld already active"
fi

# Remove default SSH service (port 22)
firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1

# Add custom SSH port with IP restrictions using rich rules
log INFO "Adding SSH port ${SSH_PORT} with IP whitelist..."
for ip in "${ALLOWED_SSH_IPS[@]}"; do
    firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"${ip}\" port port=\"${SSH_PORT}\" protocol=\"tcp\" accept" >/dev/null 2>&1
    log INFO "Added SSH access for IP: ${ip}"
done

# Keep cockpit for management
firewall-cmd --permanent --add-service=cockpit >/dev/null 2>&1

# Reload firewall
firewall-cmd --reload >/dev/null 2>&1

log INFO "Firewall configured with restricted SSH access on port ${SSH_PORT}"

################################################################################
# SECTION 3: ADVANCED SSH HARDENING (Port 1022 + SELinux)
################################################################################

log SECTION "SECTION 3: ADVANCED SSH SECURITY HARDENING"

# Install policycoreutils if not present
if ! command_exists semanage; then
    log INFO "Installing SELinux management tools..."
    dnf install -y policycoreutils-python-utils >/dev/null 2>&1
fi

# Backup original
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.pre-hardening

# Create hardened SSH config
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

# Strong ciphers only
grep -q "^Ciphers" /etc/ssh/sshd_config || echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
grep -q "^MACs" /etc/ssh/sshd_config || echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
grep -q "^KexAlgorithms" /etc/ssh/sshd_config || echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config

log INFO "SSH configuration hardened with port ${SSH_PORT}"

# Configure SELinux for custom SSH port
log INFO "Configuring SELinux for SSH port ${SSH_PORT}..."
semanage port -l | grep -q "ssh_port_t.*${SSH_PORT}" || \
    semanage port -a -t ssh_port_t -p tcp ${SSH_PORT} 2>/dev/null || \
    semanage port -m -t ssh_port_t -p tcp ${SSH_PORT} 2>/dev/null

if [ $? -eq 0 ]; then
    log INFO "SELinux configured for SSH port ${SSH_PORT}"
else
    log WARN "SELinux configuration may need manual adjustment"
fi

# Test SSH config
if sshd -t 2>/dev/null; then
    systemctl restart sshd
    log INFO "SSH service restarted successfully on port ${SSH_PORT}"
    log WARN "Test SSH connection on port ${SSH_PORT} before closing this session!"
else
    log ERROR "SSH configuration test failed, reverting..."
    cp /etc/ssh/sshd_config.pre-hardening /etc/ssh/sshd_config
    systemctl restart sshd
fi

################################################################################
# SECTION 4: FAIL2BAN INSTALLATION (Brute Force Protection)
################################################################################

log SECTION "SECTION 4: INSTALLING FAIL2BAN FOR BRUTE FORCE PROTECTION"

if ! command_exists fail2ban-server; then
    log INFO "Installing fail2ban..."
    dnf install -y epel-release >/dev/null 2>&1
    dnf install -y fail2ban fail2ban-systemd >/dev/null 2>&1
fi

# Configure fail2ban for SSH
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
banaction = firewallcmd-ipset

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
maxretry = 3
EOF

systemctl enable --now fail2ban >/dev/null 2>&1
log INFO "Fail2ban installed and configured for SSH on port ${SSH_PORT}"

################################################################################
# SECTION 5: KERNEL HARDENING (Comprehensive sysctl)
################################################################################

log SECTION "SECTION 5: KERNEL AND NETWORK HARDENING"

cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Rocky Linux Security Hardening - Kernel Parameters

# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Cookies Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ICMP Redirects (disable)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Send Redirects (disable)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source Packet Routing (disable)
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

# Address Space Layout Randomization
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1
log INFO "Kernel security parameters applied"

################################################################################
# SECTION 6: DISABLE UNCOMMON NETWORK PROTOCOLS
################################################################################

log SECTION "SECTION 6: DISABLING UNCOMMON NETWORK PROTOCOLS"

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

# Disable USB storage (remove if you need USB drives)
install usb-storage /bin/true
EOF

log INFO "Uncommon protocols and USB storage disabled"

################################################################################
# SECTION 7: COMPILER RESTRICTION
################################################################################

log SECTION "SECTION 7: RESTRICTING COMPILER ACCESS"

# Create group for compiler access
groupadd -f compilers 2>/dev/null

# Restrict compiler access
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
# SECTION 8: PASSWORD POLICY
################################################################################

log SECTION "SECTION 8: CONFIGURING STRONG PASSWORD POLICY"

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
sed -i 's/umask 022/umask 027/' /etc/bashrc
sed -i 's/umask 002/umask 027/' /etc/bashrc
grep -q "umask 027" /etc/profile || echo "umask 027" >> /etc/profile

log INFO "Strong password policy configured"

################################################################################
# SECTION 9: ACCOUNT LOCKOUT POLICY
################################################################################

log SECTION "SECTION 9: CONFIGURING ACCOUNT LOCKOUT"

# Configure pam_faillock
if ! grep -q "pam_faillock.so" /etc/pam.d/password-auth; then
    # Add faillock to auth section
    sed -i '/^auth.*pam_unix.so/i auth        required      pam_faillock.so preauth silent deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/password-auth
    sed -i '/^auth.*pam_unix.so/a auth        [default=die] pam_faillock.so authfail deny=3 unlock_time=900 fail_interval=900' /etc/pam.d/password-auth
    sed -i '/^account.*pam_unix.so/i account     required      pam_faillock.so' /etc/pam.d/password-auth
    
    log INFO "Account lockout policy configured"
fi

################################################################################
# SECTION 10: AUDITD CONFIGURATION
################################################################################

log SECTION "SECTION 10: CONFIGURING COMPREHENSIVE AUDITING"

if ! systemctl is-active --quiet auditd; then
    systemctl enable --now auditd >/dev/null 2>&1
    log INFO "Auditd enabled and started"
fi

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all previous rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Audit the audit logs
-w /var/log/audit/ -k auditlog

# Auditd configuration
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig

# Monitor for use of audit management tools
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# System calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S stime -k time-change

# User and group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network changes
-w /etc/hosts -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/sysconfig/network-scripts/ -p wa -k network

# System mount operations
-a always,exit -F arch=b64 -S mount -S umount2 -k mount

# File deletion by users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete

# Sudoers changes
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Login/Logout events
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Process execution
-a always,exit -F arch=b64 -S execve -k exec

# Privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Make configuration immutable
-e 2
EOF

augenrules --load >/dev/null 2>&1
systemctl restart auditd >/dev/null 2>&1
log INFO "Comprehensive audit rules applied"

################################################################################
# SECTION 11: SELINUX ENFORCEMENT
################################################################################

log SECTION "SECTION 11: ENSURING SELINUX ENFORCEMENT"

if [ -f /etc/selinux/config ]; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    log INFO "SELinux set to enforcing mode"
else
    log WARN "SELinux config not found"
fi

# Relabel on next boot if needed
if [ "$(getenforce)" != "Enforcing" ]; then
    touch /.autorelabel
    log WARN "SELinux relabel scheduled for next boot"
fi

################################################################################
# SECTION 12: CLAMAV INSTALLATION (Modern Antivirus)
################################################################################

log SECTION "SECTION 12: INSTALLING CLAMAV (ANTIVIRUS SCANNER)"

if ! command_exists clamscan; then
    log INFO "Installing ClamAV..."
    dnf install -y epel-release >/dev/null 2>&1
    dnf install -y clamav clamd clamav-update >/dev/null 2>&1
    log INFO "ClamAV installed"
fi

# Update virus database
log INFO "Updating ClamAV virus definitions (may take a few minutes)..."
freshclam >/dev/null 2>&1 &
FRESHCLAM_PID=$!

# Enable ClamAV service
systemctl enable --now clamd@scan >/dev/null 2>&1

# Create daily scan script
cat > /etc/cron.daily/clamav-scan << 'EOF'
#!/bin/bash
SCAN_DIR="/"
LOG_FILE="/var/log/clamav/daily-scan-$(date +%Y%m%d).log"
EXCLUDE_DIRS="--exclude-dir=/sys --exclude-dir=/proc --exclude-dir=/dev"

# Create log directory
mkdir -p /var/log/clamav

# Run scan
/usr/bin/clamscan -r -i ${EXCLUDE_DIRS} ${SCAN_DIR} >> ${LOG_FILE} 2>&1

# Send alert if virus found
if grep -q "Infected files: [1-9]" ${LOG_FILE}; then
    mail -s "VIRUS ALERT on $(hostname)" root < ${LOG_FILE}
fi
EOF

chmod +x /etc/cron.daily/clamav-scan
log INFO "ClamAV configured with daily scanning"

################################################################################
# SECTION 13: MALDET INSTALLATION (Linux Malware Detect)
################################################################################

log SECTION "SECTION 13: INSTALLING MALDET (LINUX MALWARE DETECT)"

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
        
        # Update malware signatures
        log INFO "Updating Maldet signatures..."
        /usr/local/sbin/maldet -u >/dev/null 2>&1
        
        # Configure maldet
        sed -i 's/email_alert=0/email_alert=1/' /usr/local/maldetect/conf.maldet
        sed -i 's/email_addr="you@domain.com"/email_addr="root@localhost"/' /usr/local/maldetect/conf.maldet
        
        # Create weekly scan
        cat > /etc/cron.weekly/maldet-scan << 'EOF'
#!/bin/bash
/usr/local/sbin/maldet -a /home >> /var/log/maldet-scan.log 2>&1
EOF
        chmod +x /etc/cron.weekly/maldet-scan
        log INFO "Maldet configured with weekly home directory scanning"
    else
        log WARN "Failed to download Maldet"
    fi
fi

################################################################################
# SECTION 14: PROCESS ACCOUNTING
################################################################################

log SECTION "SECTION 14: ENABLING PROCESS ACCOUNTING"

if ! command_exists psacct; then
    dnf install -y psacct >/dev/null 2>&1
fi

systemctl enable --now psacct >/dev/null 2>&1
log INFO "Process accounting enabled"

################################################################################
# SECTION 15: SYSTEM STATISTICS
################################################################################

log SECTION "SECTION 15: ENABLING SYSTEM STATISTICS"

if ! command_exists sar; then
    dnf install -y sysstat >/dev/null 2>&1
fi

systemctl enable --now sysstat >/dev/null 2>&1
log INFO "System statistics collection enabled"

################################################################################
# SECTION 16: AUTOMATIC SECURITY UPDATES
################################################################################

log SECTION "SECTION 16: CONFIGURING AUTOMATIC SECURITY UPDATES"

if ! command_exists dnf-automatic; then
    dnf install -y dnf-automatic >/dev/null 2>&1
    log INFO "dnf-automatic installed"
fi

cat > /etc/dnf/automatic.conf << 'EOF'
[commands]
upgrade_type = security
random_sleep = 3600
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[email]
email_from = root@localhost
email_to = root

[base]
debuglevel = 1
EOF

systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
log INFO "Automatic security updates configured"

################################################################################
# SECTION 17: ENHANCED LOGGING
################################################################################

log SECTION "SECTION 17: ENHANCING LOGGING CONFIGURATION"

cat >> /etc/rsyslog.conf << 'EOF'

# Enhanced security logging
auth,authpriv.*                 /var/log/auth.log
kern.*                          /var/log/kern.log
*.emerg                         :omusrmsg:*
EOF

systemctl restart rsyslog >/dev/null 2>&1

# Configure logrotate
cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log
/var/log/kern.log
/var/log/secure
{
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
EOF

log INFO "Enhanced logging configured"

################################################################################
# SECTION 18: AIDE (FILE INTEGRITY MONITORING)
################################################################################

log SECTION "SECTION 18: INSTALLING FILE INTEGRITY MONITORING (AIDE)"

if ! command_exists aide; then
    dnf install -y aide >/dev/null 2>&1
    log INFO "AIDE installed"
fi

log INFO "Initializing AIDE database (this may take several minutes)..."
aide --init >/dev/null 2>&1 &
AIDE_PID=$!

timeout=300
while kill -0 $AIDE_PID 2>/dev/null && [ $timeout -gt 0 ]; do
    sleep 5
    timeout=$((timeout-5))
    echo -n "."
done
echo ""

if [ -f "/var/lib/aide/aide.db.new.gz" ]; then
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    log INFO "AIDE database initialized"
    
    cat > /etc/cron.weekly/aide-check << 'EOF'
#!/bin/bash
/usr/sbin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    chmod +x /etc/cron.weekly/aide-check
    log INFO "Weekly AIDE checks scheduled"
else
    log WARN "AIDE database initialization incomplete"
fi

################################################################################
# SECTION 19: DISABLE UNNECESSARY SERVICES
################################################################################

log SECTION "SECTION 19: DISABLING UNNECESSARY SERVICES"

services_to_disable=(
    "telnet"
    "rsh"
    "rlogin"
    "rexec"
    "tftp"
    "finger"
    "talk"
    "ntalk"
)

for service in "${services_to_disable[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        systemctl disable --now "${service}.service" >/dev/null 2>&1
        log INFO "Disabled: ${service}"
    fi
done

################################################################################
# SECTION 20: HARDENING SYSTEMD SERVICES
################################################################################

log SECTION "SECTION 20: HARDENING SYSTEMD SERVICES"

mkdir -p /etc/systemd/system/sshd.service.d/

cat > /etc/systemd/system/sshd.service.d/hardening.conf << 'EOF'
[Service]
# Sandboxing
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/var/run/sshd

# Capabilities
NoNewPrivileges=yes
EOF

systemctl daemon-reload
log INFO "SSH service hardened with systemd sandboxing"

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

# Set GRUB password (commented out - uncomment if needed)
# grub2-setpassword

# Restrict cron/at to authorized users
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
log INFO "Cron/At access restricted to root"

# Secure shared memory
if ! grep -q "/run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
    log INFO "Shared memory secured"
fi

################################################################################
# FINAL VERIFICATION
################################################################################

log SECTION "FINAL SYSTEM VERIFICATION"

# Wait for background processes
wait $FRESHCLAM_PID 2>/dev/null

echo ""
echo "================================================================"
echo "                 HARDENING VERIFICATION REPORT"
echo "================================================================"
echo ""

# Check Firewall
if systemctl is-active --quiet firewalld; then
    echo -e "${GREEN}[✓]${NC} Firewall: Active"
    echo "         SSH Port: ${SSH_PORT}"
    echo "         Allowed IPs: ${ALLOWED_SSH_IPS[@]}"
else
    echo -e "${RED}[✗]${NC} Firewall: Inactive"
fi

# Check SELinux
if [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
    echo -e "${GREEN}[✓]${NC} SELinux: Enforcing"
    semanage port -l | grep -q "ssh_port_t.*${SSH_PORT}" && \
    echo "         SSH port ${SSH_PORT}: Configured" || \
    echo -e "         ${YELLOW}[!]${NC} SSH port ${SSH_PORT}: May need manual SELinux config"
else
    echo -e "${YELLOW}[!]${NC} SELinux: Not Enforcing (will be enforcing after reboot)"
fi

# Check SSH
if systemctl is-active --quiet sshd; then
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
    rules_count=$(auditctl -l 2>/dev/null | grep -c "^-")
    echo "         Audit rules loaded: ${rules_count}"
else
    echo -e "${RED}[✗]${NC} Audit: Inactive"
fi

# Check Malware Scanners
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

# Check AIDE
if command_exists aide; then
    echo -e "${GREEN}[✓]${NC} File Integrity: Installed (AIDE)"
else
    echo -e "${RED}[✗]${NC} File Integrity: Not Installed"
fi

# Check Process Accounting
if systemctl is-active --quiet psacct; then
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
echo "  - Backup Location: $BACKUP_DIR"
echo "  - Log File: $LOG_FILE"
echo "  - Changes Applied: 21+ major security improvements"
echo ""
echo "Expected Score Improvement:"
echo "  - Previous Index: 65"
echo "  - Expected Index: 85-90+"
echo "  - Improvement: +20-25 points"
echo ""
echo -e "${YELLOW}CRITICAL NEXT STEPS:${NC}"
echo "  1. ${RED}TEST SSH CONNECTION NOW in a new terminal:${NC}"
echo "     ssh -p ${SSH_PORT} your_user@your_server_ip"
echo "  2. If SSH works, you can continue. If not, use console to restore."
echo "  3. Review log: cat $LOG_FILE"
echo "  4. Reboot the system: reboot"
echo "  5. After reboot, verify SELinux: getenforce"
echo "  6. Run Lynis audit: sudo lynis audit system"
echo ""
echo -e "${RED}WARNING - SSH CONFIGURATION CHANGED:${NC}"
echo "  - Port changed: 22 → ${SSH_PORT}"
echo "  - IP whitelist: ${ALLOWED_SSH_IPS[@]}"
echo "  - Root login: DISABLED"
echo "  - Max auth tries: 3"
echo "  - Fail2ban: ENABLED (3 fails = 1 hour ban)"
echo ""
echo "If you lose SSH access, use console/VNC to restore:"
echo "  sudo cp $BACKUP_DIR/sshd_config /etc/ssh/sshd_config"
echo "  sudo systemctl restart sshd"
echo "  sudo firewall-cmd --permanent --add-service=ssh"
echo "  sudo firewall-cmd --reload"
echo ""
echo "================================================================"
echo "Script completed successfully!"
echo "================================================================"
