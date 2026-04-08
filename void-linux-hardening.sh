#!/usr/bin/env bash
set -Eeuo pipefail
trap 'log_error "Error at line ${LINENO}: ${BASH_COMMAND} (exit code: $?)"' ERR

SYSCTL_CONF="/etc/sysctl.d/99-custom-hardening.conf"
DOAS_CONF="/etc/doas.conf"
XBPS_IGNORE_CONF="/etc/xbps.d/ignore.conf"
NM_MAC_RANDOMIZE_CONF="/etc/NetworkManager/conf.d/00-macrandomize.conf"
LOG_FILE="/var/log/hardening.log"

log() {
    local level="$1"
    shift
    echo "[$(date '+%F %T')] [$level] $*" | tee -a "$LOG_FILE"
}

log_info()    { log INFO "$@"; }
log_success() { log OK "$@"; }
log_error()   { log ERROR "$@" >&2; }

confirm() {
    local prompt="${1:-Are you sure?}"
    local answer

    while true; do
        read -rp "Confirm \"$prompt\" [y/n]: " answer
        case "$answer" in
            [Yy]) return 0 ;;
            [Nn]) return 1 ;;
            *) echo "Please answer y or n." ;;
        esac
    done
}

require_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        log_error "Root privileges are required to run this script."
        exit 1
    fi
}

require_void() {
    if ! grep -q "Void" /etc/os-release; then
        log_error "This script is designed for Void Linux."
        exit 1
    fi
}

require_repo() {
    if ! xbps-install -S >/dev/null 2>&1; then
        log_error "Internet required to run this script"
        exit 1
    fi
}

install_package() {
    local package="$1"

    if xbps-query -S "$package" >/dev/null 2>&1; then
        log_info "$package already installed."
    else
        log_info "Installing $package..."
        if ! xbps-install -y "$package" >/dev/null; then
            log_error "Failed to install $package"
            exit 1
        fi
        log_success "$package installed successfully."
    fi
}

init_system() {
    log_info "Updating system packages..."
    xbps-install -Suvy >/dev/null
}

apply_sysctl_patches() {
    log_info "Applying system hardening patches..."

    mkdir -p "$(dirname "$SYSCTL_CONF")"
    if [[ -f $SYSCTL_CONF ]]; then
        cp -a "$SYSCTL_CONF" "${SYSCTL_CONF}.$(date +%s).bak"
    fi

    cat > "$SYSCTL_CONF" << 'EOF'
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.kexec_load_disabled=1
kernel.perf_event_paranoid=3
kernel.unprivileged_bpf_disabled=1
kernel.sysrq=0
kernel.yama.ptrace_scope=1
vm.unprivileged_userfaultfd=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv6.conf.all.forwarding=0
net.ipv4.tcp_syncookies=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.tcp_rfc1337=1
net.core.bpf_jit_harden=2
EOF

    chmod 0400 "$SYSCTL_CONF"

    sysctl --system >/dev/null
    log_success "Patches applied and made permanent."
}

setup_firewall() {
    if confirm "Enable firewall? (Desktop configuration)"; then

        log_info "Configuring nftables firewall..."

        install_package nftables

        local NFT_CONF="/etc/nftables.conf"

        if [[ -f "$NFT_CONF" ]]; then
            cp -a "$NFT_CONF" "${NFT_CONF}.$(date +%s).bak"
        fi

        cat > "$NFT_CONF" << 'EOF'
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0;
        policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related
        ct state established,related accept

        # Allow ICMP (ping ecc.)
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # DHCP client
        udp sport 67 udp dport 68 accept
        udp sport 68 udp dport 67 accept

        # Log & drop everything else
        log prefix "nft-input-drop: " flags all counter drop
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;
    }

    chain output {
        type filter hook output priority 0;
        policy accept;
    }
}
EOF

        chmod 600 "$NFT_CONF"
        
        if [[ ! -d /var/service/nftables ]]; then
            ln -s /etc/sv/nftables /var/service/
        fi
        
        nft -f "$NFT_CONF"
        
        log_success "nftables firewall configured and active."
    fi
}

configure_network() {
    if confirm "Enable MAC randomization? (recommended)"; then
        log_info "Configuring MAC randomization in NetworkManager..."
        mkdir -p "$(dirname "$NM_MAC_RANDOMIZE_CONF")"

        cat > "$NM_MAC_RANDOMIZE_CONF" << 'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF
        log_success "MAC randomization configured."
    fi
}

replace_sudo_with_doas() {
    log_info "Installing and configuring doas..."
    install_package opendoas

    if [[ -f "$DOAS_CONF" ]]; then
        cp -a "$DOAS_CONF" "${DOAS_CONF}.$(date +%s).bak"
    fi

    cat > "$DOAS_CONF" << 'EOF'
permit :wheel
EOF

    if ! doas -C "$DOAS_CONF"; then
        log_error "Configuration error in doas.conf"
        exit 1
    fi

    chown root:root "$DOAS_CONF"
    chmod 0400 "$DOAS_CONF"
    log_success "Doas installed and configured."


    if confirm "Remove sudo from system? (recommended)"; then
        if xbps-query -S sudo >/dev/null 2>&1; then
            mkdir -p "$(dirname "$XBPS_IGNORE_CONF")"
            cat > "$XBPS_IGNORE_CONF" << 'EOF'
ignorepkg=sudo
EOF

            xbps-remove -y sudo
            log_success "Sudo successfully removed."
        else
            log_info "Sudo is not installed, skipping removal."
        fi
    fi
}

linux_lts() {
    if confirm "Install linux-lts? (raccomanded)"; then
        install_package linux-lts
        install_package linux-lts-headers
        if confirm "Remove old kernels?"; then
            mkdir -p "$(dirname "$XBPS_IGNORE_CONF")"
            if [[ -f $XBPS_IGNORE_CONF ]]; then
                cp -a "$XBPS_IGNORE_CONF" "${XBPS_IGNORE_CONF}.$(date +%s).bak"
            fi

            touch "$XBPS_IGNORE_CONF"
            for pkg in linux linux-headers; do
                if ! grep -qxF "ignorepkg=$pkg" "$XBPS_IGNORE_CONF"; then
                    echo "ignorepkg=$pkg" >> "$XBPS_IGNORE_CONF"
                fi

                if xbps-query -S "$pkg" >/dev/null 2>&1; then
                    log_info "Removing $pkg..."
                    xbps-remove -y "$pkg"
                else
                    log_info "$pkg not installed, skipping"
                fi
            done
        fi
    fi
}

app_armor() {
    if apparmor_status >/dev/null; then
        log_info "apparmor already enabled"       
        aa-enforce /etc/apparmor.d/* >/dev/null
    else
        install_package apparmor
        log_info "Add parameter 'apparmor=1 security=apparmor' to '/etc/default/grub' at section 'GRUB_CMDLINE_LINUX_DEFAULT'. Then type 'update-grub' and restart"
    fi
}

main() {
    require_root
    require_void
    require_repo

    if confirm "This script is for desktop only. Run?"; then
        init_system
        apply_sysctl_patches
        setup_firewall
        configure_network
        replace_sudo_with_doas
        linux_lts
        app_armor
    fi
}

main
