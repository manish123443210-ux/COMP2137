#!/usr/bin/env bash
# COMP2137 Assignment 2 – Ubuntu server configuration for server1
# Idempotent, human-friendly output, logs to /var/log/assignment2.log.
# Requirements implemented:
# - Netplan: set 192.168.16.21/24 on the 192.168.16.x interface only (do not touch mgmt)
# - /etc/hosts: 192.168.16.21 server1 (remove any old server1 lines)
# - Packages: apache2, squid installed, enabled, running (default config)
# - Users: dennis(+sudo +extra ed25519 key), aubrey, captain, snibbles, brownie,
#          scooter, sandy, perrier, cindy, tiger, yoda
#   Each has /home dir, /bin/bash, SSH RSA(4096) + ED25519 keys, and both pubkeys in authorized_keys

set -euo pipefail

LOGFILE="/var/log/assignment2.log"
TARGET_ADDR_CIDR="192.168.16.21/24"
TARGET_IP="192.168.16.21"
SUBNET_REGEX='^192\.168\.16\.'
REQ_PKGS=(apache2 squid)
USERS=(dennis aubrey captain snibbles brownie scooter sandy perrier cindy tiger yoda)
DENNIS_EXTRA_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG4rT3vTt99Ox5kndS4HmgTrKBT8SKzhK4rhGkEVGlCI student@generic-vm'

ts(){ date +'%F %T'; }
log(){ echo -e "$(ts) | $*" | tee -a "$LOGFILE"; }
ok(){ log "✔ $*"; }
chg(){ log "⚙ $*"; }
warn(){ log "⚠ $*"; }
err(){ log "✖ $*"; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    echo "❌ Run as root (sudo -i)." | tee -a "$LOGFILE"; exit 1
  fi
}

find_netplan_file(){
  shopt -s nullglob
  for f in /etc/netplan/*.yaml /etc/netplan/*.yml; do echo "$f"; return 0; done
  return 1
}

detect_iface_192_168_16(){
  local ifc
  ifc=$(ip -o -4 addr show | awk -v r="$SUBNET_REGEX" '$4 ~ r {print $2; exit}')
  [[ -n "${ifc:-}" ]] && { echo "$ifc"; return; }
  ifc=$(ip route | awk '/192\.168\.16\.0\/24/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)
  [[ -n "${ifc:-}" ]] && { echo "$ifc"; return; }
  ifc=$(ip -o link show | awk -F': ' '$2!="lo"{print $2}' | grep -vi mgmt | head -n1)
  echo "$ifc"
}

ensure_unique_line(){
  # $1=line, $2=file
  local line="$1" file="$2"
  grep -qxF -- "$line" "$file" 2>/dev/null || echo "$line" >> "$file"
}

delete_matching_lines(){
  # $1=regex, $2=file
  local rx="$1" file="$2"
  [[ -f "$file" ]] || return 0
  sed -i.bak "/$rx/d" "$file"
}

ensure_pkg(){
  local p="$1"
  if dpkg -s "$p" >/dev/null 2>&1; then
    ok "Package $p already installed."
  else
    chg "Installing package $p."
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$p" >>"$LOGFILE" 2>&1
  fi
  systemctl enable "$p" >>"$LOGFILE" 2>&1 || true
  systemctl restart "$p" >>"$LOGFILE" 2>&1 || true
  if systemctl is-active --quiet "$p"; then ok "$p is active & enabled."; else warn "$p did not start; check: journalctl -u $p"; fi
}

add_user_if_missing(){
  local u="$1"
  if id "$u" >/dev/null 2>&1; then
    ok "User $u exists."
  else
    chg "Creating user $u (home in /home, shell /bin/bash)."
    useradd -m -s /bin/bash "$u"
  fi
  local cur_shell
  cur_shell="$(getent passwd "$u" | awk -F: '{print $7}')"
  if [[ "$cur_shell" != "/bin/bash" ]]; then
    chg "Setting /bin/bash as login shell for $u."
    chsh -s /bin/bash "$u"
  fi
}

ensure_ssh_keys_for_user(){
  local u="$1"
  local home_dir ssh_dir auth_file
  home_dir="$(getent passwd "$u" | awk -F: '{print $6}')"
  ssh_dir="${home_dir}/.ssh"
  auth_file="${ssh_dir}/authorized_keys"

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  chown "$u:$u" "$ssh_dir"

  # RSA (4096)
  if [[ ! -f "${ssh_dir}/id_rsa" || ! -f "${ssh_dir}/id_rsa.pub" ]]; then
    chg "Generating RSA key for $u."
    sudo -u "$u" ssh-keygen -q -t rsa -b 4096 -N '' -f "${ssh_dir}/id_rsa"
  else
    ok "RSA key already present for $u."
  fi

  # ED25519
  if [[ ! -f "${ssh_dir}/id_ed25519" || ! -f "${ssh_dir}/id_ed25519.pub" ]]; then
    chg "Generating ED25519 key for $u."
    sudo -u "$u" ssh-keygen -q -t ed25519 -N '' -f "${ssh_dir}/id_ed25519"
  else
    ok "ED25519 key already present for $u."
  fi

  touch "$auth_file"
  chmod 600 "$auth_file"
  chown "$u:$u" "$auth_file"

  # Add both public keys to authorized_keys (no duplicates)
  local rsa_pub ed_pub
  rsa_pub="$(cat "${ssh_dir}/id_rsa.pub")"
  ed_pub="$(cat "${ssh_dir}/id_ed25519.pub")"
  grep -qxF "$rsa_pub" "$auth_file" || echo "$rsa_pub" >> "$auth_file"
  grep -qxF "$ed_pub"  "$auth_file" || echo "$ed_pub"  >> "$auth_file"
  ok "authorized_keys contains RSA+ED25519 for $u."
}

configure_dennis_sudo_and_extra_key(){
  local u="dennis" home_dir ssh_dir auth_file
  adduser "$u" sudo >/dev/null 2>&1 || true
  ok "User dennis is in sudo group."

  home_dir="$(getent passwd "$u" | awk -F: '{print $6}')"
  ssh_dir="${home_dir}/.ssh"
  auth_file="${ssh_dir}/authorized_keys"
  mkdir -p "$ssh_dir"; chmod 700 "$ssh_dir"; chown "$u:$u" "$ssh_dir"
  touch "$auth_file"; chmod 600 "$auth_file"; chown "$u:$u" "$auth_file"

  if ! grep -qxF "$DENNIS_EXTRA_PUBKEY" "$auth_file"; then
    chg "Adding instructor-provided ed25519 key for dennis."
    echo "$DENNIS_EXTRA_PUBKEY" >> "$auth_file"
  fi
  ok "dennis has the extra required ed25519 key."
}

apply_netplan_for_192_168_16(){
  local npfile ifc current_addr
  npfile="$(find_netplan_file || true)"
  [[ -z "$npfile" ]] && { err "No /etc/netplan/*.yaml found."; exit 1; }
  ok "Netplan file: $npfile"

  ifc="$(detect_iface_192_168_16)"
  [[ -z "$ifc" ]] && { err "Could not detect interface for 192.168.16.x"; exit 1; }
  ok "Interface chosen for 192.168.16.x: $ifc"

  current_addr="$(ip -o -4 addr show dev "$ifc" | awk '{print $4}' | grep -E "$SUBNET_REGEX" || true)"
  if [[ "$current_addr" == "$TARGET_ADDR_CIDR" ]]; then
    ok "$ifc already has $TARGET_ADDR_CIDR."
    return
  fi

  chg "Configuring $ifc with static $TARGET_ADDR_CIDR via netplan (leaving mgmt iface alone)."
  cp -a "$npfile" "${npfile}.bak.$(date +%s)"

  # Use netplan set to avoid hand-editing YAML; this writes an override that the system will honor.
  netplan set "ethernets.${ifc}.dhcp4=false"
  netplan set "ethernets.${ifc}.addresses=[${TARGET_ADDR_CIDR}]"

  netplan generate
  netplan apply
  sleep 1

  current_addr="$(ip -o -4 addr show dev "$ifc" | awk '{print $4}' | grep -E "$SUBNET_REGEX" || true)"
  if [[ "$current_addr" == "$TARGET_ADDR_CIDR" ]]; then
    ok "$ifc now has $TARGET_ADDR_CIDR."
  else
    warn "After apply, $ifc shows '${current_addr:-none}'. Continue but verify."
  fi
}

fix_hosts(){
  [[ -f /etc/hosts ]] || touch /etc/hosts
  if grep -E '(^|\s)server1(\s|$)' /etc/hosts >/dev/null 2>&1; then
    chg "Removing old server1 lines from /etc/hosts."
    delete_matching_lines '(^|\s)server1(\s|$)' /etc/hosts
  fi
  echo "${TARGET_IP} server1" >> /etc/hosts
  # ensure uniqueness (in case of rerun)
  awk '!x[$0]++' /etc/hosts > /etc/hosts.tmp && mv /etc/hosts.tmp /etc/hosts
  ok "/etc/hosts updated: ${TARGET_IP} server1"
}

main(){
  need_root
  touch "$LOGFILE" && chmod 600 "$LOGFILE"
  log "===== COMP2137 Assignment 2 start on $(hostname) ====="

  # 1) Network on 192.168.16.x
  apply_netplan_for_192_168_16

  # 2) /etc/hosts
  fix_hosts

  # 3) Packages
  chg "Refreshing package index…"
  DEBIAN_FRONTEND=noninteractive apt-get update -y >>"$LOGFILE" 2>&1 || true
  for p in "${REQ_PKGS[@]}"; do ensure_pkg "$p"; done

  # 4) Users & SSH keys
  for u in "${USERS[@]}"; do
    add_user_if_missing "$u"
    ensure_ssh_keys_for_user "$u"
  done
  configure_dennis_sudo_and_extra_key

  log "===== All tasks completed. Safe to re-run. ====="
}

main
