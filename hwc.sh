#!/usr/bin/env bash
#
# Description: Ultimate All-in-One Manager for Caddy, Sing-box & AdGuard Home with self-installing shortcut.
# Author: Your Name (Inspired by P-TERX, Refactored for Sing-box)
# Version: 6.5.8 (HereDoc Syntax Fix)

# --- 第1節:全域設定與定義 ---
set -eo pipefail

# 顏色定義,用於日誌輸出
FontColor_Red="\033[31m"; FontColor_Green="\033[32m"; FontColor_Yellow="\033[33m"
FontColor_Purple="\033[35m"; FontColor_Suffix="\033[0m"

# 標準化日誌函數
log() {
    local LEVEL="$1"; local MSG="$2"
    case "${LEVEL}" in
        INFO)  local LEVEL="[${FontColor_Green}資訊${FontColor_Suffix}]";;
        WARN)  local LEVEL="[${FontColor_Yellow}警告${FontColor_Suffix}]";;
        ERROR) local LEVEL="[${FontColor_Red}錯誤${FontColor_Suffix}]";;
    esac
    echo -e "${LEVEL} ${MSG}"
}

# 固定的應用程式基礎目錄
APP_BASE_DIR="/root/hwc"
CADDY_CONTAINER_NAME="caddy-manager"; CADDY_IMAGE_NAME="caddy:latest"; CADDY_CONFIG_DIR="${APP_BASE_DIR}/caddy"; CADDY_CONFIG_FILE="${CADDY_CONFIG_DIR}/Caddyfile"; CADDY_DATA_VOLUME="hwc_caddy_data"
SINGBOX_CONTAINER_NAME="sing-box"; SINGBOX_IMAGE_NAME="ghcr.io/sagernet/sing-box:v1.13.0-alpha.27@sha256:1dd5978b10911a83e80bac61ad30c5d28f1f689dc89f1d733a50b031dc4bf4f6"; SINGBOX_CONFIG_DIR="${APP_BASE_DIR}/singbox"; SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_DIR}/config.json"
ADGUARD_CONTAINER_NAME="adguard-home"; ADGUARD_IMAGE_NAME="adguard/adguardhome:edge"; ADGUARD_CONFIG_DIR="${APP_BASE_DIR}/adguard/conf"; ADGUARD_WORK_DIR="${APP_BASE_DIR}/adguard/work"
SHARED_NETWORK_NAME="hwc-proxy-net"
SCRIPT_URL="https://raw.githubusercontent.com/thenogodcom/hwc/main/hwc.sh"; SHORTCUT_PATH="/usr/local/bin/hwc"
declare -A CONTAINER_STATUSES

# --- 第2節:所有函數定義 ---

self_install() {
    local args_string; printf -v args_string '%q ' "$@"
    local running_script_path
    if [[ -f "$0" ]]; then running_script_path=$(readlink -f "$0"); fi
    if [ "$running_script_path" = "$SHORTCUT_PATH" ]; then return 0; fi
    log INFO "首次運行設定:正在安裝 'hwc' 快捷命令以便日後存取..."
    if ! command -v curl &>/dev/null; then
        log WARN "'curl' 未安裝,正在嘗試安裝..."
        if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y --no-install-recommends curl; fi
        if command -v yum &>/dev/null || command -v dnf &>/dev/null; then
            command -v yum &>/dev/null && yum install -y curl
            command -v dnf &>/dev/null && dnf install -y curl
        fi
    fi
    if curl -sSL "${SCRIPT_URL}" -o "${SHORTCUT_PATH}"; then
        chmod +x "${SHORTCUT_PATH}"
        log INFO "快捷命令 'hwc' 安裝成功。正在從新位置重新啟動..."
        exec "${SHORTCUT_PATH}" $args_string
    else
        log ERROR "無法安裝 'hwc' 快捷命令至 ${SHORTCUT_PATH}。"
        log WARN "本次將臨時運行腳本,請檢查權限後重試。"
        sleep 3
    fi
}
validate_domain() { local domain="$1"; if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then log ERROR "域名格式無效: $domain"; return 1; fi; return 0; }
validate_email() { local email="$1"; if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then log ERROR "郵箱格式無效: $email"; return 1; fi; return 0; }
validate_backend_service() { local service="$1"; if [[ ! "$service" =~ ^[a-zA-Z0-9\._-]+:[0-9]+$ ]]; then log ERROR "後端服務地址格式無效(應為 hostname:port): $service"; return 1; fi; return 0; }
detect_cert_path() {
    local domain="$1"; local base_path="/data/caddy/certificates"
    if container_exists "$CADDY_CONTAINER_NAME"; then
        for ca_dir in "acme-v02.api.letsencrypt.org-directory" "acme.zerossl.com-v2-DV90"; do
            local cert_check
            cert_check=$(docker exec "$CADDY_CONTAINER_NAME" sh -c "[ -f $base_path/$ca_dir/$domain/$domain.crt ] && echo 'exists'" 2>/dev/null)
            if [ "$cert_check" = "exists" ]; then
                echo "$base_path/$ca_dir/$domain/$domain.crt|$base_path/$ca_dir/$domain/$domain.key"; return 0
            fi
        done
    fi
    echo "$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.crt|$base_path/acme-v02.api.letsencrypt.org-directory/$domain/$domain.key"; return 1
}
generate_random_password() { local part1=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 8); local part2=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4); local part3=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4); local part4=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 4); local part5=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 12); echo "${part1}-${part2}-${part3}-${part4}-${part5}"; }
install_docker() { log INFO "偵測到 Docker 未安裝,正在使用官方通用腳本進行安裝..."; if ! curl -fsSL https://get.docker.com | sh; then log ERROR "Docker 安裝失敗。請手動運行 'curl -fsSL https://get.docker.com | sh' 檢查錯誤。"; exit 1; fi; log INFO "正在啟動並設定 Docker 開機自啟..."; if ! systemctl start docker; then log ERROR "無法啟動 Docker 服務。請使用 'systemctl status docker' 檢查狀態。"; exit 1; fi; systemctl enable docker; log INFO "Docker 安裝成功並已啟動。"; }
check_root() { if [ "$EUID" -ne 0 ]; then log ERROR "此腳本必須以 root 身份運行。"; exit 1; fi; }
check_docker() { if ! command -v docker &>/dev/null; then install_docker; fi; if ! docker info > /dev/null 2>&1; then log WARN "Docker 服務未運行,正在嘗試啟動..."; systemctl start docker; sleep 3; if ! docker info > /dev/null 2>&1; then log ERROR "無法啟動 Docker 服務,請手動檢查。"; exit 1; fi; log INFO "Docker 服務已成功啟動。"; fi; }
check_editor() { for editor in nano vi vim; do if command -v $editor &>/dev/null; then EDITOR=$editor; return 0; fi; done; log ERROR "未找到合適的文字編輯器 (nano, vi, vim)。"; return 1; }
container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }
connect_to_shared_network() { local container_name="$1"; docker network create "${SHARED_NETWORK_NAME}" &>/dev/null; log INFO "正在將容器 ${container_name} 連接到共享網絡 ${SHARED_NETWORK_NAME}..."; if docker network connect "${SHARED_NETWORK_NAME}" "${container_name}"; then log INFO "容器 ${container_name} 已成功連接到網絡。"; return 0; else log ERROR "無法將容器 ${container_name} 連接到網絡。"; log WARN "正在嘗試清理失敗的容器..."; docker rm -f "${container_name}" &>/dev/null; return 1; fi; }

# [FIXED] 恢复了正确的函数格式
generate_caddy_config() {
    local primary_domain="$1" email="$2" log_mode="$3" proxy_domain="$4" backend_service="$5"
    mkdir -p "${CADDY_CONFIG_DIR}"
    local global_log_block=""
    if [[ ! "$log_mode" =~ ^[yY]$ ]]; then
        global_log_block=$(cat <<-'GLOBALLOG'
    log {
        output stderr
        level  ERROR
    }
GLOBALLOG
)
    fi
    cat > "${CADDY_CONFIG_FILE}" <<EOF
{
    email ${email}
${global_log_block}
    servers {
        protocols h1 h2
    }
}
(security_headers) {
    header -Via
    header -Server
    header Server "nginx"
}
(proxy_to_backend) {
    reverse_proxy ${backend_service} {
        header_up Host {args.0}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
EOF
    if [ -n "$primary_domain" ]; then
        cat >> "${CADDY_CONFIG_FILE}" <<EOF
${primary_domain} {
    import security_headers
    import proxy_to_backend {host}
}
EOF
    fi
    local proxy_target="${primary_domain:-${backend_service}}"
    cat >> "${CADDY_CONFIG_FILE}" <<EOF
${proxy_domain} {
    import security_headers
    import proxy_to_backend ${proxy_target}
}
EOF
    log INFO "已為域名 ${proxy_domain}$([ -n "$primary_domain" ] && echo " 和 ${primary_domain}") 建立 Caddyfile。"
}

generate_warp_conf() { log INFO "正在使用 wgcf 註冊新的 WARP 帳戶 (動態下載最新版)..."; local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) log ERROR "不支援的CPU架構: $(uname -m)"; return 1;; esac; local CMD_TEMPLATE='
    apk add --no-cache curl ca-certificates jq && \
    WGCF_URL=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r ".assets[] | select(.name | contains(\\"linux_%s\\")) | .browser_download_url") && \
    if [ -z "$WGCF_URL" ]; then echo "錯誤：無法獲取 wgcf 下載鏈接。"; exit 1; fi && \
    curl -fL -o wgcf "$WGCF_URL" && \
    chmod +x wgcf && \
    ./wgcf'; local WGCF_CMD; printf -v WGCF_CMD "$CMD_TEMPLATE" "$arch"; rm -f "${SINGBOX_CONFIG_DIR}/wgcf-account.toml"
    if ! docker run --rm -v "${SINGBOX_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$WGCF_CMD register --accept-tos" > /dev/null 2>&1; then log ERROR "WARP 帳戶註冊失敗 (register)。請檢查網路或稍後重試。"; log INFO "詳細錯誤信息, 請手動運行以下命令查看:"; echo "docker run --rm -v \"${SINGBOX_CONFIG_DIR}:/data\" -w /data alpine:latest sh -c '$WGCF_CMD register --accept-tos'"; return 1; fi
    if ! docker run --rm -v "${SINGBOX_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$WGCF_CMD generate" > /dev/null 2>&1; then log ERROR "WARP 設定檔生成失敗 (generate)。"; return 1; fi; log INFO "WARP 帳戶和設定檔已成功生成。";
}

generate_singbox_config() {
    local domain="$1" password="$2" private_key="$3" ipv4_address="$4" ipv6_address="$5" public_key="$6" log_level="${7:-error}"; mkdir -p "${SINGBOX_CONFIG_DIR}"
    local cert_path_info; cert_path_info=$(detect_cert_path "$domain"); local cert_path="${cert_path_info%%|*}"; local key_path="${cert_path_info##*|}"; local cert_path_in_container="${cert_path/\/data/\/caddy_certs}"; local key_path_in_container="${key_path/\/data/\/caddy_certs}"
    local dns_servers_block; local dns_resolver_tag="cloudflare"
    if container_exists "$ADGUARD_CONTAINER_NAME" && [ "$(docker inspect -f '{{.State.Running}}' "$ADGUARD_CONTAINER_NAME" 2>/dev/null)" = "true" ]; then
        local AG_IP; AG_IP=$(docker inspect -f "{{ index .NetworkSettings.Networks \"${SHARED_NETWORK_NAME}\" \"IPAddress\" }}" "$ADGUARD_CONTAINER_NAME" 2>/dev/null)
        if [ -n "$AG_IP" ]; then
            log INFO "檢測到 AdGuard Home (IP: ${AG_IP})，Sing-box 將使用此 IP 進行 DNS 解析。"; dns_resolver_tag="adguard"
            dns_servers_block=$(cat <<DNS
      { "type": "udp", "server": "${AG_IP}", "server_port": 53, "tag": "adguard" },
DNS
)
        else
            log WARN "無法獲取 AdGuard Home 在 ${SHARED_NETWORK_NAME} 網絡的 IP，回退到 Cloudflare DNS。"; dns_servers_block=$(cat <<DNS
      { "type": "https", "server": "1.1.1.1", "tag": "cloudflare", "detour": "direct" },
DNS
)
        fi
    else
        log WARN "未檢測到運行的 AdGuard Home，Sing-box 將回退到 Cloudflare DNS。"; dns_servers_block=$(cat <<DNS
      { "type": "https", "server": "1.1.1.1", "tag": "cloudflare", "detour": "direct" },
DNS
)
    fi
    cat > "${SINGBOX_CONFIG_FILE}" <<EOF
{
  "log": { "disabled": false, "level": "${log_level}", "timestamp": true },
  "dns": { "servers": [ ${dns_servers_block} { "type": "local", "tag": "local-dns" } ], "strategy": "prefer_ipv4" },
  "endpoints": [ { "type": "wireguard", "tag": "warp-out", "system": false, "mtu": 1280, "address": [ "${ipv4_address}/32", "${ipv6_address}/128" ], "private_key": "${private_key}", "listen_port": 0, "peers": [ { "address": "162.159.192.1", "port": 2408, "public_key": "${public_key}", "allowed_ips": [ "0.0.0.0/0", "::/0" ], "persistent_keepalive_interval": 15, "reserved": [0, 0, 0] } ] } ],
  "inbounds": [ { "type": "hysteria2", "tag": "hysteria-in", "listen": "::", "listen_port": 443, "users": [ { "password": "${password}" } ], "tls": { "enabled": true, "server_name": "${domain}", "certificate_path": "${cert_path_in_container}", "key_path": "${key_path_in_container}" } }, { "type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 8008 } ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "rules": [ { "protocol": "dns", "outbound": "direct" }, { "ip_is_private": true, "outbound": "direct" }, { "domain_suffix": [ "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "github.com", "github.io", "githubassets.com", "githubusercontent.com" ], "outbound": "direct" } ], "final": "warp-out", "default_domain_resolver": "${dns_resolver_tag}", "auto_detect_interface": true }
}
EOF
    log INFO "Sing-box 優化設定檔生成完畢。"
}

manage_caddy() { if ! container_exists "$CADDY_CONTAINER_NAME"; then while true; do clear; log INFO "--- 管理 Caddy (未安裝) ---"; echo " 1. 安裝 Caddy (用於自動申請SSL證書)"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) log INFO "--- 正在安裝 Caddy ---"; read -p "請輸入主域名 (可選, 用於網站偽裝, 直接回車跳過): " PRIMARY_DOMAIN < /dev/tty; if [ -n "$PRIMARY_DOMAIN" ] && ! validate_domain "$PRIMARY_DOMAIN"; then press_any_key; continue; fi; while true; do read -p "請輸入代理域名 (必選, 用於 Sing-box): " PROXY_DOMAIN < /dev/tty; if [ -n "$PROXY_DOMAIN" ] && validate_domain "$PROXY_DOMAIN"; then break; fi; done; while true; do read -p "請輸入您的郵箱: " EMAIL < /dev/tty; if [ -n "$EMAIL" ] && validate_email "$EMAIL"; then break; fi; done; read -p "請輸入後端服務地址 [預設: app:80]: " BACKEND_SERVICE < /dev/tty; BACKEND_SERVICE=${BACKEND_SERVICE:-app:80}; if ! validate_backend_service "$BACKEND_SERVICE"; then press_any_key; continue; fi; read -p "是否為 Caddy 啟用詳細日誌？(y/N): " LOG_MODE < /dev/tty; generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "$LOG_MODE" "$PROXY_DOMAIN" "$BACKEND_SERVICE"; log INFO "正在拉取最新的 Caddy 鏡像..."; if ! docker pull "${CADDY_IMAGE_NAME}"; then log ERROR "Caddy 鏡像拉取失敗。"; press_any_key; break; fi; if docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "${CADDY_IMAGE_NAME}"; then if connect_to_shared_network "${CADDY_CONTAINER_NAME}"; then log INFO "Caddy 部署成功,正在後台申請證書..."; else log ERROR "Caddy 容器創建成功但網絡連接失敗，部署中止。"; fi; else log ERROR "Caddy 部署失敗。"; docker rm -f "${CADDY_CONTAINER_NAME}" 2>/dev/null; rm -rf "${CADDY_CONFIG_DIR}"; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; else while true; do clear; log INFO "--- 管理 Caddy (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯 Caddyfile"; echo " 3. 重啟 Caddy"; echo " 4. 卸載 Caddy"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) docker logs -f "$CADDY_CONTAINER_NAME"; press_any_key;; 2) if check_editor; then "$EDITOR" "${CADDY_CONFIG_FILE}"; log INFO "設定已儲存,請手動重啟以應用。"; fi; press_any_key;; 3) log INFO "正在重啟 Caddy..."; docker restart "$CADDY_CONTAINER_NAME"; sleep 2;; 4) log WARN "Sing-box 依賴 Caddy 提供證書,卸載 Caddy 將導致其無法工作。"; read -p "確定要卸載 Caddy 嗎? (y/N): " uninstall_choice < /dev/tty; if [[ "$uninstall_choice" =~ ^[yY]$ ]]; then docker stop "${CADDY_CONTAINER_NAME}" &>/dev/null && docker rm "${CADDY_CONTAINER_NAME}" &>/dev/null; read -p "是否刪除 Caddy 的設定檔和證書？(y/N): " del_choice < /dev/tty; if [[ "$del_choice" =~ ^[yY]$ ]]; then rm -rf "${CADDY_CONFIG_DIR}"; docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null; log INFO "Caddy 設定和數據已刪除。"; fi; docker rmi "${CADDY_IMAGE_NAME}" &>/dev/null; log INFO "Caddy 已卸載。"; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; fi; }
update_warp_keys() { if [ ! -f "$SINGBOX_CONFIG_FILE" ]; then log ERROR "Sing-box 設定檔 ${SINGBOX_CONFIG_FILE} 不存在。"; return 1; fi; if ! command -v jq &>/dev/null; then log INFO "正在安裝 JSON 處理工具 jq..."; if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y jq; elif command -v yum &>/dev/null; then yum install -y jq; elif command -v dnf &>/dev/null; then dnf install -y jq; else log ERROR "無法自動安裝 jq,請手動安裝後重試。"; return 1; fi; fi; log INFO "請提供您的靜態 WARP WireGuard 金鑰信息。"; local private_key warp_address ipv4_address ipv6_address; read -p "請輸入您的 WARP PrivateKey: " private_key < /dev/tty; read -p "請輸入您的 WARP Address (可直接粘貼帶 /32,/128 的完整行): " warp_address < /dev/tty; if [ -z "$private_key" ] || [[ ! "$warp_address" =~ "," ]]; then log ERROR "輸入格式無效。PrivateKey 和 Address 均不能為空,且 Address 必須包含逗號。"; return 1; fi; ipv4_address=$(echo "$warp_address" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs); ipv6_address=$(echo "$warp_address" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs); if [ -z "$ipv4_address" ] || [ -z "$ipv6_address" ]; then log ERROR "無法從輸入中正確解析 IPv4 和 IPv6 地址。請檢查格式。"; return 1; fi; jq --arg pk "$private_key" --arg ip4 "${ipv4_address}/32" --arg ip6 "${ipv6_address}/128" '.endpoints |= map(if .tag == "warp-out" then .private_key = $pk | .address = [$ip4, $ip6] else . end)' "$SINGBOX_CONFIG_FILE" > "${SINGBOX_CONFIG_FILE}.tmp" && mv "${SINGBOX_CONFIG_FILE}.tmp" "$SINGBOX_CONFIG_FILE"; if [ $? -eq 0 ]; then log INFO "WARP 金鑰已成功更新。請稍後手動重啟 Sing-box 容器以應用變更。"; else log ERROR "更新 WARP 金鑰失敗。設定檔未被修改。"; fi; }
manage_singbox() { if ! container_exists "$SINGBOX_CONTAINER_NAME"; then while true; do clear; log INFO "--- 管理 Sing-box (未安裝) ---"; echo " 1. 安裝 Sing-box (整合 Hysteria2 + WARP)"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) if ! container_exists "$CADDY_CONTAINER_NAME"; then log ERROR "依賴項缺失！請務必先安裝 Caddy。"; press_any_key; break; fi; log INFO "--- 正在安裝 Sing-box ---"; local available_domains; available_domains=$(awk 'NR>1 && NF>=2 && $2=="{" {print $1}' "${CADDY_CONFIG_FILE}" 2>/dev/null | tr '\n' ' '); local HY_DOMAIN=""; if [ -n "$available_domains" ]; then log INFO "檢測到以下可用域名: $available_domains"; read -p "請選擇 Sing-box 使用的域名 [${available_domains%% *}]: " HY_DOMAIN < /dev/tty; HY_DOMAIN=${HY_DOMAIN:-${available_domains%% *}}; else read -p "請輸入 Sing-box 使用的域名(必須與 Caddy 配置一致): " HY_DOMAIN < /dev/tty; fi; if [ -z "$HY_DOMAIN" ] || ! validate_domain "$HY_DOMAIN"; then press_any_key; break; fi; read -p "是否手動輸入密碼？(預設自動生成) (y/N): " MANUAL_PASSWORD < /dev/tty; if [[ "$MANUAL_PASSWORD" =~ ^[yY]$ ]]; then while true; do read -p "請設定連接密碼: " PASSWORD < /dev/tty; if [ -n "$PASSWORD" ]; then break; else log ERROR "密碼不能為空。"; fi; done; else PASSWORD=$(generate_random_password); log INFO "已自動生成連接密碼: ${FontColor_Yellow}${PASSWORD}${FontColor_Suffix}"; fi; local SINGBOX_LOG_LEVEL="error"; read -p "請選擇日誌級別 [1.warn | 2.info | 預設.error]: " LOG_CHOICE < /dev/tty; case "$LOG_CHOICE" in 1) SINGBOX_LOG_LEVEL="warn";; 2) SINGBOX_LOG_LEVEL="info";; esac; local private_key ipv4_address ipv6_address public_key; read -p "是否自動生成新的 WARP 帳戶？(Y/n): " AUTO_WARP < /dev/tty; if [[ ! "$AUTO_WARP" =~ ^[nN]$ ]]; then if ! generate_warp_conf; then press_any_key; break; fi; private_key=$(grep -oP 'PrivateKey = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"); public_key=$(grep -oP 'PublicKey = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"); warp_addresses=$(grep -oP 'Address = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"); ipv4_address=$(echo "$warp_addresses" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs); ipv6_address=$(echo "$warp_addresses" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs); if [ -z "$ipv4_address" ] || [ -z "$ipv6_address" ]; then log ERROR "從 wgcf-profile.conf 中提取 IP 地址失敗！"; log INFO "文件內容如下:"; cat "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"; press_any_key; break; fi; else log INFO "請提供您的靜態 WARP WireGuard 金鑰信息。"; read -p "請輸入您的 WARP PrivateKey: " private_key < /dev/tty; read -p "請輸入您的 WARP Address (可直接粘貼帶 /32,/128 的完整行): " warp_address < /dev/tty; if [ -z "$private_key" ] || [[ ! "$warp_address" =~ "," ]]; then log ERROR "輸入格式無效,安裝中止。"; press_any_key; break; fi; ipv4_address=$(echo "$warp_address" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs); ipv6_address=$(echo "$warp_address" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs); if [ -z "$ipv4_address" ] || [ -z "$ipv6_address" ]; then log ERROR "無法從輸入中正確解析 IPv4 和 IPv6 地址，安裝中止。"; press_any_key; break; fi; public_key="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="; fi; log INFO "正在拉取最新的 Sing-box 鏡像..."; if ! docker pull "${SINGBOX_IMAGE_NAME}"; then log ERROR "Sing-box 鏡像拉取失敗。"; press_any_key; break; fi; if ! generate_singbox_config "$HY_DOMAIN" "$PASSWORD" "$private_key" "$ipv4_address" "$ipv6_address" "$public_key" "$SINGBOX_LOG_LEVEL"; then log ERROR "Sing-box 設定檔生成失敗,安裝中止。"; press_any_key; break; fi; log INFO "正在部署 Sing-box 容器..."; if docker run -d --name "${SINGBOX_CONTAINER_NAME}" --restart always --cap-add NET_ADMIN -p 443:443/udp -p 8008:8008/tcp -v "${SINGBOX_CONFIG_FILE}:/etc/sing-box/config.json:ro" -v "${CADDY_DATA_VOLUME}:/caddy_certs:ro" "${SINGBOX_IMAGE_NAME}" run -c /etc/sing-box/config.json; then if connect_to_shared_network "${SINGBOX_CONTAINER_NAME}"; then log INFO "Sing-box 部署成功。"; else log ERROR "Sing-box 容器創建成功但網絡連接失敗，部署中止。"; fi; else log ERROR "Sing-box 部署失敗,正在清理..."; docker rm -f "${SINGBOX_CONTAINER_NAME}" 2>/dev/null; rm -rf "${SINGBOX_CONFIG_DIR}"; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; else while true; do clear; log INFO "--- 管理 Sing-box (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯設定檔"; echo " 3. 重啟 Sing-box"; echo " 4. 手動更換 WARP 金鑰"; echo " 5. 卸載 Sing-box"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) docker logs -f "$SINGBOX_CONTAINER_NAME"; press_any_key;; 2) if check_editor; then "$EDITOR" "${SINGBOX_CONFIG_FILE}"; log INFO "設定已儲存,請手動重啟以應用。"; fi; press_any_key;; 3) log INFO "正在重啟 Sing-box..."; docker restart "$SINGBOX_CONTAINER_NAME"; sleep 2;; 4) update_warp_keys; press_any_key;; 5) read -p "確定要卸載 Sing-box 嗎? (y/N): " uninstall_choice < /dev/tty; if [[ "$uninstall_choice" =~ ^[yY]$ ]]; then docker stop "${SINGBOX_CONTAINER_NAME}" &>/dev/null && docker rm "${SINGBOX_CONTAINER_NAME}" &>/dev/null; rm -rf "${SINGBOX_CONFIG_DIR}"; docker rmi -f "${SINGBOX_IMAGE_NAME}" &>/dev/null; log INFO "Sing-box 已卸載,設定檔已清除。"; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; fi; }
manage_adguard() { if ! container_exists "$ADGUARD_CONTAINER_NAME"; then while true; do clear; log INFO "--- 管理 AdGuard Home (未安裝) ---"; echo " 1. 安裝 AdGuard Home (內部 DNS 過濾)"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) log INFO "--- 正在安裝 AdGuard Home (內部DNS模式) ---"; if lsof -i :53 -sTCP:LISTEN -t >/dev/null || lsof -i :53 -sUDP:LISTEN -t >/dev/null; then log WARN "檢測到 53 端口已被佔用 (可能是 systemd-resolved)。"; read -p "是否嘗試停止 systemd-resolved? (y/N): " fix_port < /dev/tty; if [[ "$fix_port" =~ ^[yY]$ ]]; then systemctl stop systemd-resolved &>/dev/null; systemctl disable systemd-resolved &>/dev/null; rm -f /etc/resolv.conf && echo "nameserver 8.8.8.8" > /etc/resolv.conf; log INFO "已停止 systemd-resolved 並重置 resolv.conf。"; fi; fi; log INFO "正在拉取最新的 AdGuard Home 鏡像..."; if ! docker pull "${ADGUARD_IMAGE_NAME}"; then log ERROR "鏡像拉取失敗。"; press_any_key; break; fi; mkdir -p "${ADGUARD_CONFIG_DIR}" "${ADGUARD_WORK_DIR}"; log INFO "正在部署 AdGuard Home 容器..."; if docker run -d --name "${ADGUARD_CONTAINER_NAME}" --restart always -v "${ADGUARD_WORK_DIR}:/opt/adguardhome/work" -v "${ADGUARD_CONFIG_DIR}:/opt/adguardhome/conf" -p 3000:3000/tcp "${ADGUARD_IMAGE_NAME}"; then if connect_to_shared_network "${ADGUARD_CONTAINER_NAME}"; then log INFO "AdGuard Home 部署成功。"; log INFO "請立即訪問 http://<您的IP>:3000 進行初始化設置。"; log WARN "【重要】在設置嚮導中, '網頁管理界面' 端口請保留 3000, 且 'DNS 伺服器' 端口保留 53。"; else log ERROR "AdGuard Home 容器創建成功但網絡連接失敗，部署中止。"; fi; else log ERROR "AdGuard Home 部署失敗。"; docker rm -f "${ADGUARD_CONTAINER_NAME}" 2>/dev/null; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; else while true; do clear; log INFO "--- 管理 AdGuard Home (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 重啟 AdGuard Home"; echo " 3. 更新 AdGuard Home"; echo " 4. 卸載 AdGuard Home"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) docker logs -f "$ADGUARD_CONTAINER_NAME"; press_any_key;; 2) log INFO "正在重啟 AdGuard Home..."; docker restart "$ADGUARD_CONTAINER_NAME"; sleep 2;; 3) log INFO "正在更新 AdGuard Home..."; docker pull "${ADGUARD_IMAGE_NAME}"; docker stop "${ADGUARD_CONTAINER_NAME}" &>/dev/null && docker rm "${ADGUARD_CONTAINER_NAME}" &>/dev/null; if docker run -d --name "${ADGUARD_CONTAINER_NAME}" --restart always -v "${ADGUARD_WORK_DIR}:/opt/adguardhome/work" -v "${ADGUARD_CONFIG_DIR}:/opt/adguardhome/conf" -p 3000:3000/tcp "${ADGUARD_IMAGE_NAME}"; then if connect_to_shared_network "${ADGUARD_CONTAINER_NAME}"; then log INFO "更新成功。"; else log ERROR "更新失敗，容器已創建但網絡連接失敗。"; fi; else log ERROR "更新失敗。"; fi; press_any_key;; 4) read -p "確定要卸載 AdGuard Home 嗎? (y/N): " uninstall_choice < /dev/tty; if [[ "$uninstall_choice" =~ ^[yY]$ ]]; then docker stop "${ADGUARD_CONTAINER_NAME}" &>/dev/null && docker rm "${ADGUARD_CONTAINER_NAME}" &>/dev/null; rm -rf "${APP_BASE_DIR}/adguard"; docker rmi -f "${ADGUARD_IMAGE_NAME}" &>/dev/null; log INFO "AdGuard Home 已卸載。"; fi; press_any_key; break;; 0) break;; *) log ERROR "無效輸入!"; sleep 1;; esac; done; fi; }
clear_all_logs() { log INFO "正在清除所有已安裝服務容器的內部日誌..."; for container in "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME"; do if container_exists "$container"; then log INFO "正在清除 ${container} 的日誌..."; local log_path; log_path=$(docker inspect --format='{{.LogPath}}' "$container"); if [ -f "$log_path" ]; then truncate -s 0 "$log_path" || log WARN "無法清空 ${container} 的日誌檔案。"; fi; fi; done; log INFO "所有服務日誌已清空。"; }
wait_for_container_ready() { local container="$1" service_name="$2" max_wait="${3:-30}"; log INFO "等待 ${service_name} 就緒..."; for (( i=1; i<=max_wait; i++ )); do if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != "true" ]; then sleep 1; continue; fi; local ready=false; case "$container" in "$ADGUARD_CONTAINER_NAME") if docker exec "$container" sh -c "timeout 1 nslookup google.com 127.0.0.1 >/dev/null 2>&1" 2>/dev/null; then ready=true; fi;; "$CADDY_CONTAINER_NAME") if docker logs "$container" 2>&1 | grep -q "serving initial configuration"; then ready=true; fi;; "$SINGBOX_CONTAINER_NAME") ! docker logs "$container" 2>&1 | tail -n 20 | grep -qiE "error|fatal|fail|failed" && ready=true;; esac; if $ready; then echo ""; log INFO "✓ ${service_name} 已就緒"; return 0; fi; echo -ne "."; sleep 1; done; echo ""; return 1; }
restart_all_services() { log INFO "正在按依賴順序重啟所有正在運行的容器 (AdGuard -> Caddy -> Sing-box)..."; local restart_order=("$ADGUARD_CONTAINER_NAME:AdGuard (DNS)" "$CADDY_CONTAINER_NAME:Caddy (SSL)" "$SINGBOX_CONTAINER_NAME:Sing-box (核心服務)"); local restarted=0; for item in "${restart_order[@]}"; do local container="${item%%:*}" service_name="${item#*:}"; if container_exists "$container" && [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" = "true" ]; then log INFO "正在重啟 ${service_name}..."; if docker restart "$container" &>/dev/null; then restarted=$((restarted + 1)); if ! wait_for_container_ready "$container" "$service_name"; then log WARN "✗ ${service_name} 未能在 30 秒內就緒,但將繼續下一步"; fi; sleep 2; else log ERROR "✗ ${service_name} 重啟失敗"; fi; fi; done; if [ "$restarted" -eq 0 ]; then log WARN "沒有正在運行的容器可供重啟。"; else log INFO "所有服務已按順序重啟完成。"; fi; }
clear_logs_and_restart_all() { clear_all_logs; log INFO "3秒後將自動重啟所有服務..."; sleep 3; restart_all_services; }
uninstall_all_services() { log WARN "此操作將不可逆地刪除 Caddy, Sing-box, AdGuard Home 的所有相關數據！"; read -p "您確定要徹底清理所有服務嗎? (y/N): " choice < /dev/tty; if [[ ! "$choice" =~ ^[yY]$ ]]; then log INFO "操作已取消。"; return; fi; log INFO "正在停止並刪除所有服務容器..."; local containers_to_remove=("$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME"); local container_ids=""; for name in "${containers_to_remove[@]}"; do id=$(docker ps -a -q --filter "name=^/${name}$"); if [ -n "$id" ]; then container_ids+="$id "; fi; done; if [ -n "$container_ids" ]; then docker stop $container_ids &>/dev/null; docker rm $container_ids &>/dev/null; log INFO "所有現存的 HWC 容器已停止並刪除。"; else log INFO "未找到需要清理的 HWC 容器。"; fi; log INFO "正在刪除本地設定檔和數據..."; rm -rf "${APP_BASE_DIR}"; log INFO "正在刪除 Docker 數據卷..."; docker volume rm "${CADDY_DATA_VOLUME}" &>/dev/null || true; log INFO "正在刪除共享網路..."; docker network rm "${SHARED_NETWORK_NAME}" &>/dev/null || true; log INFO "正在清除所有鏡像緩存..."; docker rmi -f "${CADDY_IMAGE_NAME}" "${SINGBOX_IMAGE_NAME}" "${ADGUARD_IMAGE_NAME}" &>/dev/null || true; log INFO "所有服務已徹底清理完畢。"; }

# [FINAL-FIX v6.5.9] wait_for_container_ready
# 对 Sing-box 改用功能性测试，不再依赖日志
wait_for_container_ready() {
    local container="$1" service_name="$2" max_wait="${3:-30}"
    log INFO "等待 ${service_name} 就緒..."

    for (( i=1; i<=max_wait; i++ )); do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != "true" ]; then
            # 如果容器在启动后5秒内就退出了，直接判定失败
            if (( i > 5 )); then
                log WARN "✗ ${service_name} 容器未能保持运行状态。"
                return 1
            fi
            sleep 1; continue
        fi
        
        local ready=false
        case "$container" in
            "$ADGUARD_CONTAINER_NAME")
                if docker exec "$container" sh -c "timeout 2 nslookup google.com 127.0.0.1 >/dev/null 2>&1" 2>/dev/null; then ready=true; fi
                ;;
            "$CADDY_CONTAINER_NAME")
                if docker logs "$container" 2>&1 | grep -q "serving initial configuration"; then ready=true; fi
                ;;
            "$SINGBOX_CONTAINER_NAME")
                # 功能性测试：通过容器内部的SOCKS5代理访问外部，测试全链路
                # Sing-box 容器镜像是 alpine linux，默认不带 curl
                # 我们需要在需要时为其安装 curl，以便进行健康检查
                if ! docker exec "$container" command -v curl &>/dev/null; then
                    log INFO " - (首次检查) 正在为 ${service_name} 容器安装 'curl' 以进行健康检查..."
                    if ! docker exec "$container" apk add --no-cache curl >/dev/null 2>&1; then
                        log WARN "   - 在 ${service_name} 容器内安装 'curl' 失败，将回退到基础运行状态检查。"
                        # 如果安装 curl 失败 (例如网络问题)，我们至少可以确认容器在运行
                        sleep 1 # 等待一秒，假设它能自己恢复
                        continue
                    fi
                fi
                
                # 使用 curl 通过 socks5h 代理进行测试 (h 表示让代理去解析域名)
                if docker exec "$container" curl --silent --fail --show-error -x socks5h://127.0.0.1:8008 --connect-timeout 5 https://www.cloudflare.com/cdn-cgi/trace >/dev/null 2>&1; then
                    ready=true
                fi
                ;;
        esac

        if $ready; then
            echo ""; log INFO "✓ ${service_name} 已就绪"
            return 0
        fi
        echo -ne "."
        sleep 1
    done

    echo ""
    log WARN "✗ ${service_name} 在 ${max_wait} 秒內未能达到就绪状态。"
    if [ "$container" = "$SINGBOX_CONTAINER_NAME" ]; then
        log WARN "   这可能是由于 WARP 连接不稳定。请尝试手动重启 Sing-box，或将日志级别设为 'info' 以便调试。"
        log WARN "   手动重启命令: hwc -> 选项 2 -> 选项 3"
        log WARN "   查看日志命令: docker logs ${SINGBOX_CONTAINER_NAME}"
    fi
    return 1
}

cleanup_and_recreate_network() {
    log WARN "此操作將停止所有 HWC 相關容器，清空其日誌，刪除並重建共享網路 (${SHARED_NETWORK_NAME})，然後重新啟動容器。"
    read -p "您確定要執行 '一鍵淨化共享網絡' 嗎? (y/N): " choice < /dev/tty
    if [[ ! "$choice" =~ ^[yY]$ ]]; then log INFO "操作已取消。"; return; fi

    if ! command -v jq &>/dev/null; then
        log INFO "正在安裝 JSON 處理工具 jq...";
        if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y jq;
        elif command -v yum &>/dev/null; then yum install -y jq;
        elif command -v dnf &>/dev/null; then dnf install -y jq;
        else log ERROR "無法自動安裝 jq, 請手動安裝後重試。"; return 1; fi
    fi

    local containers_to_process=("$ADGUARD_CONTAINER_NAME" "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME")
    local found_containers=()

    log INFO "1/6 正在清空並停止所有 HWC 相關容器..."
    for container in "${containers_to_process[@]}"; do
        if container_exists "$container"; then
            # 新增：清空日志
            log INFO " - 清空容器日志: $container"
            local log_path; log_path=$(docker inspect --format='{{.LogPath}}' "$container")
            if [ -f "$log_path" ]; then
                truncate -s 0 "$log_path" || log WARN "   - 无法清空 ${container} 的日志文件。"
            fi
            
            # 停止容器
            log INFO " - 停止容器: $container"; docker stop "$container" &>/dev/null || log WARN "無法停止 $container"; found_containers+=("$container")
        fi
    done

    if [ ${#found_containers[@]} -eq 0 ]; then log WARN "未找到任何已安裝的 HWC 相關容器。"; return; fi
    log INFO "2/6 等待 3 秒確保連接完全釋放..."; sleep 3
    log INFO "3/6 刪除並重建共享網路 (${SHARED_NETWORK_NAME})..."
    for container in "${found_containers[@]}"; do
        docker network disconnect -f "${SHARED_NETWORK_NAME}" "${container}" &>/dev/null || true
    done
    docker network rm "${SHARED_NETWORK_NAME}" &>/dev/null || true
    if docker network create "${SHARED_NETWORK_NAME}" &>/dev/null; then log INFO " - 新網路 ${SHARED_NETWORK_NAME} 已重建成功。"; else log ERROR " - 網路重建失敗，操作中止！"; return 1; fi
    
    local restart_order=("$ADGUARD_CONTAINER_NAME" "$CADDY_CONTAINER_NAME")
    log INFO "4/6 正在按順序啟動基礎服務 (AdGuard, Caddy)..."
    for container in "${restart_order[@]}"; do
        if [[ " ${found_containers[*]} " =~ " ${container} " ]]; then
            log INFO " - 連接並啟動 ${container}..."; docker network connect "${SHARED_NETWORK_NAME}" "${container}" &>/dev/null
            if docker start "${container}" &>/dev/null; then
                wait_for_container_ready "$container" "$container" 20 || true
            else log ERROR " - ${container} 啟動失敗。"; fi
        fi
    done

    if [[ " ${found_containers[*]} " =~ " ${SINGBOX_CONTAINER_NAME} " ]]; then
        log INFO "5/6 正在動態更新 Sing-box 配置並啟動核心服務..."
        if container_exists "$ADGUARD_CONTAINER_NAME" && [ "$(docker inspect -f '{{.State.Running}}' "$ADGUARD_CONTAINER_NAME")" = "true" ]; then
            local NEW_AG_IP; NEW_AG_IP=$(docker inspect -f "{{ index .NetworkSettings.Networks \"${SHARED_NETWORK_NAME}\" \"IPAddress\" }}" "$ADGUARD_CONTAINER_NAME" 2>/dev/null)
            if [ -n "$NEW_AG_IP" ]; then
                log INFO " - 檢測到 AdGuard Home 新 IP: ${NEW_AG_IP}。正在更新 Sing-box 配置文件..."
                if ! jq empty "${SINGBOX_CONFIG_FILE}" >/dev/null 2>&1; then log ERROR " - Sing-box 配置文件不是有效的 JSON 文件！操作中止。"; else
                    if jq -e 'any(.dns.servers[]; .tag == "adguard")' "${SINGBOX_CONFIG_FILE}" >/dev/null; then
                        jq --arg new_ip "$NEW_AG_IP" '(.dns.servers[] | select(.tag == "adguard")).server = $new_ip' "${SINGBOX_CONFIG_FILE}" > "${SINGBOX_CONFIG_FILE}.tmp" && mv "${SINGBOX_CONFIG_FILE}.tmp" "${SINGBOX_CONFIG_FILE}"
                    else
                        local adguard_server_obj; adguard_server_obj=$(jq -n --arg ip "$NEW_AG_IP" '{type: "udp", server: $ip, server_port: 53, tag: "adguard"}')
                        jq --argjson obj "$adguard_server_obj" '.dns.servers = [$obj] + .dns.servers' "${SINGBOX_CONFIG_FILE}" > "${SINGBOX_CONFIG_FILE}.tmp" && mv "${SINGBOX_CONFIG_FILE}.tmp" "${SINGBOX_CONFIG_FILE}"
                    fi
                    if [ $? -eq 0 ]; then log INFO " - 配置文件更新成功。"; else log ERROR " - 配置文件更新失敗！"; fi
                fi
            fi
        fi
        
        log INFO "6/6 核心服務啟動..."
        log INFO " - 等待 5 秒，確保依賴服務稳定..."; sleep 5
        log INFO " - 連接並啟動 ${SINGBOX_CONTAINER_NAME}..."
        docker network connect "${SHARED_NETWORK_NAME}" "${SINGBOX_CONTAINER_NAME}" &>/dev/null
        if docker start "${SINGBOX_CONTAINER_NAME}" &>/dev/null; then
             if ! wait_for_container_ready "${SINGBOX_CONTAINER_NAME}" "Sing-box" 45; then
                log WARN "Sing-box 自動重啟後未能立即就緒，脚本将继续执行。"
             fi
        else
            log ERROR " - ${SINGBOX_CONTAINER_NAME} 啟動失敗。请检查日志: docker logs sing-box"
        fi
    fi
    
    log INFO "✅ 共享網絡淨化與所有服務重啟完成。"
}

check_all_status() { local containers=("$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" "$ADGUARD_CONTAINER_NAME"); for container in "${containers[@]}"; do if ! container_exists "$container"; then CONTAINER_STATUSES["$container"]="${FontColor_Red}未安裝${FontColor_Suffix}"; else local status; status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null); if [ "$status" = "running" ]; then CONTAINER_STATUSES["$container"]="${FontColor_Green}運行中${FontColor_Suffix}"; else CONTAINER_STATUSES["$container"]="${FontColor_Red}異常 (${status})${FontColor_Suffix}"; fi; fi; done; }
start_menu() { while true; do check_all_status; clear; echo -e "\n${FontColor_Purple}Caddy + Sing-box + AdGuard 終極管理腳本${FontColor_Suffix} (v${SCRIPT_VERSION:-6.5.8})"; echo -e "  快捷命令: ${FontColor_Yellow}hwc${FontColor_Suffix}  |  設定目錄: ${FontColor_Yellow}${APP_BASE_DIR}${FontColor_Suffix}"; echo -e " --------------------------------------------------"; echo -e "  Caddy 服務        : ${CONTAINER_STATUSES[$CADDY_CONTAINER_NAME]}"; echo -e "  Sing-box 服務     : ${CONTAINER_STATUSES[$SINGBOX_CONTAINER_NAME]}"; echo -e "  AdGuard Home 服務 : ${CONTAINER_STATUSES[$ADGUARD_CONTAINER_NAME]}"; echo -e " --------------------------------------------------\n"; echo -e " ${FontColor_Green}1.${FontColor_Suffix} 管理 Caddy..."; echo -e " ${FontColor_Green}2.${FontColor_Suffix} 管理 Sing-box (整合核心服務)..."; echo -e " ${FontColor_Green}3.${FontColor_Suffix} 管理 AdGuard Home...\n"; echo -e " ${FontColor_Yellow}4.${FontColor_Suffix} 清理日誌並重啟所有服務"; echo -e " ${FontColor_Yellow}6.${FontColor_Suffix} 一鍵淨化共享網絡 (修復網路問題)"; echo -e " ${FontColor_Red}5.${FontColor_Suffix} 徹底清理所有服務\n"; echo -e " ${FontColor_Yellow}0.${FontColor_Suffix} 退出腳本\n"; read -p " 請輸入選項 [0-6]: " num < /dev/tty; case "$num" in 1) manage_caddy;; 2) manage_singbox;; 3) manage_adguard;; 4) clear_logs_and_restart_all; press_any_key;; 5) uninstall_all_services; press_any_key;; 6) cleanup_and_recreate_network; press_any_key;; 0) exit 0;; *) log ERROR "無效輸入!"; sleep 2;; esac; done; }


# --- 第3節:腳本入口 (主邏輯) ---
SCRIPT_VERSION="6.5.8"
clear
cat <<-'EOM'
  ____      _        __          __      _   _             _             _
 / ___|__ _| |_ __ _ \ \        / /     | | | |           | |           (_)
| |   / _` | __/ _` | \ \  /\  / /  __ _| |_| |_ ___ _ __ | |_ __ _ _ __ _  ___
| |__| (_| | || (_| |  \ \/  \/ /  / _` | __| __/ _ \ '_ \| __/ _` | |  | |/ __|
 \____\__,_|\__\__,_|   \  /\  /  | (_| | |_| ||  __/ | | | || (_| | |  | | (__
                        \/  \/    \__,_|\__|\__\___|_| |_|\__\__,_|_|  |_|\___|
EOM
echo -e "${FontColor_Purple}Caddy + Sing-box + AdGuard 終極一鍵管理腳本${FontColor_Suffix} (v${SCRIPT_VERSION})"
echo "----------------------------------------------------------------"

check_root
self_install "$@"
check_docker
mkdir -p "${APP_BASE_DIR}"
start_menu
