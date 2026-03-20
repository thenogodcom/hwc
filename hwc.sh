#!/usr/bin/env bash
#
# Description: Ultimate All-in-One Manager for Caddy & Sing-box with self-installing shortcut.
# Author: Your Name (Refactored for Sing-box v1.12+)
# Version: 6.7.5 (Removed AdGuard Home & Apply v1.12+ Fix)

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
SINGBOX_CONTAINER_NAME="sing-box"; SINGBOX_IMAGE_NAME="ghcr.io/sagernet/sing-box:v1.11.15"; SINGBOX_CONFIG_DIR="${APP_BASE_DIR}/singbox"; SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_DIR}/config.json"

SHARED_NETWORK_NAME="hwc-proxy-net"
SHARED_NETWORK_SUBNET="172.18.0.0/16"
CADDY_STATIC_IP="172.18.0.12"
SINGBOX_STATIC_IP="172.18.0.13"

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
install_docker() { log INFO "偵測到 Docker 未安裝,正在使用官方通用腳本進行安裝..."; if ! curl -fsSL https://get.docker.com | sh; then log ERROR "Docker 安裝失敗。"; exit 1; fi; log INFO "正在啟動並設定 Docker 開機自啟..."; systemctl start docker; systemctl enable docker; log INFO "Docker 安裝成功並已啟動。"; }
check_root() { if [ "$EUID" -ne 0 ]; then log ERROR "此腳本必須以 root 身份運行。"; exit 1; fi; }
check_docker() { if ! command -v docker &>/dev/null; then install_docker; fi; if ! docker info > /dev/null 2>&1; then log WARN "Docker 服務未運行,正在嘗試啟動..."; systemctl start docker; sleep 3; fi; }
check_editor() { for editor in nano vi vim; do if command -v $editor &>/dev/null; then EDITOR=$editor; return 0; fi; done; log ERROR "未找到合適的文字編輯器。"; return 1; }
container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }

create_shared_network() {
    if ! docker network inspect "${SHARED_NETWORK_NAME}" &>/dev/null; then
        log INFO "共享網絡 ${SHARED_NETWORK_NAME} 不存在，正在創建..."
        docker network create --subnet="${SHARED_NETWORK_SUBNET}" "${SHARED_NETWORK_NAME}"
    fi
    return 0
}

generate_caddy_config() {
    local primary_domain="$1" email="$2" log_mode="$3" proxy_domain="$4"
    mkdir -p "${CADDY_CONFIG_DIR}"
    local global_log_block=""
    if [[ ! "$log_mode" =~ ^[yY]$ ]]; then
        global_log_block=$(cat <<-'GLOBALLOG'
        log {
                output stderr
                level ERROR
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
EOF
    if [ -n "$primary_domain" ]; then
        cat >> "${CADDY_CONFIG_FILE}" <<EOF
${primary_domain} {
    reverse_proxy app:80 {
        header_up Host {host}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
EOF
    fi
    cat >> "${CADDY_CONFIG_FILE}" <<EOF
${proxy_domain} {
    header -Via
    header -Server
    header Server "nginx"
    reverse_proxy app:80 {
        header_up Host ${primary_domain:-${proxy_domain}}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
}
EOF
    log INFO "已為域名 ${proxy_domain} 建立 Caddyfile。"
}

generate_warp_conf() {
    log INFO "正在註冊新的 WARP 帳戶..."; local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) return 1;; esac
    local CMD="apk add --no-cache curl ca-certificates jq && WGCF_URL=\$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r '.assets[] | select(.name | contains(\"linux_$arch\")) | .browser_download_url') && curl -fL -o wgcf \"\$WGCF_URL\" && chmod +x wgcf && ./wgcf register --accept-tos && ./wgcf generate"
    docker run --rm -v "${SINGBOX_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$CMD" > /dev/null 2>&1
}

generate_singbox_config() {
    local domain="$1" password="$2" private_key="$3" ipv4_address="$4" ipv6_address="$5" public_key="$6" log_level="${7:-error}"; mkdir -p "${SINGBOX_CONFIG_DIR}"
    local cert_path_info; cert_path_info=$(detect_cert_path "$domain"); local cert_path="${cert_path_info%%|*}"; local key_path="${cert_path_info##*|}"
    local cert_path_in_container="${cert_path/\/data/\/caddy_certs}"; local key_path_in_container="${key_path/\/data/\/caddy_certs}"

    # [修復] Sing-box v1.12+ 兼容結構: endpoints + default_domain_resolver
    cat > "${SINGBOX_CONFIG_FILE}" <<EOF
{
  "log": { "disabled": false, "level": "${log_level}", "timestamp": true },
  "dns": {
    "servers": [
      { "tag": "dns-remote", "type": "https", "server": "1.1.1.1" },
      { "tag": "dns-local", "type": "local" }
    ],
    "strategy": "prefer_ipv4"
  },
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "warp-out",
      "system": false,
      "mtu": 1280,
      "address": [ "${ipv4_address}/32", "${ipv6_address}/128" ],
      "private_key": "${private_key}",
      "listen_port": 0,
      "peers": [
        {
          "address": "162.159.192.1",
          "port": 2408,
          "public_key": "${public_key}",
          "allowed_ips": [ "0.0.0.0/0", "::/0" ],
          "persistent_keepalive_interval": 15,
          "reserved": [0, 0, 0]
        }
      ]
    }
  ],
  "inbounds": [
    { "type": "hysteria2", "tag": "hysteria-in", "listen": "::", "listen_port": 443, "users": [ { "password": "${password}" } ], "tls": { "enabled": true, "server_name": "${domain}", "certificate_path": "${cert_path_in_container}", "key_path": "${key_path_in_container}" } },
    { "type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 8008 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rules": [
      { "protocol": "dns", "outbound": "direct" },
      { "ip_is_private": true, "outbound": "direct" },
      { "domain_suffix": [ "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "github.com", "github.io", "githubassets.com", "githubusercontent.com" ], "outbound": "direct" }
    ],
    "final": "warp-out",
    "default_domain_resolver": "dns-remote",
    "auto_detect_interface": true
  }
}
EOF
    log INFO "Sing-box v1.12+ 兼容設定檔生成完畢。"
}

manage_caddy() { if ! container_exists "$CADDY_CONTAINER_NAME"; then while true; do clear; log INFO "--- 管理 Caddy (未安裝) ---"; echo " 1. 安裝 Caddy (用於自動申請SSL證書)"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) log INFO "--- 正在安裝 Caddy ---"; read -p "請輸入主域名 (可選, 用於網站偽裝, 直接回車跳過): " PRIMARY_DOMAIN < /dev/tty; while true; do read -p "請輸入代理域名 (必選, 用於 Sing-box): " PROXY_DOMAIN < /dev/tty; if [ -n "$PROXY_DOMAIN" ] && validate_domain "$PROXY_DOMAIN"; then break; fi; done; while true; do read -p "請輸入您的郵箱: " EMAIL < /dev/tty; if [ -n "$EMAIL" ] && validate_email "$EMAIL"; then break; fi; done; read -p "是否為 Caddy 啟用詳細日誌？(y/N): " LOG_MODE < /dev/tty; generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "$LOG_MODE" "$PROXY_DOMAIN"; log INFO "正在部署 Caddy 鏡像..."; create_shared_network; docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" --ip "${CADDY_STATIC_IP}" -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "${CADDY_IMAGE_NAME}"; press_any_key; break;; 0) break;; esac; done; else while true; do clear; log INFO "--- 管理 Caddy (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯 Caddyfile"; echo " 3. 重啟 Caddy"; echo " 4. 卸載 Caddy"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) docker logs -f "$CADDY_CONTAINER_NAME"; press_any_key;; 2) if check_editor; then "$EDITOR" "${CADDY_CONFIG_FILE}"; log INFO "設定已儲存,請手動重啟以應用。"; fi; press_any_key;; 3) log INFO "正在重啟 Caddy..."; docker restart "$CADDY_CONTAINER_NAME"; sleep 2;; 4) read -p "確定要卸載 Caddy 嗎? (y/N): " uninstall_choice < /dev/tty; if [[ "$uninstall_choice" =~ ^[yY]$ ]]; then docker stop "${CADDY_CONTAINER_NAME}" &>/dev/null && docker rm "${CADDY_CONTAINER_NAME}" &>/dev/null; log INFO "Caddy 已卸載。"; fi; press_any_key; break;; 0) break;; esac; done; fi; }

update_warp_keys() {
    if [ ! -f "$SINGBOX_CONFIG_FILE" ]; then log ERROR "設定檔不存在。"; return 1; fi
    log INFO "請輸入新的靜態 WARP 金鑰信息。"; local private_key warp_address ipv4_address ipv6_address;
    read -p "請輸入 WARP PrivateKey: " private_key < /dev/tty;
    read -p "請輸入 WARP Address (帶逗號): " warp_address < /dev/tty;
    ipv4_address=$(echo "$warp_address" | cut -d, -f1 | cut -d/ -f1 | xargs);
    ipv6_address=$(echo "$warp_address" | cut -d, -f2 | cut -d/ -f1 | xargs);
    if ! command -v jq &>/dev/null; then apt-get update && apt-get install -y jq; fi
    jq --arg pk "$private_key" --arg ip4 "${ipv4_address}/32" --arg ip6 "${ipv6_address}/128" '.endpoints |= map(if .tag == "warp-out" then .private_key = $pk | .address = [$ip4, $ip6] else . end)' "$SINGBOX_CONFIG_FILE" > "${SINGBOX_CONFIG_FILE}.tmp" && mv "${SINGBOX_CONFIG_FILE}.tmp" "$SINGBOX_CONFIG_FILE"
    log INFO "WARP 金鑰已成功更新，請重啟 Sing-box。";
}

manage_singbox() { if ! container_exists "$SINGBOX_CONTAINER_NAME"; then while true; do clear; log INFO "--- 管理 Sing-box (未安裝) ---"; echo " 1. 安裝 Sing-box (整合 Hysteria2 + WARP)"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) if ! container_exists "$CADDY_CONTAINER_NAME"; then log ERROR "請先安裝 Caddy。"; press_any_key; break; fi; log INFO "--- 正在安裝 Sing-box ---"; local available_domains; available_domains=$(awk 'NR>1 && NF>=2 && $2=="{" {print $1}' "${CADDY_CONFIG_FILE}" 2>/dev/null | tr '\n' ' '); local HY_DOMAIN=""; read -p "請選擇 Sing-box 使用的域名 [${available_domains%% *}]: " HY_DOMAIN < /dev/tty; HY_DOMAIN=${HY_DOMAIN:-${available_domains%% *}}; PASSWORD=$(generate_random_password); log INFO "已自動生成密碼: ${FontColor_Yellow}${PASSWORD}${FontColor_Suffix}"; generate_warp_conf; local private_key=$(grep -oP 'PrivateKey = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"); local warp_addresses=$(grep -oP 'Address = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf"); ipv4_address=$(echo "$warp_addresses" | cut -d, -f1 | cut -d/ -f1 | xargs); ipv6_address=$(echo "$warp_addresses" | cut -d, -f2 | cut -d/ -f1 | xargs); public_key="bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="; generate_singbox_config "$HY_DOMAIN" "$PASSWORD" "$private_key" "$ipv4_address" "$ipv6_address" "$public_key" "error"; create_shared_network; docker run -d --name "${SINGBOX_CONTAINER_NAME}" --restart always --cap-add NET_ADMIN --network "${SHARED_NETWORK_NAME}" --ip "${SINGBOX_STATIC_IP}" -p 443:443/udp -p 8008:8008/tcp -v "${SINGBOX_CONFIG_FILE}:/etc/sing-box/config.json:ro" -v "${CADDY_DATA_VOLUME}:/caddy_certs:ro" "${SINGBOX_IMAGE_NAME}" run -c /etc/sing-box/config.json; press_any_key; break;; 0) break;; esac; done; else while true; do clear; log INFO "--- 管理 Sing-box (已安裝) ---"; echo " 1. 查看日誌"; echo " 2. 編輯設定檔"; echo " 3. 重啟 Sing-box"; echo " 4. 手動更換 WARP 金鑰"; echo " 5. 卸載 Sing-box"; echo " 0. 返回主選單"; read -p "請輸入選項: " choice < /dev/tty; case "$choice" in 1) docker logs -f "$SINGBOX_CONTAINER_NAME"; press_any_key;; 2) if check_editor; then "$EDITOR" "${SINGBOX_CONFIG_FILE}"; fi; press_any_key;; 3) docker restart "$SINGBOX_CONTAINER_NAME"; press_any_key;; 4) update_warp_keys; press_any_key;; 5) read -p "確定卸載? (y/N): " c; if [[ "$c" =~ ^[yY]$ ]]; then docker stop "${SINGBOX_CONTAINER_NAME}" && docker rm "${SINGBOX_CONTAINER_NAME}"; fi; press_any_key; break;; 0) break;; esac; done; fi; }

clear_all_logs() { log INFO "正在清空所有日誌..."; for container in "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME"; do if container_exists "$container"; then local log_path=$(docker inspect --format='{{.LogPath}}' "$container"); if [ -f "$log_path" ]; then truncate -s 0 "$log_path"; fi; fi; done; }

wait_for_container_ready() {
    local container="$1" service_name="$2" max_wait=20
    log INFO "等待 ${service_name} 啟動..."
    local i=0
    while [ $i -lt $max_wait ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" == "true" ]; then
            echo -e " ✓ ${service_name} 已就緒。"; return 0
        fi
        echo -ne "."; sleep 1; i=$((i+1))
    done
    return 0
}

restart_all_services() {
    log INFO "按順序重啟: Caddy -> Sing-box...";
    local order=("$CADDY_CONTAINER_NAME:Caddy" "$SINGBOX_CONTAINER_NAME:Sing-box")
    for item in "${order[@]}"; do
        local container="${item%%:*}" service_name="${item#*:}"
        if container_exists "$container"; then
            docker restart "$container"
            wait_for_container_ready "$container" "$service_name"
            if [ "$container" == "$CADDY_CONTAINER_NAME" ]; then sleep 15; fi
        fi
    done
}

uninstall_all_services() {
    log WARN "此操作將刪除所有 Caddy 與 Sing-box 數據！"; read -p "確定? (y/N): " choice < /dev/tty;
    if [[ ! "$choice" =~ ^[yY]$ ]]; then return; fi
    docker stop "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" 2>/dev/null || true
    rm -rf "${APP_BASE_DIR}"
    docker volume rm "${CADDY_DATA_VOLUME}" 2>/dev/null || true
    docker network rm "${SHARED_NETWORK_NAME}" 2>/dev/null || true
    log INFO "所有服務已徹底清理。";
}

check_all_status() { 
    local containers=("$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME")
    for container in "${containers[@]}"; do
        if ! container_exists "$container"; then CONTAINER_STATUSES["$container"]="${FontColor_Red}未安裝${FontColor_Suffix}";
        else local s=$(docker inspect --format '{{.State.Status}}' "$container");
        if [ "$s" == "running" ]; then CONTAINER_STATUSES["$container"]="${FontColor_Green}運行中${FontColor_Suffix}";
        else CONTAINER_STATUSES["$container"]="${FontColor_Red}異常 ($s)${FontColor_Suffix}"; fi; fi; done; 
}

start_menu() {
    while true; do
        check_all_status; clear
        echo -e "\n${FontColor_Purple}Caddy + Sing-box 終極管理腳本${FontColor_Suffix} (v6.7.5)"
        echo -e "  快捷命令: ${FontColor_Yellow}hwc${FontColor_Suffix}  |  設定目錄: ${FontColor_Yellow}${APP_BASE_DIR}${FontColor_Suffix}"
        echo -e " --------------------------------------------------"
        echo -e "  Caddy 服務        : ${CONTAINER_STATUSES[$CADDY_CONTAINER_NAME]}"
        echo -e "  Sing-box 服務     : ${CONTAINER_STATUSES[$SINGBOX_CONTAINER_NAME]}"
        echo -e " --------------------------------------------------\n"
        echo -e " ${FontColor_Green}1.${FontColor_Suffix} 管理 Caddy..."
        echo -e " ${FontColor_Green}2.${FontColor_Suffix} 管理 Sing-box (整合核心服務)...\n"
        echo -e " ${FontColor_Yellow}3.${FontColor_Suffix} 清理日誌並重啟所有服務"
        echo -e " ${FontColor_Red}4.${FontColor_Suffix} 徹底清理所有服務\n"
        echo -e " ${FontColor_Yellow}0.${FontColor_Suffix} 退出腳本\n"
        read -p " 請輸入選項 [0-4]: " num < /dev/tty
        case "$num" in
            1) manage_caddy ;;
            2) manage_singbox ;;
            3) clear_all_logs; restart_all_services; press_any_key ;;
            4) uninstall_all_services; press_any_key ;;
            0) exit 0 ;;
            *) log ERROR "無效輸入!"; sleep 2;;
        esac
    done
}

# --- 第3節:腳本入口 ---
SCRIPT_VERSION="6.7.5"
clear
cat <<-'EOM'
  ____      _        __          __      _   _             _             _
 / ___|__ _| |_ __ _ \ \        / /     | | | |           | |           (_)
| |   / _` | __/ _` | \ \  /\  / /  __ _| |_| |_ ___ _ __ | |_ __ _ _ __ _  ___
| |__| (_| | || (_| |  \ \/  \/ /  / _` | __| __/ _ \ '_ \| __/ _` | |  | |/ __|
 \____\__,_|\__\__,_|   \  /\  /  | (_| | |_| ||  __/ | | | || (_| | |  | | (__
                        \/  \/    \__,_|\__|\__\___|_| |_|\__\__,_|_|  |_|\___|
EOM
check_root
self_install "$@"
check_docker
mkdir -p "${APP_BASE_DIR}"
start_menu
