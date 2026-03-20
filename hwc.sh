#!/usr/bin/env bash
#
# Description: Ultimate Manager for Caddy & Sing-box (AdGuard Removed)
# Version: 6.8.0 (Removed AdGuard Home)

# --- 第1節:全域設定與定義 ---
set -eo pipefail

# 顏色定義
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
SINGBOX_CONTAINER_NAME="sing-box"; SINGBOX_IMAGE_NAME="ghcr.io/sagernet/sing-box:latest"; SINGBOX_CONFIG_DIR="${APP_BASE_DIR}/singbox"; SINGBOX_CONFIG_FILE="${SINGBOX_CONFIG_DIR}/config.json"

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
    log INFO "首次運行設定:正在安裝 'hwc' 快捷命令..."
    if ! command -v curl &>/dev/null; then
        log WARN "'curl' 未安裝,正在嘗試安裝..."
        if command -v apt-get &>/dev/null; then apt-get update && apt-get install -y --no-install-recommends curl; fi
    fi
    if curl -sSL "${SCRIPT_URL}" -o "${SHORTCUT_PATH}"; then
        chmod +x "${SHORTCUT_PATH}"
        log INFO "快捷命令 'hwc' 安裝成功。正在重新啟動..."
        exec "${SHORTCUT_PATH}" $args_string
    else
        log ERROR "無法安裝 'hwc' 快捷命令。"
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

install_docker() { log INFO "偵測到 Docker 未安裝,正在安裝..."; if ! curl -fsSL https://get.docker.com | sh; then log ERROR "Docker 安裝失敗。"; exit 1; fi; systemctl start docker; systemctl enable docker; }
check_root() { if [ "$EUID" -ne 0 ]; then log ERROR "此腳本必須以 root 身份運行。"; exit 1; fi; }
check_docker() { if ! command -v docker &>/dev/null; then install_docker; fi; }
check_editor() { for editor in nano vi vim; do if command -v $editor &>/dev/null; then EDITOR=$editor; return 0; fi; done; return 1; }
container_exists() { docker ps -a --format '{{.Names}}' | grep -q "^${1}$"; }
press_any_key() { echo ""; read -p "按 Enter 鍵返回..." < /dev/tty; }

create_shared_network() {
    if ! docker network inspect "${SHARED_NETWORK_NAME}" &>/dev/null; then
        log INFO "正在創建共享網絡 ${SHARED_NETWORK_NAME}..."
        docker network create --subnet="${SHARED_NETWORK_SUBNET}" "${SHARED_NETWORK_NAME}"
    fi
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
}

generate_warp_conf() {
    log INFO "正在註冊新的 WARP 帳戶..."; local arch; case $(uname -m) in x86_64) arch="amd64";; aarch64) arch="arm64";; *) return 1;; esac
    local CMD_TEMPLATE='apk add --no-cache curl ca-certificates jq && WGCF_URL=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | jq -r ".assets[] | select(.name | contains(\"linux_%s\")) | .browser_download_url") && curl -fL -o wgcf "$WGCF_URL" && chmod +x wgcf && ./wgcf'
    local WGCF_CMD; printf -v WGCF_CMD "$CMD_TEMPLATE" "$arch"
    docker run --rm -v "${SINGBOX_CONFIG_DIR}:/data" -w /data alpine:latest sh -c "$WGCF_CMD register --accept-tos && ./wgcf generate" > /dev/null 2>&1
}

generate_singbox_config() {
    local domain="$1" password="$2" private_key="$3" ipv4_address="$4" ipv6_address="$5" public_key="$6" log_level="${7:-error}"
    mkdir -p "${SINGBOX_CONFIG_DIR}"
    local cert_path_info; cert_path_info=$(detect_cert_path "$domain")
    local cert_path="${cert_path_info%%|*}"
    local key_path="${cert_path_info##*|}"
    local cert_path_in_container="${cert_path/\/data/\/caddy_certs}"
    local key_path_in_container="${key_path/\/data/\/caddy_certs}"

    # DNS 設定：固定使用 Cloudflare (因為移除了 AdGuard)
    local dns_servers_block=$(cat <<DNS
      { "type": "https", "server": "1.1.1.1", "tag": "cloudflare", "detour": "direct" },
DNS
)
    cat > "${SINGBOX_CONFIG_FILE}" <<EOF
{
  "log": { "disabled": false, "level": "${log_level}", "timestamp": true },
  "dns": { "servers": [ ${dns_servers_block} { "type": "local", "tag": "local-dns" } ], "strategy": "prefer_ipv4" },
  "endpoints": [ { "type": "wireguard", "tag": "warp-out", "system": false, "mtu": 1280, "address": [ "${ipv4_address}/32", "${ipv6_address}/128" ], "private_key": "${private_key}", "listen_port": 0, "peers": [ { "address": "162.159.192.1", "port": 2408, "public_key": "${public_key}", "allowed_ips": [ "0.0.0.0/0", "::/0" ], "persistent_keepalive_interval": 15, "reserved": [0, 0, 0] } ] } ],
  "inbounds": [ { "type": "hysteria2", "tag": "hysteria-in", "listen": "::", "listen_port": 443, "users": [ { "password": "${password}" } ], "tls": { "enabled": true, "server_name": "${domain}", "certificate_path": "${cert_path_in_container}", "key_path": "${key_path_in_container}" } }, { "type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": 8008 } ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": { "rules": [ { "protocol": "dns", "outbound": "direct" }, { "ip_is_private": true, "outbound": "direct" }, { "domain_suffix": [ "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "github.com", "github.io", "githubassets.com", "githubusercontent.com" ], "outbound": "direct" } ], "final": "warp-out", "default_domain_resolver": "cloudflare", "auto_detect_interface": true }
}
EOF
}

manage_caddy() {
    if ! container_exists "$CADDY_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Caddy (未安裝) ---"
            echo " 1. 安裝 Caddy"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    read -p "主域名 (可選): " PRIMARY_DOMAIN < /dev/tty
                    read -p "代理域名 (必選): " PROXY_DOMAIN < /dev/tty
                    read -p "郵箱: " EMAIL < /dev/tty
                    read -p "啟用詳細日誌？(y/N): " LOG_MODE < /dev/tty
                    generate_caddy_config "$PRIMARY_DOMAIN" "$EMAIL" "$LOG_MODE" "$PROXY_DOMAIN"
                    create_shared_network
                    docker pull "${CADDY_IMAGE_NAME}"
                    docker run -d --name "${CADDY_CONTAINER_NAME}" --restart always --network "${SHARED_NETWORK_NAME}" --ip "${CADDY_STATIC_IP}" -p 80:80/tcp -p 443:443/tcp -v "${CADDY_CONFIG_FILE}:/etc/caddy/Caddyfile:ro" -v "${CADDY_DATA_VOLUME}:/data" "${CADDY_IMAGE_NAME}"
                    press_any_key; break ;;
                0) break ;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Caddy (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 編輯 Caddyfile"; echo " 3. 重啟 Caddy"; echo " 4. 卸載 Caddy"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$CADDY_CONTAINER_NAME"; press_any_key ;;
                2) if check_editor; then "$EDITOR" "${CADDY_CONFIG_FILE}"; fi; press_any_key ;;
                3) docker restart "$CADDY_CONTAINER_NAME"; press_any_key ;;
                4) docker stop "${CADDY_CONTAINER_NAME}" && docker rm "${CADDY_CONTAINER_NAME}"; log INFO "Caddy 已卸載。"; press_any_key; break ;;
                0) break ;;
            esac
        done
    fi
}

manage_singbox() {
    if ! container_exists "$SINGBOX_CONTAINER_NAME"; then
        while true; do
            clear; log INFO "--- 管理 Sing-box (未安裝) ---"
            echo " 1. 安裝 Sing-box"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1)
                    if ! container_exists "$CADDY_CONTAINER_NAME"; then log ERROR "請先安裝 Caddy。"; press_any_key; break; fi
                    read -p "請輸入 Sing-box 使用的域名: " HY_DOMAIN < /dev/tty
                    PASSWORD=$(generate_random_password)
                    log INFO "生成的密碼: ${PASSWORD}"
                    generate_warp_conf
                    private_key=$(grep -oP 'PrivateKey = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf")
                    public_key=$(grep -oP 'PublicKey = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf")
                    warp_addresses=$(grep -oP 'Address = \K.*' "${SINGBOX_CONFIG_DIR}/wgcf-profile.conf")
                    ipv4_address=$(echo "$warp_addresses" | awk -F, '{print $1}' | awk -F/ '{print $1}' | xargs)
                    ipv6_address=$(echo "$warp_addresses" | awk -F, '{print $2}' | awk -F/ '{print $1}' | xargs)
                    generate_singbox_config "$HY_DOMAIN" "$PASSWORD" "$private_key" "$ipv4_address" "$ipv6_address" "$public_key"
                    create_shared_network
                    docker pull "${SINGBOX_IMAGE_NAME}"
                    docker run -d --name "${SINGBOX_CONTAINER_NAME}" --restart always --cap-add NET_ADMIN --network "${SHARED_NETWORK_NAME}" --ip "${SINGBOX_STATIC_IP}" -p 443:443/udp -p 8008:8008/tcp -v "${SINGBOX_CONFIG_FILE}:/etc/sing-box/config.json:ro" -v "${CADDY_DATA_VOLUME}:/caddy_certs:ro" "${SINGBOX_IMAGE_NAME}" run -c /etc/sing-box/config.json
                    press_any_key; break ;;
                0) break ;;
            esac
        done
    else
        while true; do
            clear; log INFO "--- 管理 Sing-box (已安裝) ---"
            echo " 1. 查看日誌"; echo " 2. 編輯設定檔"; echo " 3. 重啟 Sing-box"; echo " 4. 卸載 Sing-box"; echo " 0. 返回主選單"
            read -p "請輸入選項: " choice < /dev/tty
            case "$choice" in
                1) docker logs -f "$SINGBOX_CONTAINER_NAME"; press_any_key ;;
                2) if check_editor; then "$EDITOR" "${SINGBOX_CONFIG_FILE}"; fi; press_any_key ;;
                3) docker restart "$SINGBOX_CONTAINER_NAME"; press_any_key ;;
                4) docker stop "${SINGBOX_CONTAINER_NAME}" && docker rm "${SINGBOX_CONTAINER_NAME}"; log INFO "Sing-box 已卸載。"; press_any_key; break ;;
                0) break ;;
            esac
        done
    fi
}

clear_all_logs() {
    for container in "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME"; do
        if container_exists "$container"; then
            local log_path=$(docker inspect --format='{{.LogPath}}' "$container")
            if [ -f "$log_path" ]; then truncate -s 0 "$log_path"; fi
        fi
    done
    log INFO "日誌已清空。"
}

wait_for_container_ready() {
    local container="$1" service_name="$2"
    log INFO "等待 ${service_name} 啟動..."
    sleep 5
}

restart_all_services() {
    log INFO "正在重啟服務: Caddy -> Sing-box..."
    for container in "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME"; do
        if container_exists "$container"; then
            docker restart "$container"
            wait_for_container_ready "$container" "$container"
            if [ "$container" == "$CADDY_CONTAINER_NAME" ]; then sleep 15; fi
        fi
    done
    log INFO "服務已全部重啟。"
}

uninstall_all_services() {
    read -p "確定刪除所有數據？(y/N): " choice < /dev/tty
    if [[ "$choice" =~ ^[yY]$ ]]; then
        docker stop "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME" 2>/dev/null || true
        rm -rf "${APP_BASE_DIR}"
        docker volume rm "${CADDY_DATA_VOLUME}" 2>/dev/null || true
        docker network rm "${SHARED_NETWORK_NAME}" 2>/dev/null || true
        log INFO "全部清理完畢。"
    fi
}

check_all_status() {
    for container in "$CADDY_CONTAINER_NAME" "$SINGBOX_CONTAINER_NAME"; do
        if ! container_exists "$container"; then
            CONTAINER_STATUSES["$container"]="${FontColor_Red}未安裝${FontColor_Suffix}"
        else
            local status=$(docker inspect --format '{{.State.Status}}' "$container")
            if [ "$status" = "running" ]; then
                CONTAINER_STATUSES["$container"]="${FontColor_Green}運行中${FontColor_Suffix}"
            else
                CONTAINER_STATUSES["$container"]="${FontColor_Red}異常${FontColor_Suffix}"
            fi
        fi
    done
}

start_menu() {
    while true; do
        check_all_status; clear
        echo -e "\n${FontColor_Purple}Caddy + Sing-box 管理腳本${FontColor_Suffix} (v6.8.0)"
        echo -e " --------------------------------------------------"
        echo -e "  Caddy 服務        : ${CONTAINER_STATUSES[$CADDY_CONTAINER_NAME]}"
        echo -e "  Sing-box 服務     : ${CONTAINER_STATUSES[$SINGBOX_CONTAINER_NAME]}"
        echo -e " --------------------------------------------------\n"
        echo -e " ${FontColor_Green}1.${FontColor_Suffix} 管理 Caddy"
        echo -e " ${FontColor_Green}2.${FontColor_Suffix} 管理 Sing-box\n"
        echo -e " ${FontColor_Yellow}3.${FontColor_Suffix} 清理日誌並重啟所有服務"
        echo -e " ${FontColor_Red}4.${FontColor_Suffix} 徹底清理所有服務\n"
        echo -e " ${FontColor_Yellow}0.${FontColor_Suffix} 退出\n"
        read -p " 請輸入選項 [0-4]: " num < /dev/tty
        case "$num" in
            1) manage_caddy ;;
            2) manage_singbox ;;
            3) clear_all_logs; restart_all_services; press_any_key ;;
            4) uninstall_all_services; press_any_key ;;
            0) exit 0 ;;
        esac
    done
}

# --- 第3節:主邏輯 ---
check_root
self_install "$@"
check_docker
mkdir -p "${APP_BASE_DIR}"
start_menu
