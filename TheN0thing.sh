#!/usr/bin/env bash

if [ -z "${BASH_VERSINFO+x}" ] 2>/dev/null; then
    printf 'ERROR: Bash 4.4+ required\n' >&2; exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ] 2>/dev/null || \
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
    printf 'ERROR: Bash 4.4+ required (found %s.%s)\n' \
        "${BASH_VERSINFO[0]}" "${BASH_VERSINFO[1]}" >&2; exit 1
fi
set -o pipefail; set -u

NOCOLOR="${NOCOLOR:-}"
_setup_colors() {
    if [[ -n "$NOCOLOR" ]] || [[ ! -t 2 ]]; then
        C_YELLOW="" C_WHITE="" C_BLUE="" C_RED="" C_GREEN=""
        C_CYAN="" C_BOLD="" C_DIM="" C_RESET="" C_MAGENTA=""
    else
        C_YELLOW='\033[1;33m' C_WHITE='\033[1;97m' C_BLUE='\033[1;34m'
        C_RED='\033[0;31m'    C_GREEN='\033[0;32m'  C_CYAN='\033[0;36m'
        C_BOLD='\033[1m'      C_DIM='\033[2m'       C_RESET='\033[0m'
        C_MAGENTA='\033[0;35m'
    fi
}
_setup_colors

SCRIPT_NAME="$(basename "$0" | tr -cd 'a-zA-Z0-9._-')"
[[ -z "$SCRIPT_NAME" ]] && SCRIPT_NAME="then0thing"
readonly SCRIPT_NAME

CONFIG_DIR="${HOME}/.config/then0thing"
LOG_DIR="${CONFIG_DIR}/logs"
PLUGIN_DIR="${CONFIG_DIR}/plugins"
SCHEDULE_DIR="${CONFIG_DIR}/schedules"
DB_DIR="${CONFIG_DIR}/db"
if ! mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$PLUGIN_DIR" "$SCHEDULE_DIR" "$DB_DIR" 2>/dev/null; then
    printf 'FATAL: cannot create %s\n' "$CONFIG_DIR" >&2; exit 1
fi

LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}_$(date +%Y%m%d_%H%M%S).log"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
readonly MAX_LOG_SIZE=104857600
readonly MAX_LOGS=10

TEMP_DIR=""
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}.XXXXXXXX") || {
    printf 'FATAL: temp dir\n' >&2; exit 1
}
[[ -d "$TEMP_DIR" && -w "$TEMP_DIR" ]] || { printf 'FATAL: temp\n' >&2; exit 1; }
readonly TEMP_DIR

readonly VERSION="9.0"
readonly SCRIPT_PID=$$
readonly START_TIME=$SECONDS
readonly START_EPOCH=$(date +%s)
readonly MAX_THREADS_LIMIT=500
readonly MAX_RATE_LIMIT=5000
readonly MAX_TARGETS=1000
readonly MAX_CFG_LINE=4096
readonly MAX_PAR_JOBS=20
readonly CACHE_EXPIRY=7
readonly MAX_CACHE_SZ=52428800
readonly MAX_RESPONSE_SIZE=10485760
readonly MAX_FINGERPRINT_TARGETS=10000
readonly NAABU_TIMEOUT=1800
readonly UPDATE_URL="https://raw.githubusercontent.com/yourusername/TheN0thing/main/then0thing.sh"
readonly IS_MACOS=$( [[ "$(uname -s)" == "Darwin" ]] && echo true || echo false )

declare -a ACQUIRED_LOCKS=()
declare -a CHILD_PIDS=()
declare -A _LOCK_FDS=()

ERROR_COUNT=0
WARNING_COUNT=0
readonly ERROR_COUNTER_FILE="${TEMP_DIR}/.error_counter"
readonly WARNING_COUNTER_FILE="${TEMP_DIR}/.warning_counter"
printf '0' > "$ERROR_COUNTER_FILE"   || { printf 'FATAL: counter\n' >&2; exit 1; }
printf '0' > "$WARNING_COUNTER_FILE" || { printf 'FATAL: counter\n' >&2; exit 1; }

_CLEANED_UP=false
_CLEANING_UP=false
USE_CACHE="true"
SCAN_PROFILE=""
PROFILE_FAST=""
NOTIFY_METHOD=""
NOTIFY_WEBHOOK=""
NOTIFY_BOT_TOKEN=""
NOTIFY_CHAT_ID=""
SCOPE_FILE=""
OOS_FILE=""
RESUME_DIR=""
DIFF_OLD=""
DIFF_NEW=""
INTERACTIVE_MODE=false
DB_EXPORT=false
AUTO_UPDATE=false
SECURITYTRAILS_KEY="${SECURITYTRAILS_KEY:-}"

declare -rA LOG_LEVELS=(
    [DEBUG]=0 [INFO]=1 [SUCCESS]=2 [WARNING]=3 [ERROR]=4 [CRITICAL]=5
)
declare -rA PROFILES=(
    [stealth]="THREADS=10 RATE_LIMIT=10 TIMEOUT=15 FAST=false"
    [passive]="THREADS=50 RATE_LIMIT=50 TIMEOUT=10 FAST=passive"
    [aggressive]="THREADS=300 RATE_LIMIT=500 TIMEOUT=3 FAST=false"
    [ci]="THREADS=50 RATE_LIMIT=100 TIMEOUT=5 FAST=true"
    [default]="THREADS=100 RATE_LIMIT=150 TIMEOUT=5 FAST=false"
    [bounty]="THREADS=200 RATE_LIMIT=300 TIMEOUT=5 FAST=false"
)

log() {
    local lvl="$1" msg="$2"
    local ln="${LOG_LEVELS[$lvl]:-1}" th="${LOG_LEVELS[$LOG_LEVEL]:-1}"
    (( ln < th )) && return 0
    msg=$(printf '%s' "$msg" | tr -d '\033' | tr -cd '[:print:] \n')
    local col ico
    case "$lvl" in
        DEBUG)    col="$C_DIM"    ico="D" ;;
        INFO)     col="$C_BLUE"   ico="I" ;;
        SUCCESS)  col="$C_GREEN"  ico="+" ;;
        WARNING)  col="$C_YELLOW" ico="W" ;;
        ERROR)    col="$C_RED"    ico="E" ;;
        CRITICAL) col="$C_RED"    ico="!" ;;
        *)        col="$C_WHITE"  ico=" " ;;
    esac
    printf "%b%s [%s] %s%b\n" "$col" "$ico" "$(date +%H:%M:%S)" "$msg" "$C_RESET" >&2
    if [[ -f "$LOG_FILE" ]]; then
        local log_sz
        log_sz=$(wc -c < "$LOG_FILE" 2>/dev/null) || log_sz=0
        log_sz="${log_sz//[[:space:]]/}"
        [[ "$log_sz" =~ ^[0-9]+$ ]] || log_sz=0
        if (( log_sz > MAX_LOG_SIZE )); then
            printf "[%s] [WARNING ] Log truncated\n" "$(date +"%Y-%m-%d %H:%M:%S")" > "$LOG_FILE" 2>/dev/null || true
            return 0
        fi
    fi
    local safe_msg
    safe_msg=$(printf '%s' "$msg" | sed -E \
        -e 's/(token|key|secret|password|credential|api[_-]?key|access[_-]?token|private[_-]?key|authorization)[=: ]+[^[:space:]]*/\1=***REDACTED***/gi' \
        -e 's/(Bearer )[^[:space:]]+/\1***REDACTED***/gi' \
        -e 's/(X-API-Key[: ]+)[^[:space:]]+/\1***REDACTED***/gi' \
        -e 's/(bot)[0-9]+:[A-Za-z0-9_-]+/\1***REDACTED***/gi' \
        -e 's/(SECURITYTRAILS_KEY[=: ]+)[^[:space:]]*/\1***REDACTED***/gi')
    printf "[%s] [%-8s] %s\n" "$(date +"%Y-%m-%d %H:%M:%S")" "$lvl" "$safe_msg" \
        >> "$LOG_FILE" 2>/dev/null || true
}

_resolve_script_dir() {
    local src="${BASH_SOURCE[0]}" dep=0
    while [[ -L "$src" ]]; do
        (( ++dep > 20 )) && { pwd; return 0; }
        local d; d=$(cd -P "$(dirname "$src")" 2>/dev/null && pwd) || { pwd; return 0; }
        src=$(readlink "$src" 2>/dev/null) || { pwd; return 0; }
        [[ "$src" != /* ]] && src="$d/$src"
    done
    cd -P "$(dirname "$src")" 2>/dev/null && pwd || pwd
}
readonly SCRIPT_DIR="$(_resolve_script_dir)"

_hash_string() {
    local i="$1"
    if   command -v sha256sum &>/dev/null; then printf '%s' "$i" | sha256sum | cut -c1-32
    elif command -v shasum    &>/dev/null; then printf '%s' "$i" | shasum -a 256 | cut -c1-32
    elif command -v md5sum    &>/dev/null; then printf '%s' "$i" | md5sum | cut -d' ' -f1
    elif command -v md5       &>/dev/null; then printf '%s' "$i" | md5 -q
    else
        local ck len h
        ck=$(printf '%s' "$i" | cksum | awk '{print $1}'); len=${#i}
        h=$(printf '%08x%08x' "$ck" "$len")
        local j c s=0
        for (( j=0; j<${#i} && j<32; j++ )); do
            printf -v c '%d' "'${i:$j:1}"; s=$(( (s * 31 + c) & 0xFFFFFFFF ))
        done
        printf '%s%08x' "$h" "$s"
    fi
}

_stat_field() {
    stat -c "$1" "$3" 2>/dev/null || stat -f "$2" "$3" 2>/dev/null || printf '%s' "${4:-}"
}

_safe_sleep() {
    local d="$1"
    [[ "$d" =~ ^[0-9]*\.?[0-9]+$ ]] || return 0
    sleep "$d" 2>/dev/null || {
        local i="${d%.*}"
        [[ -n "$i" && "$i" != "0" ]] && sleep "$i" 2>/dev/null || true
    }
}

_count_lines() {
    local f="$1"
    [[ -f "$f" && -r "$f" ]] || { printf '0'; return 0; }
    local c; c=$(wc -l < "$f" 2>/dev/null) || { printf '0'; return 0; }
    c="${c//[[:space:]]/}"
    [[ "$c" =~ ^[0-9]+$ ]] && printf '%s' "$c" || printf '0'
}

_safe_count() {
    local result; result=$(_count_lines "$1")
    [[ "$result" =~ ^[0-9]+$ ]] || result=0
    printf '%s' "$result"
}

_sort_inplace() {
    local f="$1"; [[ -s "$f" ]] || return 0
    local t; t=$(mktemp "${f}.sort.XXXXXX") || return 1
    if sort -u -- "$f" > "$t" 2>/dev/null; then mv -- "$t" "$f"
    else rm -f -- "$t"; return 1; fi
}

_clamp() {
    local nm="$1" v="$2" lo="$3" hi="$4"
    if [[ ! "$v" =~ ^[0-9]+$ ]]; then
        log "WARNING" "[$nm] Non-numeric '$v', using $lo"
        printf '%s' "$lo"; return 1
    fi
    (( v < lo )) && v=$lo; (( v > hi )) && v=$hi
    printf '%s' "$v"
}

_strip_q() {
    local v="$1"
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
    printf '%s' "$v"
}

_mktmp() { mktemp "${TEMP_DIR}/${1:-t}.XXXXXX" 2>/dev/null; }

_safe_cat_dir() {
    local dir="$1" sfx="${2:-.txt}"
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a f=("${dir}"/*"${sfx}"); eval "$sv"
    (( ${#f[@]} )) && cat -- "${f[@]}" || true
}

_close_fd() {
    local fd="${1:-}"; [[ -z "$fd" ]] && return 0
    [[ "$fd" =~ ^[0-9]{1,4}$ ]] || return 0
    (( fd <= 2 || fd > 1023 )) && return 0
    eval "exec ${fd}>&-" 2>/dev/null || true
}

_remove_child_pid() {
    local target_pid="$1"
    local -a _n=(); local _p
    for _p in "${CHILD_PIDS[@]+"${CHILD_PIDS[@]}"}"; do
        [[ "$_p" != "$target_pid" ]] && _n+=("$_p")
    done
    CHILD_PIDS=("${_n[@]+"${_n[@]}"}")
}

_get_disk_free_kb() {
    local path="$1" free_kb
    free_kb=$(df -Pk "$path" 2>/dev/null | awk 'NR==2{print $4}')
    free_kb="${free_kb//[[:space:]]/}"
    [[ "$free_kb" =~ ^[0-9]+$ ]] && printf '%s' "$free_kb" || printf '999999999'
}

_check_disk_ok() {
    local path="$1" min_kb="${2:-262144}"
    local dfree; dfree=$(_get_disk_free_kb "$path")
    (( dfree >= min_kb ))
}

_url_encode() {
    local string="$1" LC_ALL=C i c encoded=""
    for (( i = 0; i < ${#string}; i++ )); do
        c="${string:$i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) encoded+="$c" ;;
            *)
                local hex
                hex=$(printf '%s' "$c" | xxd -plain 2>/dev/null | tr -d '\n' | sed 's/\(..\)/%\1/g')
                if [[ -n "$hex" ]]; then
                    encoded+=$(printf '%s' "$hex" | tr '[:lower:]' '[:upper:]')
                else
                    encoded+=$(printf '%%%02X' "'$c")
                fi
                ;;
        esac
    done
    printf '%s' "$encoded"
}

_escape_ere() {
    local input="$1" escaped="" i c
    for (( i=0; i<${#input}; i++ )); do
        c="${input:$i:1}"
        case "$c" in
            '['|']'|'.'|'*'|'+'|'?'|'('|')'|'{'|'}'|'|'|'^'|'$'|'\\')
                escaped+="\\$c" ;;
            *) escaped+="$c" ;;
        esac
    done
    printf '%s' "$escaped"
}

_validate_url() {
    local url="$1"
    [[ "$url" =~ ^https:// ]] || return 1
    [[ "$url" =~ [[:space:]\;\|\&\$\`\<\>] ]] && return 1
    (( ${#url} > 2048 )) && return 1
    return 0
}

_sanitize_notify_text() {
    printf '%s' "$1" | tr -cd 'a-zA-Z0-9 ._:/-@#,()[]{}=+\n'
}

_atomic_inc() {
    local counter_file="$1"
    [[ -f "$counter_file" ]] || return 0
    if command -v flock &>/dev/null; then
        {
            flock -x 200
            local current; current=$(cat "$counter_file" 2>/dev/null) || current=0
            current="${current//[[:space:]]/}"
            [[ "$current" =~ ^[0-9]+$ ]] || current=0
            printf '%s' "$(( current + 1 ))" > "$counter_file"
        } 200>"${counter_file}.lock"
    else
        printf '1\n' >> "${counter_file}.inc"
    fi
}

_atomic_read() {
    local counter_file="$1" result=0
    if command -v flock &>/dev/null; then
        {
            flock -x 200
            if [[ -f "${counter_file}.inc" && -s "${counter_file}.inc" ]]; then
                local inc_count
                inc_count=$(wc -l < "${counter_file}.inc" 2>/dev/null) || inc_count=0
                inc_count="${inc_count//[[:space:]]/}"
                [[ "$inc_count" =~ ^[0-9]+$ ]] || inc_count=0
                if (( inc_count > 0 )); then
                    local val; val=$(cat "$counter_file" 2>/dev/null) || val=0
                    val="${val//[[:space:]]/}"; [[ "$val" =~ ^[0-9]+$ ]] || val=0
                    printf '%s' "$(( val + inc_count ))" > "$counter_file"
                    : > "${counter_file}.inc"
                fi
            fi
            result=$(cat "$counter_file" 2>/dev/null) || result=0
        } 200>"${counter_file}.lock"
    else
        if [[ -f "${counter_file}.inc" && -s "${counter_file}.inc" ]]; then
            local tmp_inc="${counter_file}.inc.$$"
            if mv "${counter_file}.inc" "$tmp_inc" 2>/dev/null; then
                local inc_count
                inc_count=$(wc -l < "$tmp_inc" 2>/dev/null) || inc_count=0
                inc_count="${inc_count//[[:space:]]/}"
                [[ "$inc_count" =~ ^[0-9]+$ ]] || inc_count=0
                if (( inc_count > 0 )); then
                    local val; val=$(cat "$counter_file" 2>/dev/null) || val=0
                    val="${val//[[:space:]]/}"; [[ "$val" =~ ^[0-9]+$ ]] || val=0
                    printf '%s' "$(( val + inc_count ))" > "$counter_file"
                fi
                rm -f "$tmp_inc"
            fi
        fi
        result=$(cat "$counter_file" 2>/dev/null) || result=0
    fi
    result="${result//[[:space:]]/}"; [[ "$result" =~ ^[0-9]+$ ]] || result=0
    printf '%s' "$result"
}

_warn_count() { _atomic_inc "$WARNING_COUNTER_FILE"; }
_error_count() { _atomic_inc "$ERROR_COUNTER_FILE"; }
_sync_counters() {
    ERROR_COUNT=$(_atomic_read "$ERROR_COUNTER_FILE")
    WARNING_COUNT=$(_atomic_read "$WARNING_COUNTER_FILE")
}

_has_timeout=false
command -v timeout &>/dev/null && _has_timeout=true

_ptimeout() {
    local sec="$1"; shift
    [[ "$sec" =~ ^[0-9]+$ ]] || sec=30
    (( sec < 1 )) && sec=1; (( sec > 7200 )) && sec=7200
    if [[ "$_has_timeout" == true ]]; then
        if timeout --help 2>&1 | grep -q '\-\-foreground' 2>/dev/null; then
            timeout --kill-after=10 --foreground "$sec" "$@"
        else
            timeout --kill-after=10 "$sec" "$@" 2>/dev/null || timeout "$sec" "$@"
        fi
        return $?
    fi
    "$@" &
    local bg_pid=$!; CHILD_PIDS+=("$bg_pid")
    local t_start=$SECONDS elapsed=0
    while true; do
        if ! kill -0 "$bg_pid" 2>/dev/null; then
            wait "$bg_pid" 2>/dev/null; local rc=$?
            _remove_child_pid "$bg_pid"; return "$rc"
        fi
        elapsed=$(( SECONDS - t_start ))
        (( elapsed >= sec )) && break
        local remaining=$(( sec - elapsed ))
        if (( remaining > 1 )); then sleep 0.5 2>/dev/null || sleep 1
        else sleep 0.2 2>/dev/null || sleep 1; fi
    done
    local pgid
    pgid=$(ps -o pgid= -p "$bg_pid" 2>/dev/null | tr -d ' ')
    if [[ -n "$pgid" && "$pgid" =~ ^[0-9]+$ && "$pgid" != "$$" && "$pgid" != "1" ]]; then
        kill -TERM -"$pgid" 2>/dev/null || true; sleep 2
        kill -9 -"$pgid" 2>/dev/null || true
    else
        kill -TERM "$bg_pid" 2>/dev/null; sleep 2
        kill -0 "$bg_pid" 2>/dev/null && kill -9 "$bg_pid" 2>/dev/null
    fi
    wait "$bg_pid" 2>/dev/null || true
    _remove_child_pid "$bg_pid"; return 124
}

_safe_jq() {
    local out="$1" inp="$2"; shift 2
    if [[ -f "$inp" ]]; then
        local isz; isz=$(wc -c < "$inp" 2>/dev/null); isz="${isz//[[:space:]]/}"
        [[ "$isz" =~ ^[0-9]+$ ]] || isz=0
        (( isz > MAX_RESPONSE_SIZE )) && { log "WARNING" "[jq] Input too large"; return 1; }
    fi
    local _jarg
    for _jarg in "$@"; do
        case "$_jarg" in
            -r|-e|-s|-S|-c|-R|--raw-output|--exit-status|--slurp|--sort-keys) continue ;;
        esac
        if [[ "$_jarg" == *'$('* || "$_jarg" == *'`'* || \
              "$_jarg" == *'$ENV'* || "$_jarg" == *'env.'* ]]; then
            log "WARNING" "[jq] Blocked suspicious filter"; return 1
        fi
    done
    local jt je
    jt=$(_mktmp jqo) || return 1
    je=$(_mktmp jqe) || { rm -f -- "$jt"; return 1; }
    if _ptimeout 30 jq "$@" < "$inp" > "$jt" 2> "$je"; then
        mv -- "$jt" "$out"; rm -f -- "$je"; return 0
    fi
    local rc=$?
    [[ -s "$je" ]] && log "DEBUG" "[jq] $(head -3 "$je" 2>/dev/null)"
    rm -f -- "$jt" "$je"; return "$rc"
}

CONFIG_FILE="${CONFIG_DIR}/config.conf"
CACHE_DIR="${CONFIG_DIR}/cache"
LOCK_DIR="${CONFIG_DIR}/locks"
mkdir -p "$CACHE_DIR" "$LOCK_DIR" 2>/dev/null || true

acquire_lock() {
    local tgt="$1" lh; lh=$(_hash_string "$tgt")
    if ! command -v flock &>/dev/null; then
        local lock_dir="${LOCK_DIR}/${lh}.lock.d"
        local max_attempts=5 attempt=0
        while (( attempt++ < max_attempts )); do
            if mkdir "$lock_dir" 2>/dev/null; then
                local info_tmp="${lock_dir}/info.$$"
                printf '%s\n%s' "$SCRIPT_PID" "$(date +%s)" > "$info_tmp" 2>/dev/null
                mv "$info_tmp" "$lock_dir/info" 2>/dev/null || true
                ACQUIRED_LOCKS+=("$lock_dir"); return 0
            fi
            local lock_pid="" lock_time="" stale=false
            if [[ -f "$lock_dir/info" ]]; then
                lock_pid=$(head -1 "$lock_dir/info" 2>/dev/null)
                lock_time=$(sed -n '2p' "$lock_dir/info" 2>/dev/null)
                lock_pid="${lock_pid//[[:space:]]/}"; lock_time="${lock_time//[[:space:]]/}"
            fi
            if [[ -n "$lock_pid" && "$lock_pid" =~ ^[0-9]+$ ]]; then
                if ! kill -0 "$lock_pid" 2>/dev/null; then stale=true
                elif [[ "$lock_time" =~ ^[0-9]+$ ]]; then
                    (( $(date +%s) - lock_time > 3600 )) && stale=true
                fi
            else stale=true; fi
            [[ "$stale" == true ]] && { rm -rf "$lock_dir" 2>/dev/null; continue; }
            sleep 1
        done
        log "ERROR" "[lock] Cannot acquire: $tgt"; return 1
    fi
    local lock_file="${LOCK_DIR}/${lh}.lock" lock_fd=""
    exec {lock_fd}>"$lock_file"
    if ! flock -n "$lock_fd"; then
        _close_fd "$lock_fd"; log "ERROR" "[lock] Locked: $tgt"; return 1
    fi
    printf '%s' "$SCRIPT_PID" >&"$lock_fd"
    _LOCK_FDS["$lock_file"]="$lock_fd"
    ACQUIRED_LOCKS+=("$lock_file"); return 0
}

release_lock() {
    local tgt="$1" lh; lh=$(_hash_string "$tgt")
    local lock_file="${LOCK_DIR}/${lh}.lock"
    [[ -n "${_LOCK_FDS[$lock_file]+x}" ]] && {
        _close_fd "${_LOCK_FDS[$lock_file]}"; unset '_LOCK_FDS[$lock_file]'
    }
    rm -f "$lock_file" 2>/dev/null || true
    rm -rf "${LOCK_DIR}/${lh}.lock.d" 2>/dev/null || true
    local -a _n=(); local _l
    for _l in "${ACQUIRED_LOCKS[@]+"${ACQUIRED_LOCKS[@]}"}"; do
        [[ "$_l" != "$lock_file" && "$_l" != "${LOCK_DIR}/${lh}.lock.d" ]] && _n+=("$_l")
    done
    ACQUIRED_LOCKS=("${_n[@]+"${_n[@]}"}")
}

_chk_sec() {
    local fp="$1" lb="${2:-File}"
    local ow; ow=$(_stat_field '%u' '%u' "$fp")
    [[ -n "$ow" && "$ow" != "$(id -u)" ]] && { log "ERROR" "[$lb] Wrong owner"; return 1; }
    local pm; pm=$(_stat_field '%a' '%Lp' "$fp" '600'); pm="${pm: -3}"
    [[ "$pm" =~ ^[0-7]{3}$ ]] && (( (${pm:1:1}&2) || (${pm:2:1}&2) )) && chmod 600 "$fp"
    return 0
}

_val_file() {
    local fp="$1" lb="${2:-File}"
    [[ -e "$fp" ]] || { log "ERROR" "[$lb] Missing: $fp"; return 1; }
    if [[ -L "$fp" ]]; then
        fp=$(readlink -f "$fp" 2>/dev/null || realpath "$fp" 2>/dev/null) || {
            log "ERROR" "[$lb] Cannot resolve symlink"; return 1; }
    fi
    case "$fp" in
        /etc/shadow|/etc/passwd|/etc/sudoers*|*/.ssh/*|*/.gnupg/*)
            log "ERROR" "[$lb] Blocked path: $fp"; return 1 ;;
    esac
    [[ -f "$fp" && -r "$fp" ]] || { log "ERROR" "[$lb] Not readable: $fp"; return 1; }
    printf '%s' "$fp"
}

_val_opath() {
    local od="$1"
    [[ "$od" == *".."* || "$od" == *$'\n'* || "$od" == *$'\r'* ]] && {
        log "ERROR" "[path] Invalid chars"; return 1; }
    local bn; bn=$(basename "$od")
    [[ "$bn" == "." || "$bn" == ".." ]] && { log "ERROR" "[path] Invalid basename"; return 1; }
    local pd; pd=$(dirname "$od"); mkdir -p "$pd" 2>/dev/null || true
    local resolved
    if [[ -d "$pd" ]]; then
        local rp; rp=$(cd -P "$pd" 2>/dev/null && pwd) || {
            log "ERROR" "[path] Cannot resolve: $pd"; return 1; }
        resolved="${rp}/$(basename "$od")"
    else log "ERROR" "[path] Parent missing: $pd"; return 1; fi
    if [[ -e "$od" ]]; then
        if [[ -d "$od" ]]; then
            resolved=$(cd -P "$od" 2>/dev/null && pwd) || {
                log "ERROR" "[path] Cannot resolve: $od"; return 1; }
        elif [[ -L "$od" ]]; then
            resolved=$(readlink -f "$od" 2>/dev/null) || {
                log "ERROR" "[path] Cannot resolve link"; return 1; }
        fi
    fi
    local cwd; cwd=$(pwd -P 2>/dev/null || pwd)
    local allowed=false
    case "$resolved" in "${cwd}/"*) allowed=true ;; "${HOME}/"*) allowed=true ;; esac
    case "$resolved" in
        "${HOME}/.ssh/"*|"${HOME}/.gnupg/"*|"/etc/"*|"/var/"*|"/usr/"*|"/bin/"*|"/sbin/"*) allowed=false ;;
        "${HOME}/.config/then0thing/"*) allowed=true ;;
    esac
    [[ "$allowed" != true ]] && { log "ERROR" "[path] Blocked: $resolved"; return 1; }
    printf '%s' "$resolved"
}

sanitize_target() {
    local t="$1"
    [[ "$t" =~ ^[a-zA-Z0-9._-]+$ ]] || { log "ERROR" "[sanitize] Bad chars: $t"; return 1; }
    (( ${#t} > 253 )) && { log "ERROR" "[sanitize] Too long"; return 1; }
    [[ "$t" == "." || "$t" == ".." ]] && { log "ERROR" "[sanitize] Invalid"; return 1; }
    printf '%s' "$t"
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    local -a oc; IFS='.' read -ra oc <<< "$ip"
    [[ ${#oc[@]} -eq 4 ]] || return 1
    local o; for o in "${oc[@]}"; do
        [[ "$o" =~ ^[0-9]+$ ]] || return 1
        [[ ${#o} -gt 1 && "$o" == 0* ]] && return 1
        (( 10#$o > 255 )) && return 1
    done; return 0
}

is_private_ip() {
    local ip="$1"; validate_ip "$ip" || return 1
    local -a oc; IFS='.' read -ra oc <<< "$ip"
    (( oc[0] == 0 )) && return 0
    (( oc[0] == 10 )) && return 0
    (( oc[0] == 127 )) && return 0
    (( oc[0] == 169 && oc[1] == 254 )) && return 0
    (( oc[0] == 172 && oc[1] >= 16 && oc[1] <= 31 )) && return 0
    (( oc[0] == 192 && oc[1] == 168 )) && return 0
    (( oc[0] >= 224 )) && return 0
    return 1
}

_filter_public_ips() {
    local input_file="$1" output_file="$2"
    local tmp_out; tmp_out=$(_mktmp fpi) || return 1
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        validate_ip "$ip" || continue
        is_private_ip "$ip" && continue
        printf '%s\n' "$ip"
    done < "$input_file" > "$tmp_out"
    mv -- "$tmp_out" "$output_file" 2>/dev/null || { rm -f "$tmp_out"; return 1; }
}

detect_type() {
    local i="$1"; (( ${#i} > 253 )) && { printf 'unknown'; return; }
    if [[ "$i" =~ ^AS[0-9]+$ ]]; then printf 'asn'
    elif [[ "$i" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local _dip _dmask; IFS='/' read -r _dip _dmask <<< "$i"
        validate_ip "$_dip" && [[ "$_dmask" =~ ^[0-9]+$ ]] && (( _dmask >= 0 && _dmask <= 32 )) && \
            printf 'ip_range' || printf 'unknown'
    elif [[ "$i" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        validate_ip "$i" && printf 'ip' || printf 'unknown'
    elif [[ "$i" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,63}$ ]]; then
        printf 'domain'
    else printf 'unknown'; fi
}

validate_asn()    { [[ "$1" =~ ^AS[0-9]+$ ]]; }
validate_domain() { [[ "$1" =~ \. && ! "$1" =~ [[:space:]] && "$1" =~ ^[a-zA-Z0-9.\-]+$ ]]; }

_val_ports() {
    local ps="$1"
    [[ "$ps" =~ ^[0-9,]+$ ]] || { log "ERROR" "[ports] Numbers only"; return 1; }
    local -a _pa; IFS=',' read -ra _pa <<< "$ps"
    local p; for p in "${_pa[@]}"; do
        [[ -z "$p" ]] && continue
        [[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 )) || return 1
    done; return 0
}

_write_token_file() {
    local token_name="$1" token_value="$2"
    [[ -z "$token_value" ]] && return 1
    [[ "$token_name" =~ ^[a-zA-Z0-9_]+$ ]] || return 1
    local token_file="${TEMP_DIR}/.token_${token_name}"
    ( umask 077; printf '%s' "$token_value" > "$token_file" ) || return 1
    chmod 600 "$token_file" 2>/dev/null
    [[ -f "$token_file" ]] || return 1
    printf '%s' "$token_file"
}

_read_token_file() {
    local tf="$1"; [[ -f "$tf" && -r "$tf" ]] || return 1; cat "$tf" 2>/dev/null
}

_clean_token_files() {
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a tf=("${TEMP_DIR}"/.token_*); eval "$sv"
    local f; for f in "${tf[@]}"; do
        [[ -f "$f" ]] || continue
        local sz; sz=$(wc -c < "$f" 2>/dev/null) || sz=0; sz="${sz//[[:space:]]/}"
        [[ "$sz" =~ ^[0-9]+$ ]] || sz=0; (( sz < 64 )) && sz=64
        dd if=/dev/urandom of="$f" bs="$sz" count=1 2>/dev/null || true
        sync 2>/dev/null || true; rm -f -- "$f"
    done
}
# ══════════════════════════════════════════
# CONFIG & DEFAULTS
# ══════════════════════════════════════════
declare -rA _DFLT=(
    [THREADS]=100 [TIMEOUT]=5 [MAX_RETRIES]=3 [RATE_LIMIT]=150
    [WORDLISTS]="${SCRIPT_DIR}/wordlist/subdomains-top1million-5000.txt"
    [RESOLVERS]="${SCRIPT_DIR}/wordlist/resolvers.txt"
    [WEB_PORTS]="80,443,8080,8443,3000,8000,8081"
    [EXT_PORTS]="80,443,81,82,88,135,143,300,554,591,593,832,902,981,993,1010,1024,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3128,3306,3333,3389,4243,4443,4567,4711,4712,4993,5000,5001,5060,5104,5108,5357,5432,5800,5985,6379,6543,7000,7170,7396,7474,7547,8000,8001,8008,8014,8042,8069,8080,8081,8083,8085,8088,8089,8090,8091,8118,8123,8172,8181,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9100,9200,9443,9800,9981,9999,10000,10443,12345,12443,16080,18091,18092,20720,28017,49152"
)
declare -A _FENV=()
[[ "${THREADS+x}" == x ]] && _FENV[THREADS]=1
[[ "${TIMEOUT+x}" == x ]] && _FENV[TIMEOUT]=1
[[ "${MAX_RETRIES+x}" == x ]] && _FENV[MAX_RETRIES]=1
[[ "${RATE_LIMIT+x}" == x ]] && _FENV[RATE_LIMIT]=1

THREADS="${THREADS:-${_DFLT[THREADS]}}" TIMEOUT="${TIMEOUT:-${_DFLT[TIMEOUT]}}"
WORDLISTS="${WORDLISTS:-${_DFLT[WORDLISTS]}}" RESOLVERS="${RESOLVERS:-${_DFLT[RESOLVERS]}}"
MAX_RETRIES="${MAX_RETRIES:-${_DFLT[MAX_RETRIES]}}" RATE_LIMIT="${RATE_LIMIT:-${_DFLT[RATE_LIMIT]}}"
WEB_PORTS="${WEB_PORTS:-${_DFLT[WEB_PORTS]}}" EXT_PORTS="${EXT_PORTS:-${_DFLT[EXT_PORTS]}}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}" CHAOS_KEY="${CHAOS_KEY:-}" GITLAB_TOKEN="${GITLAB_TOKEN:-}"
SHODAN_KEY="${SHODAN_KEY:-}" CENSYS_API_ID="${CENSYS_API_ID:-}" CENSYS_API_SECRET="${CENSYS_API_SECRET:-}"
SPYSE_API_TOKEN="${SPYSE_API_TOKEN:-}"

_load_token() {
    local k="$1" v="$2"; [[ "$v" =~ ^[a-zA-Z0-9._:/-]+$ ]] || return 1
    case "$k" in
        GITHUB_TOKEN) GITHUB_TOKEN="$v" ;;
        CHAOS_KEY) CHAOS_KEY="$v" ;;
        GITLAB_TOKEN) GITLAB_TOKEN="$v" ;;
        SHODAN_KEY) SHODAN_KEY="$v" ;;
        CENSYS_API_ID) CENSYS_API_ID="$v" ;;
        CENSYS_API_SECRET) CENSYS_API_SECRET="$v" ;;
        SPYSE_API_TOKEN) SPYSE_API_TOKEN="$v" ;;
        SECURITYTRAILS_KEY) SECURITYTRAILS_KEY="$v" ;;
        *) return 1 ;;
    esac
}

load_config() {
    local k v
    if [[ -f "$CONFIG_FILE" ]]; then
        _chk_sec "$CONFIG_FILE" "Config" || return 1
        while IFS='=' read -r -n "$MAX_CFG_LINE" k v || [[ -n "$k" ]]; do
            [[ "$k" =~ ^[[:space:]]*# || -z "$k" ]] && continue
            k="${k//[[:space:]]/}"; v=$(_strip_q "$v")
            case "$k" in
                THREADS)     [[ -n "${_FENV[THREADS]+x}" ]] && continue; THREADS=$(_clamp THREADS "$v" 1 "$MAX_THREADS_LIMIT") || true ;;
                TIMEOUT)     [[ -n "${_FENV[TIMEOUT]+x}" ]] && continue; TIMEOUT=$(_clamp TIMEOUT "$v" 1 300) || true ;;
                MAX_RETRIES) [[ -n "${_FENV[MAX_RETRIES]+x}" ]] && continue; MAX_RETRIES=$(_clamp MAX_RETRIES "$v" 1 10) || true ;;
                RATE_LIMIT)  [[ -n "${_FENV[RATE_LIMIT]+x}" ]] && continue; RATE_LIMIT=$(_clamp RATE_LIMIT "$v" 1 "$MAX_RATE_LIMIT") || true ;;
                WORDLISTS)   [[ -f "$v" ]] && WORDLISTS="$v" ;;
                RESOLVERS)   [[ -f "$v" ]] && RESOLVERS="$v" ;;
                WEB_PORTS)   v="${v//[[:space:]]/}"; _val_ports "$v" 2>/dev/null && WEB_PORTS="$v" ;;
                EXT_PORTS)   v="${v//[[:space:]]/}"; _val_ports "$v" 2>/dev/null && EXT_PORTS="$v" ;;
                LOG_LEVEL)   v="${v//[[:space:]]/}"; [[ "$v" =~ ^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$ ]] && LOG_LEVEL="$v" ;;
            esac
        done < "$CONFIG_FILE"
    else
        _mk_dflt_cfg
    fi
    local tf="${CONFIG_DIR}/api_tokens.conf"
    [[ -f "$tf" ]] || return 0
    _chk_sec "$tf" "Tokens" || return 1
    while IFS='=' read -r -n "$MAX_CFG_LINE" k v || [[ -n "$k" ]]; do
        [[ "$k" =~ ^[[:space:]]*# || -z "$k" ]] && continue
        k="${k//[[:space:]]/}"; v=$(_strip_q "$v"); [[ -z "$v" ]] && continue
        _load_token "$k" "$v" || true
    done < "$tf"
}

_mk_dflt_cfg() {
    cat > "$CONFIG_FILE" << 'C'
THREADS=100
TIMEOUT=5
MAX_RETRIES=3
RATE_LIMIT=150
WEB_PORTS=80,443,8080,8443,3000,8000,8081
LOG_LEVEL=INFO
C
    chmod 600 "$CONFIG_FILE"
    cat > "${CONFIG_DIR}/api_tokens.conf" << 'T'
# API Tokens
# GITHUB_TOKEN=
# CHAOS_KEY=
# SHODAN_KEY=
# SECURITYTRAILS_KEY=
# CENSYS_API_ID=
# CENSYS_API_SECRET=
# GITLAB_TOKEN=
# SPYSE_API_TOKEN=
T
    chmod 600 "${CONFIG_DIR}/api_tokens.conf"
}

apply_profile() {
    local profile="$1"; [[ -z "$profile" ]] && return 0
    local pdata="${PROFILES[$profile]:-}"
    [[ -z "$pdata" ]] && { log "ERROR" "[profile] Unknown: $profile"; return 1; }
    log "INFO" "Profile: $profile"
    local -a pairs=(); read -ra pairs <<< "$pdata"
    local pair key val
    for pair in "${pairs[@]}"; do
        [[ -z "$pair" ]] && continue
        key="${pair%%=*}"; val="${pair#*=}"
        case "$key" in
            THREADS) THREADS="$val" ;; RATE_LIMIT) RATE_LIMIT="$val" ;;
            TIMEOUT) TIMEOUT="$val" ;; FAST) PROFILE_FAST="$val" ;;
        esac
    done
}

# ══════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════
send_notification() {
    local title="$1" body="$2"; [[ -z "$NOTIFY_METHOD" ]] && return 0
    local safe_title safe_body
    safe_title=$(_sanitize_notify_text "$title")
    safe_body=$(_sanitize_notify_text "$body")
    case "$NOTIFY_METHOD" in
        slack)
            [[ -z "$NOTIFY_WEBHOOK" ]] && return 0
            _validate_url "$NOTIFY_WEBHOOK" || { log "WARNING" "Invalid webhook"; return 0; }
            local pf; pf=$(_mktmp slkpay) || return 0
            jq -n --arg t "$safe_title" --arg b "$safe_body" \
                '{text:($t+"\n"+$b)}' > "$pf" 2>/dev/null || { rm -f "$pf"; return 0; }
            _ptimeout 30 curl -fsS -X POST -H 'Content-type: application/json' \
                --data-binary "@${pf}" "$NOTIFY_WEBHOOK" >/dev/null 2>/dev/null || true
            rm -f "$pf"
            ;;
        discord)
            [[ -z "$NOTIFY_WEBHOOK" ]] && return 0
            _validate_url "$NOTIFY_WEBHOOK" || { log "WARNING" "Invalid webhook"; return 0; }
            local pf; pf=$(_mktmp dcpay) || return 0
            jq -n --arg t "$safe_title" --arg b "$safe_body" \
                '{content:($t+"\n"+$b)}' > "$pf" 2>/dev/null || { rm -f "$pf"; return 0; }
            _ptimeout 30 curl -fsS -X POST -H 'Content-type: application/json' \
                --data-binary "@${pf}" "$NOTIFY_WEBHOOK" >/dev/null 2>/dev/null || true
            rm -f "$pf"
            ;;
        telegram)
            [[ -z "$NOTIFY_BOT_TOKEN" || -z "$NOTIFY_CHAT_ID" ]] && return 0
            [[ "$NOTIFY_CHAT_ID" =~ ^-?[0-9]+$ ]] || { log "WARNING" "Invalid chat_id"; return 0; }
            local tg_data tg_cfg
            tg_data=$(_mktmp tgdata) || return 0
            tg_cfg=$(_mktmp tgcfg) || { rm -f "$tg_data"; return 0; }
            local tf; tf=$(_write_token_file "tg_bot" "$NOTIFY_BOT_TOKEN") || {
                rm -f "$tg_data" "$tg_cfg"; return 0; }
            local _tok; _tok=$(_read_token_file "$tf") || {
                rm -f "$tg_data" "$tg_cfg" "$tf"; return 0; }
            ( umask 077; printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "$_tok" > "$tg_cfg" )
            jq -n --arg cid "$NOTIFY_CHAT_ID" \
                  --arg txt "${safe_title}: ${safe_body}" \
                  '{chat_id:$cid,text:$txt}' > "$tg_data" 2>/dev/null || {
                rm -f "$tg_data" "$tg_cfg" "$tf"; return 0; }
            _ptimeout 30 curl -fsS -K "$tg_cfg" -X POST \
                -H 'Content-Type: application/json' \
                --data-binary "@${tg_data}" >/dev/null 2>/dev/null || true
            rm -f "$tg_data" "$tg_cfg" "$tf"
            ;;
    esac
}
notify_finding() { send_notification "[$1] TheN0thing" "$2"; }

# ══════════════════════════════════════════
# SCOPE MANAGEMENT
# ══════════════════════════════════════════
declare -a _SCOPE_PATTERNS=()
declare -a _OOS_PATTERNS=()

_load_scope_patterns() {
    _SCOPE_PATTERNS=(); _OOS_PATTERNS=()
    local pattern
    if [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
            pattern="${pattern//[[:space:]]/}"
            _SCOPE_PATTERNS+=("$pattern")
        done < "$SCOPE_FILE"
    fi
    if [[ -n "$OOS_FILE" && -f "$OOS_FILE" ]]; then
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
            pattern="${pattern//[[:space:]]/}"
            _OOS_PATTERNS+=("$pattern")
        done < "$OOS_FILE"
    fi
}

is_in_scope() {
    local domain="$1"
    [[ -z "$SCOPE_FILE" ]] && return 0
    (( ${#_SCOPE_PATTERNS[@]} == 0 )) && return 1
    local pattern
    for pattern in "${_SCOPE_PATTERNS[@]}"; do
        if [[ "$pattern" == \** ]]; then
            local base="${pattern#\*.}"
            [[ "$domain" == *".$base" || "$domain" == "$base" ]] && return 0
        else
            [[ "$domain" == "$pattern" ]] && return 0
        fi
    done
    return 1
}

is_out_of_scope() {
    local domain="$1"
    [[ -z "$OOS_FILE" || ! -f "$OOS_FILE" ]] && return 1
    (( ${#_OOS_PATTERNS[@]} == 0 )) && return 1
    local pattern
    for pattern in "${_OOS_PATTERNS[@]}"; do
        [[ "$domain" == "$pattern" ]] && return 0
        if [[ "$pattern" == \** ]]; then
            local base="${pattern#\*.}"
            [[ "$domain" == *".$base" ]] && return 0
        fi
    done
    return 1
}

filter_scope() {
    local input_file="$1" output_file="$2"
    [[ -z "$SCOPE_FILE" && -z "$OOS_FILE" ]] && {
        [[ "$input_file" != "$output_file" ]] && cp -- "$input_file" "$output_file" 2>/dev/null
        return 0
    }
    local tmp_out; tmp_out=$(_mktmp scope) || return 1

    if [[ -n "$SCOPE_FILE" && -f "$SCOPE_FILE" ]]; then
        local scope_regex; scope_regex=$(_mktmp sg) || { rm -f -- "$tmp_out"; return 1; }
        local pattern
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
            pattern="${pattern//[[:space:]]/}"
            if [[ "$pattern" == \** ]]; then
                local base="${pattern#\*.}"; base=$(_escape_ere "$base")
                printf '(^|\\.)%s$\n' "$base" >> "$scope_regex"
            else
                printf '^%s$\n' "$(_escape_ere "$pattern")" >> "$scope_regex"
            fi
        done < "$SCOPE_FILE"
        if [[ -s "$scope_regex" ]]; then
            grep -Ef "$scope_regex" "$input_file" > "$tmp_out" 2>/dev/null || true
        else
            cp -- "$input_file" "$tmp_out" 2>/dev/null || true
        fi
        rm -f -- "$scope_regex"
    else
        cp -- "$input_file" "$tmp_out" 2>/dev/null || true
    fi

    if [[ -n "$OOS_FILE" && -f "$OOS_FILE" && -s "$tmp_out" ]]; then
        local oos_regex; oos_regex=$(_mktmp og) || { mv -- "$tmp_out" "$output_file"; return 0; }
        local pattern
        while IFS= read -r pattern; do
            [[ -z "$pattern" || "$pattern" =~ ^[[:space:]]*# ]] && continue
            pattern="${pattern//[[:space:]]/}"
            if [[ "$pattern" == \** ]]; then
                local base="${pattern#\*.}"; base=$(_escape_ere "$base")
                printf '(^|\\.)%s$\n' "$base" >> "$oos_regex"
            else
                printf '^%s$\n' "$(_escape_ere "$pattern")" >> "$oos_regex"
            fi
        done < "$OOS_FILE"
        if [[ -s "$oos_regex" ]]; then
            local tmp_f; tmp_f=$(_mktmp sf) || { rm -f -- "$oos_regex"; mv -- "$tmp_out" "$output_file"; return 0; }
            grep -vEf "$oos_regex" "$tmp_out" > "$tmp_f" 2>/dev/null || true
            mv -- "$tmp_f" "$tmp_out" 2>/dev/null || rm -f -- "$tmp_f"
        fi
        rm -f -- "$oos_regex"
    fi
    mv -- "$tmp_out" "$output_file" 2>/dev/null || { rm -f -- "$tmp_out"; return 1; }
}

# ══════════════════════════════════════════
# CHECKPOINT & DIFF
# ══════════════════════════════════════════
save_checkpoint() { printf '%s\n' "$2" > "$1/.checkpoint"; }
get_checkpoint() { [[ -f "$1/.checkpoint" ]] && cat "$1/.checkpoint" 2>/dev/null || printf '0'; }
should_run_phase() {
    [[ -z "$RESUME_DIR" ]] && return 0
    local l; l=$(get_checkpoint "$1"); (( $2 > l ))
}

run_diff() {
    local old="$1" new="$2" out="${new}/reports/diff.md"
    log "INFO" "Diff: $old vs $new"
    mkdir -p "${new}/reports" 2>/dev/null
    printf '# Scan Diff\n**Old:** `%s` | **New:** `%s` | %s\n---\n' \
        "$old" "$new" "$(date "+%Y-%m-%d %H:%M:%S")" > "$out"
    local asset
    for asset in subdomains ips asns cidrs; do
        local of="$old/assets/$asset/all.txt" nf="$new/assets/$asset/all.txt"
        [[ -f "$of" ]] || of="/dev/null"
        [[ -f "$nf" ]] || nf="/dev/null"
        local added removed
        added=$(comm -13 <(sort "$of") <(sort "$nf") 2>/dev/null | wc -l)
        added="${added//[[:space:]]/}"
        removed=$(comm -23 <(sort "$of") <(sort "$nf") 2>/dev/null | wc -l)
        removed="${removed//[[:space:]]/}"
        printf '## %s (+%s / -%s)\n' "$asset" "$added" "$removed" >> "$out"
        if [[ "${added:-0}" =~ ^[0-9]+$ ]] && (( added > 0 )); then
            printf '```\n' >> "$out"
            comm -13 <(sort "$of") <(sort "$nf") 2>/dev/null | head -50 >> "$out"
            printf '```\n' >> "$out"
            notify_finding "NEW" "$added new $asset"
        fi
        printf '\n' >> "$out"
    done
    printf '---\n*TheN0thing v%s*\n' "$VERSION" >> "$out"
    log "SUCCESS" "Diff: $out"
}

# ══════════════════════════════════════════
# PLUGINS
# ══════════════════════════════════════════
_plugin_is_safe() {
    local pf="$1"
    _chk_sec "$pf" "Plugin" || return 1
    local pname; pname=$(basename "$pf" .sh)
    [[ "$pname" =~ ^[a-zA-Z0-9_-]+$ ]] || return 1
    local sz; sz=$(wc -c < "$pf" 2>/dev/null); sz="${sz//[[:space:]]/}"
    [[ "$sz" =~ ^[0-9]+$ ]] && (( sz > 102400 )) && return 1
    local -a dp=(
        'eval[[:space:]]' 'eval$' '\bexec[[:space:]]' '\bexec$'
        'bash[[:space:]]+-c' 'sh[[:space:]]+-c'
        '/dev/tcp' '/dev/udp' '\bnc\b.*-[el]' '\bnetcat\b' '\bsocat\b' '\btelnet\b'
        'curl.*\|.*bash' 'curl.*\|.*sh' 'wget.*\|.*bash' 'wget.*\|.*sh'
        '\bsource[[:space:]]+\$' '\.\s+\$' '\$\{!.*\}' 'printf[[:space:]]+-v'
        '\bdd[[:space:]]' '\bmkfifo\b'
        '\bchmod[[:space:]]+[0-7]*777' '\bchown\b' '\bsudo\b' '\bsu[[:space:]]'
        '\brm[[:space:]]+-rf[[:space:]]+/'
        'GITHUB_TOKEN' 'SHODAN_KEY' 'CHAOS_KEY' 'CENSYS_API' 'SPYSE_API'
        'GITLAB_TOKEN' 'SECURITYTRAILS_KEY' 'api_tokens'
        '\btrap\b.*EXIT' '\btrap\b.*ERR' '\bkill\b' '\bkillall\b'
        'export[[:space:]]+PATH=' 'export[[:space:]]+LD_'
        'HISTFILE' 'BASH_ENV' 'ENV=' 'PROMPT_COMMAND'
        '\bpython[23]?\b.*-c' '\bperl\b.*-e' '\bruby\b.*-e' '\bnode\b.*-e' '\bphp\b.*-r'
        'base64.*-d.*\|' '\\x[0-9a-fA-F]'
        '\bcrontab\b' '\bsystemctl\b' '\bservice[[:space:]]'
        '\bdocker\b' '\bkubectl\b' '\bdisown\b' '\bnohup\b'
        '/proc/self' '/proc/[0-9]' 'declare[[:space:]]+-x'
        '\bmapfile\b' '\breadarray\b' '\bcompgen\b' '\bcomplete\b'
        '\benable\b' '\bbuiltin\b' '\breadonly[[:space:]]+-f'
        '\bcommand[[:space:]]+-p' '<\(' '>\('
        '\bset[[:space:]]+[+-][ueopx]'
        '"ev""al"' "\$'\\\\x" '${BASH_ALIASES'
        'declare[[:space:]]+-f[[:space:]]+>' 'read.*\$'
        '<<.*\|[[:space:]]*bash' '<<.*\|[[:space:]]*sh'
        '\bxargs.*-I.*sh\b'
        '/etc/shadow' '/etc/passwd' '/etc/hosts'
        '\bcat\b.*\bshadow\b' '\bcat\b.*\bpasswd\b'
        '\$\{[a-zA-Z_]*\!.*\}' '\benv\b[[:space:]]' '\bprintenv\b'
        '/proc/self/environ'
    )
    local pat
    for pat in "${dp[@]}"; do
        if grep -v '^\s*#' "$pf" 2>/dev/null | grep -qE "$pat" 2>/dev/null; then
            log "WARNING" "[plugin] Blocked (${pat:0:25}): $pname"; return 1
        fi
    done
    return 0
}

_extract_plugin_function() {
    local pf="$1" fn_name="$2" out_file="$3"
    awk -v fn="$fn_name" '
    BEGIN { found=0; braces=0; started=0 }
    {
        if (!found && $0 ~ fn "[[:space:]]*\\(\\)[[:space:]]*\\{?") {
            found=1; if ($0 ~ /\{/) { braces=1; started=1 }; print; next
        }
        if (found && !started && $0 ~ /\{/) { braces=1; started=1; print; next }
        if (found && started) {
            print; n=gsub(/\{/,"{"); braces+=n; n=gsub(/\}/,"}"); braces-=n
            if (braces <= 0) exit
        }
    }' "$pf" > "$out_file" 2>/dev/null
    [[ -s "$out_file" ]]
}

_run_plugin_sandboxed() {
    local pf="$1" hook="$2" od="${3:-}"
    local hook_clean="${hook//[^a-zA-Z0-9_]/}"
    [[ "$hook_clean" != "$hook" ]] && return 1
    local fn_name="plugin_${hook_clean}"
    local extracted; extracted=$(_mktmp pext) || return 1
    if _extract_plugin_function "$pf" "$fn_name" "$extracted"; then
        (
            unset GITHUB_TOKEN CHAOS_KEY GITLAB_TOKEN SHODAN_KEY \
                  CENSYS_API_ID CENSYS_API_SECRET SPYSE_API_TOKEN \
                  SECURITYTRAILS_KEY NOTIFY_WEBHOOK NOTIFY_BOT_TOKEN
            unset BASH_ENV ENV PROMPT_COMMAND
            export PATH="/usr/local/bin:/usr/bin:/bin"
            if [[ "$IS_MACOS" == true ]]; then ulimit -f 204800 2>/dev/null || true
            else ulimit -f 104857600 2>/dev/null || true; fi
            ulimit -v 1048576 2>/dev/null || true
            ulimit -t 300 2>/dev/null || true
            source "$extracted"
            if declare -f "$fn_name" &>/dev/null; then
                if [[ -n "$od" ]]; then "$fn_name" "$od"; else "$fn_name"; fi
            fi
        ) || log "WARNING" "[plugin] Failed: $(basename "$pf" .sh)::$hook"
    fi
    rm -f "$extracted"
}

load_plugins() {
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a pl=("${PLUGIN_DIR}"/*.sh); eval "$sv"
    (( ${#pl[@]} == 0 )) && return 0
    log "INFO" "Loading ${#pl[@]} plugin(s)"
    local pf
    for pf in "${pl[@]}"; do
        [[ -f "$pf" && -r "$pf" ]] || continue
        _plugin_is_safe "$pf" || continue
        _run_plugin_sandboxed "$pf" "init" ""
        log "SUCCESS" "Plugin: $(basename "$pf" .sh)"
    done
}

run_plugins() {
    local hook="$1" od="$2"
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a pl=("${PLUGIN_DIR}"/*.sh); eval "$sv"
    (( ${#pl[@]} == 0 )) && return 0
    local pf
    for pf in "${pl[@]}"; do
        [[ -f "$pf" && -r "$pf" ]] || continue
        _plugin_is_safe "$pf" || continue
        _run_plugin_sandboxed "$pf" "$hook" "$od"
    done
}

create_plugin_template() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || { log "ERROR" "Bad name"; return 1; }
    local pf="${PLUGIN_DIR}/${name}.sh"
    [[ -f "$pf" ]] && { log "ERROR" "Exists"; return 1; }
    printf '#!/usr/bin/env bash\nplugin_init() { log "INFO" "Plugin: %s"; }\nplugin_post_passive() { local od="$1"; }\nplugin_post_active() { local od="$1"; }\nplugin_post_scan() { local od="$1"; }\nplugin_report() { local od="$1"; }\n' "$name" > "$pf"
    chmod 600 "$pf"; log "SUCCESS" "Template: $pf"
}

# ══════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════
_sql_escape() {
    local input="$1"
    [[ -z "$input" ]] && { printf ''; return 0; }
    input=$(printf '%s' "$input" | tr -d '\0' | tr -cd '[:print:]')
    input="${input//\'/\'\'}"
    input=$(printf '%s' "$input" | tr -cd 'a-zA-Z0-9._ @,:-')
    (( ${#input} > 1024 )) && input="${input:0:1024}"
    printf '%s' "$input"
}

_sql_int() {
    local val="${1:-0}"; val="${val//[[:space:]]/}"
    [[ "$val" =~ ^[0-9]+$ ]] && printf '%s' "$val" || printf '0'
}

db_init() {
    [[ "$DB_EXPORT" != true ]] && return 0
    command -v sqlite3 &>/dev/null || { log "WARNING" "sqlite3 missing"; DB_EXPORT=false; return 0; }
    local db="${DB_DIR}/then0thing.db"
    ( umask 077; touch "$db" 2>/dev/null )
    if [[ ! -s "$db" ]] || ! sqlite3 "$db" "SELECT 1 FROM scans LIMIT 1;" 2>/dev/null; then
        sqlite3 "$db" << 'SQL'
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL, target_type TEXT NOT NULL,
    start_time TEXT NOT NULL, end_time TEXT, duration INTEGER,
    subdomains INTEGER DEFAULT 0, ips INTEGER DEFAULT 0,
    asns INTEGER DEFAULT 0, cidrs INTEGER DEFAULT 0,
    live_urls INTEGER DEFAULT 0, open_ports INTEGER DEFAULT 0,
    vulnerabilities INTEGER DEFAULT 0, errors INTEGER DEFAULT 0,
    warnings INTEGER DEFAULT 0, output_dir TEXT, profile TEXT,
    status TEXT DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER, asset_type TEXT NOT NULL,
    value TEXT NOT NULL, first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id),
    UNIQUE(asset_type,value)
);
CREATE INDEX IF NOT EXISTS idx_at ON assets(asset_type);
SQL
        log "SUCCESS" "DB: $db"
    fi
}

db_start_scan() {
    [[ "$DB_EXPORT" != true ]] && return 0
    local db="${DB_DIR}/then0thing.db"
    local st stt sp
    st=$(_sql_escape "$1"); stt=$(_sql_escape "$2"); sp=$(_sql_escape "${3:-default}")
    sqlite3 "$db" "INSERT INTO scans(target,target_type,start_time,profile,status) \
        VALUES('$st','$stt',datetime('now'),'$sp','running')" 2>/dev/null || return 0
    local sid; sid=$(sqlite3 "$db" "SELECT last_insert_rowid()" 2>/dev/null) || return 0
    [[ "$sid" =~ ^[0-9]+$ ]] && printf '%s' "$sid"
}

db_end_scan() {
    [[ "$DB_EXPORT" != true ]] && return 0
    local scan_id="$1" od="$2" db="${DB_DIR}/then0thing.db"
    scan_id=$(_sql_int "$scan_id"); (( scan_id == 0 )) && return 0
    _sync_counters
    local now_epoch; now_epoch=$(date +%s 2>/dev/null) || now_epoch=$START_EPOCH
    local el=$(( now_epoch - START_EPOCH )); (( el < 0 )) && el=0
    local ns ni na nc nu np nv
    ns=$(_sql_int "$(_safe_count "$od/assets/subdomains/all.txt")")
    ni=$(_sql_int "$(_safe_count "$od/assets/ips/all.txt")")
    na=$(_sql_int "$(_safe_count "$od/assets/asns/all.txt")")
    nc=$(_sql_int "$(_safe_count "$od/assets/cidrs/all.txt")")
    nu=$(_sql_int "$(_safe_count "$od/processed/all_urls.txt")")
    np=$(_sql_int "$(_safe_count "$od/processed/open_ports.txt")")
    nv=0; [[ -f "$od/processed/nuclei_results.txt" ]] && \
        nv=$(_sql_int "$(_safe_count "$od/processed/nuclei_results.txt")")
    local so; so=$(_sql_escape "$od")
    sqlite3 "$db" "UPDATE scans SET end_time=datetime('now'),duration=$el,\
        subdomains=$ns,ips=$ni,asns=$na,cidrs=$nc,live_urls=$nu,open_ports=$np,\
        vulnerabilities=$nv,errors=$(_sql_int "$ERROR_COUNT"),\
        warnings=$(_sql_int "$WARNING_COUNT"),output_dir='$so',\
        status='complete' WHERE id=$scan_id" 2>/dev/null || true
}

db_import_assets() {
    [[ "$DB_EXPORT" != true ]] && return 0
    local scan_id="$1" od="$2" db="${DB_DIR}/then0thing.db"
    scan_id=$(_sql_int "$scan_id"); (( scan_id == 0 )) && return 0
    local now; now=$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)
    local sn; sn=$(_sql_escape "$now")
    local at file
    for at in subdomain ip asn cidr; do
        case "$at" in
            subdomain) file="$od/assets/subdomains/all.txt" ;;
            ip) file="$od/assets/ips/all.txt" ;;
            asn) file="$od/assets/asns/all.txt" ;;
            cidr) file="$od/assets/cidrs/all.txt" ;;
        esac
        [[ -s "$file" ]] || continue
        local sa; sa=$(_sql_escape "$at")
        local sql_file; sql_file=$(_mktmp sqlbatch) || continue
        printf 'PRAGMA journal_mode=WAL;\nPRAGMA synchronous=NORMAL;\nBEGIN TRANSACTION;\n' > "$sql_file"
        local lc=0 line max_import=50000
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            (( lc >= max_import )) && { log "WARNING" "[db] $at capped at $max_import"; break; }
            case "$at" in
                subdomain) [[ "$line" =~ ^[a-zA-Z0-9.\-]+$ ]] || continue ;;
                ip) validate_ip "$line" || continue ;;
                asn) validate_asn "$line" || continue ;;
                cidr) [[ "$line" =~ ^[0-9./]+$ ]] || continue ;;
            esac
            local sl; sl=$(_sql_escape "$line")
            printf "INSERT INTO assets(scan_id,asset_type,value,first_seen,last_seen) VALUES(%s,'%s','%s','%s','%s') ON CONFLICT(asset_type,value) DO UPDATE SET last_seen='%s',scan_id=%s;\n" \
                "$scan_id" "$sa" "$sl" "$sn" "$sn" "$sn" "$scan_id" >> "$sql_file"
            (( ++lc ))
            (( lc % 1000 == 0 )) && printf 'COMMIT;\nBEGIN TRANSACTION;\n' >> "$sql_file"
        done < "$file"
        if (( lc > 0 )); then
            printf 'COMMIT;\n' >> "$sql_file"
            _ptimeout 120 sqlite3 "$db" < "$sql_file" 2>/dev/null || \
                log "WARNING" "[db] Import failed: $at"
            log "DEBUG" "[db] Imported $lc $at"
        fi
        rm -f "$sql_file"
    done
}

db_query() {
    local query="$1" db="${DB_DIR}/then0thing.db"
    [[ -f "$db" ]] || { log "ERROR" "No DB"; return 1; }
    local cq; cq=$(printf '%s' "$query" | tr -d '\0')
    cq=$(printf '%s' "$cq" | sed -e 's/--.*$//' -e ':a;s|/\*[^*]*\*/||g;ta')
    cq="${cq//;/ }"
    local uq; uq=$(printf '%s' "$cq" | tr '[:lower:]' '[:upper:]' | sed 's/^[[:space:]]*//')
    [[ "$uq" =~ ^SELECT[[:space:]] ]] || { log "ERROR" "Only SELECT"; return 1; }
    local -a blocked=(
        INSERT UPDATE DELETE DROP ALTER CREATE ATTACH DETACH REPLACE
        PRAGMA VACUUM REINDEX LOAD_EXTENSION RETURNING
        SQLITE_MASTER SQLITE_SCHEMA READFILE WRITEFILE FOPEN
    )
    local bw; for bw in "${blocked[@]}"; do
        [[ "$uq" =~ (^|[[:space:]]|[\(\)])${bw}([[:space:]]|[\(\)]|$) ]] && {
            log "ERROR" "Blocked: $bw"; return 1; }
    done
    [[ "$cq" =~ ^\. ]] && { log "ERROR" "Dot-commands blocked"; return 1; }
    sqlite3 -header -column -readonly "$db" "$cq" 2>/dev/null || \
        sqlite3 -header -column "$db" "$cq" 2>/dev/null
}

db_show_history() {
    db_query "SELECT id,target,target_type,start_time,duration||'s' as dur,subdomains,live_urls,status FROM scans ORDER BY id DESC LIMIT 20"
}

db_show_assets() {
    local at="${1:-subdomain}"
    case "$at" in subdomain|ip|asn|cidr) ;; *) log "ERROR" "Bad type"; return 1 ;; esac
    db_query "SELECT value,first_seen,last_seen FROM assets WHERE asset_type='$at' ORDER BY last_seen DESC LIMIT 50"
}

# ══════════════════════════════════════════
# UPDATE & SCHEDULE
# ══════════════════════════════════════════
check_update() {
    [[ "$AUTO_UPDATE" != true ]] && return 0
    log "INFO" "Checking updates..."
    local rv
    rv=$(_ptimeout 15 curl -fsS --max-time 10 --max-filesize "$MAX_RESPONSE_SIZE" \
        "$UPDATE_URL" 2>/dev/null | grep -oP 'VERSION="\K[^"]+' | head -1) || return 0
    [[ -z "$rv" || ! "$rv" =~ ^[0-9]+\.[0-9]+$ ]] && return 0
    [[ "$rv" != "$VERSION" ]] && log "WARNING" "Update: v$VERSION->v$rv" || log "SUCCESS" "Latest"
}

self_update() {
    log "INFO" "Downloading..."
    local sp="${BASH_SOURCE[0]}"
    [[ -L "$sp" ]] && sp=$(readlink -f "$sp" 2>/dev/null || realpath "$sp" 2>/dev/null)
    [[ -w "$sp" ]] || { log "ERROR" "Not writable"; return 1; }
    cp -- "$sp" "${sp}.backup.$(date +%s)" || return 1
    local tf cf; tf=$(_mktmp upd) || return 1
    cf=$(_mktmp chk) || { rm -f "$tf"; return 1; }
    _ptimeout 120 curl -fsS --max-time 60 --max-filesize "$MAX_RESPONSE_SIZE" \
        "$UPDATE_URL" > "$tf" 2>/dev/null || { rm -f "$tf" "$cf"; return 1; }
    head -1 "$tf" | grep -q '#!/usr/bin/env bash' || { rm -f "$tf" "$cf"; return 1; }
    local verified=false
    if _ptimeout 15 curl -fsS --max-time 10 --max-filesize 1024 \
        "${UPDATE_URL}.sha256" > "$cf" 2>/dev/null && [[ -s "$cf" ]]; then
        local eh ah=""
        eh=$(awk '{print $1}' "$cf" 2>/dev/null)
        command -v sha256sum &>/dev/null && ah=$(sha256sum "$tf" | awk '{print $1}')
        command -v shasum &>/dev/null && [[ -z "$ah" ]] && ah=$(shasum -a 256 "$tf" | awk '{print $1}')
        [[ -n "$eh" && -n "$ah" ]] && {
            [[ "$eh" == "$ah" ]] && verified=true || { rm -f "$tf" "$cf"; return 1; }
        }
    fi
    [[ "$verified" != true ]] && {
        [[ ! -t 0 ]] && { log "ERROR" "No checksum + non-interactive"; rm -f "$tf" "$cf"; return 1; }
        printf '%bNo checksum. Continue? [y/N]: %b' "$C_YELLOW" "$C_RESET" >&2
        local r; IFS= read -r r
        [[ "$r" =~ ^[yY]$ ]] || { rm -f "$tf" "$cf"; return 1; }
    }
    local nv; nv=$(grep -oP 'VERSION="\K[^"]+' "$tf" | head -1)
    if [[ -n "$nv" && "$nv" =~ ^[0-9]+\.[0-9]+$ ]]; then
        mv -- "$tf" "$sp"; chmod +x "$sp"; rm -f "$cf"
        log "SUCCESS" "v$VERSION->v$nv"; exit 0
    fi
    rm -f "$tf" "$cf"; return 1
}

setup_schedule() {
    local expr="$1" target="$2" opts="${3:-}"
    [[ -z "$expr" || -z "$target" ]] && return 1
    command -v crontab &>/dev/null || return 1
    local st; st=$(sanitize_target "$target") || return 1
    local tt; tt=$(detect_type "$st"); [[ "$tt" == unknown ]] && return 1
    local -a cron_fields; read -ra cron_fields <<< "$expr"
    (( ${#cron_fields[@]} == 5 )) || { log "ERROR" "Invalid cron: need 5 fields"; return 1; }
    local cf; for cf in "${cron_fields[@]}"; do
        [[ "$cf" =~ ^[0-9*/,-]+$ ]] || { log "ERROR" "Invalid cron field: $cf"; return 1; }
    done
    [[ -n "$opts" ]] && { [[ "$opts" =~ ^[a-zA-Z0-9\ _./-]+$ ]] || {
        log "ERROR" "Invalid options"; return 1; }; }
    local sp; sp=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")
    [[ -x "$sp" ]] || return 1
    local cl="${expr} ${sp} ${target} ${opts} --no-color >> ${LOG_DIR}/scheduled.log 2>&1"
    local sid; sid=$(_hash_string "${target}_${expr}" | cut -c1-8)
    printf 'TARGET=%s\nSCHEDULE=%s\nOPTIONS=%s\nCREATED=%s\n' \
        "$target" "$expr" "$opts" "$(date -Iseconds 2>/dev/null)" > "${SCHEDULE_DIR}/${sid}.conf"
    (crontab -l 2>/dev/null | grep -v "# then0thing:${sid}"; \
     printf '%s # then0thing:%s\n' "$cl" "$sid") | crontab - 2>/dev/null || {
        rm -f "${SCHEDULE_DIR}/${sid}.conf"; return 1; }
    log "SUCCESS" "Scheduled: $target ID:$sid"
}

list_schedules() {
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a sc=("${SCHEDULE_DIR}"/*.conf); eval "$sv"
    (( ${#sc[@]} == 0 )) && { log "INFO" "None"; return 0; }
    printf '%b%-10s %-30s %-20s%b\n' "$C_BOLD" "ID" "TARGET" "SCHEDULE" "$C_RESET" >&2
    local sf; for sf in "${sc[@]}"; do
        printf '%-10s %-30s %-20s\n' "$(basename "$sf" .conf)" \
            "$(grep '^TARGET=' "$sf" 2>/dev/null | cut -d= -f2-)" \
            "$(grep '^SCHEDULE=' "$sf" 2>/dev/null | cut -d= -f2-)" >&2
    done
}

remove_schedule() {
    local sid="$1"; [[ "$sid" =~ ^[a-f0-9]+$ ]] || return 1
    [[ -f "${SCHEDULE_DIR}/${sid}.conf" ]] || return 1
    (crontab -l 2>/dev/null | grep -v "then0thing:${sid}") | crontab - 2>/dev/null || true
    rm -f "${SCHEDULE_DIR}/${sid}.conf"; log "SUCCESS" "Removed: $sid"
}
# ══════════════════════════════════════════
# CACHE SYSTEM
# ══════════════════════════════════════════
_cpath() { printf '%s/%s.cache' "$CACHE_DIR" "$(_hash_string "$1")"; }
_mtime() {
    local r; r=$(_stat_field '%Y' '%m' "$1" '0')
    printf '%s' "${r:-0}"
}
cache_get() {
    local cf; cf=$(_cpath "$1")
    [[ -f "$cf" ]] || return 1
    (( ($(date +%s) - $(_mtime "$cf")) / 86400 > CACHE_EXPIRY )) && { rm -f -- "$cf"; return 1; }
    cat -- "$cf"
}
cache_set() {
    local cf; cf=$(_cpath "$1")
    if [[ $# -ge 2 ]]; then
        local t; t=$(_mktmp c) || return 1
        printf '%s' "$2" > "$t"
        mv -- "$t" "$cf" 2>/dev/null || rm -f -- "$t"
    else
        local t; t=$(_mktmp c) || return 1
        head -c "$((MAX_CACHE_SZ + 1))" > "$t" 2>/dev/null || true
        if [[ ! -s "$t" ]]; then rm -f -- "$t"; return 1; fi
        local sz; sz=$(wc -c < "$t" 2>/dev/null); sz="${sz//[[:space:]]/}"
        [[ "$sz" =~ ^[0-9]+$ ]] && (( sz > MAX_CACHE_SZ )) && { rm -f -- "$t"; return 1; }
        mv -- "$t" "$cf" 2>/dev/null || rm -f -- "$t"
    fi
}
cache_purge() {
    find "$CACHE_DIR" -name '*.cache' -mtime +"$CACHE_EXPIRY" -delete 2>/dev/null || true
    local total_cache
    total_cache=$(du -sk "$CACHE_DIR" 2>/dev/null | awk '{print $1}')
    total_cache="${total_cache//[[:space:]]/}"
    [[ "$total_cache" =~ ^[0-9]+$ ]] || return 0
    (( total_cache > MAX_CACHE_SZ / 1024 )) && {
        log "WARNING" "[cache] Large (${total_cache}KB), purging old"
        find "$CACHE_DIR" -name '*.cache' -type f -mtime +1 -delete 2>/dev/null || true
    }
}

# ══════════════════════════════════════════
# LOG ROTATION & DEPS
# ══════════════════════════════════════════
rotate_logs() {
    local mx="$MAX_LOGS" ll=""
    if [[ "$IS_MACOS" == true ]]; then
        ll=$(find "$LOG_DIR" -name "${SCRIPT_NAME}_*.log" -type f \
             -exec stat -f '%m %N' {} \; 2>/dev/null | sort -rn) || true
    else
        ll=$(find "$LOG_DIR" -name "${SCRIPT_NAME}_*.log" -type f \
             -printf '%T@ %p\n' 2>/dev/null | sort -rn) || true
    fi
    [[ -z "$ll" ]] && return 0
    local c; c=$(printf '%s\n' "$ll" | wc -l); c="${c//[[:space:]]/}"
    [[ "$c" =~ ^[0-9]+$ ]] && (( c > mx )) && \
        printf '%s\n' "$ll" | tail -n "$((c - mx))" | awk '{print $2}' | \
        while IFS= read -r fp; do rm -f -- "$fp"; done
}

check_deps() {
    local -a m=() om=()
    local -a rq=(httpx jq curl)
    local -a op=(
        subfinder amass assetfinder findomain puredns whois asnmap dig dnsx
        mapcidr naabu massdns ipinfo gowitness aquatone subjack gospider
        sublist3r rapiddns-cli nuclei wafw00f webanalyze whatweb sqlite3
        github-subdomains chaos split
    )
    local t
    for t in "${rq[@]}"; do command -v "$t" &>/dev/null || m+=("$t"); done
    for t in "${op[@]}"; do command -v "$t" &>/dev/null || om+=("$t"); done
    (( ${#m[@]} )) && { log "ERROR" "[deps] Missing: $(printf '%s ' "${m[@]}")"; return 1; }
    (( ${#om[@]} )) && log "WARNING" "[deps] Optional: $(printf '%s ' "${om[@]}")"
    log "SUCCESS" "${#rq[@]} required + $((${#op[@]} - ${#om[@]})) optional OK"
}

# ══════════════════════════════════════════
# PARALLEL EXECUTION
# ══════════════════════════════════════════
run_critical() {
    local lb="$1"; shift
    local rc=0; "$@" || rc=$?
    [[ $rc -eq 0 ]] && return 0
    _error_count; _sync_counters
    log "ERROR" "[$lb] rc=$rc"
    (( ERROR_COUNT > 20 )) && { log "CRITICAL" "Aborting"; _cleanup; exit 1; }
    return "$rc"
}

_prune() {
    (( ${#CHILD_PIDS[@]} )) || return 0
    local -a a=(); local p
    for p in "${CHILD_PIDS[@]}"; do kill -0 "$p" 2>/dev/null && a+=("$p"); done
    CHILD_PIDS=("${a[@]+"${a[@]}"}")
}

_killch() {
    (( ${#CHILD_PIDS[@]} )) || return 0
    local p
    for p in "${CHILD_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    _safe_sleep 0.5
    for p in "${CHILD_PIDS[@]}"; do kill -9 "$p" 2>/dev/null || true; done
    CHILD_PIDS=()
}

_cleanup() {
    [[ "$_CLEANED_UP" == true ]] && return 0
    [[ "$_CLEANING_UP" == true ]] && return 0
    _CLEANING_UP=true
    _killch; _safe_sleep 0.3; _sync_counters
    local now_epoch; now_epoch=$(date +%s 2>/dev/null) || now_epoch=$START_EPOCH
    local el=$(( now_epoch - START_EPOCH )); (( el < 0 )) && el=0
    log "INFO" "${el}s | E:$ERROR_COUNT W:$WARNING_COUNT"
    local _lk
    for _lk in "${!_LOCK_FDS[@]}"; do _close_fd "${_LOCK_FDS[$_lk]}"; done
    _LOCK_FDS=()
    for _lk in "${ACQUIRED_LOCKS[@]+"${ACQUIRED_LOCKS[@]}"}"; do rm -rf "$_lk" 2>/dev/null || true; done
    ACQUIRED_LOCKS=()
    _clean_token_files
    [[ -d "${TEMP_DIR:-}" ]] && rm -rf "$TEMP_DIR" 2>/dev/null || true
    _CLEANED_UP=true; _CLEANING_UP=false
}
trap '_cleanup' EXIT
trap 'trap "" INT TERM; log "WARNING" "Interrupted"; exit 130' INT TERM

readonly _SEP="__PSEP_a7f3b2e1__"

run_par() {
    local _a
    for _a in "$@"; do
        [[ "$_a" == "$_SEP" ]] && continue
        [[ "$_a" == *"$_SEP"* ]] && return 1
    done
    local -a pids=() cur=() _alive=()
    local mj=$MAX_PAR_JOBS fail=0 _np _p a
    local all=("$@" "$_SEP") prune_counter=0
    for a in "${all[@]}"; do
        if [[ "$a" == "$_SEP" ]]; then
            (( ${#cur[@]} )) || continue
            while (( ${#pids[@]} >= mj )); do
                wait -n 2>/dev/null || true; _alive=()
                for _p in "${pids[@]}"; do
                    if kill -0 "$_p" 2>/dev/null; then _alive+=("$_p")
                    else wait "$_p" 2>/dev/null || ((fail++)) || true; _remove_child_pid "$_p"; fi
                done
                pids=("${_alive[@]+"${_alive[@]}"}")
                (( ${#pids[@]} < mj )) && break
            done
            "${cur[@]}" &
            _np=$!; pids+=("$_np"); CHILD_PIDS+=("$_np"); cur=()
            (( ++prune_counter % 20 == 0 )) && _prune
        else cur+=("$a"); fi
    done
    for _p in "${pids[@]+"${pids[@]}"}"; do
        wait "$_p" 2>/dev/null || ((fail++)) || true; _remove_child_pid "$_p"
    done
    _sync_counters; (( fail )) && _warn_count; return 0
}

_par_sort() {
    local -a sp=(); local f
    for f in "$@"; do
        [[ -f "$f" ]] || continue
        _sort_inplace "$f" &
		sp+=($!)
		CHILD_PIDS+=($!)
    done
    local p; for p in "${sp[@]+"${sp[@]}"}"; do
        wait "$p" 2>/dev/null || true; _remove_child_pid "$p"
    done
}

_TERM_WIDTH=""
_get_term_width() {
    [[ -z "$_TERM_WIDTH" ]] && {
        _TERM_WIDTH=$(tput cols 2>/dev/null) || _TERM_WIDTH=80
        [[ "$_TERM_WIDTH" =~ ^[0-9]+$ ]] || _TERM_WIDTH=80
    }; printf '%s' "$_TERM_WIDTH"
}

show_prog() {
    local c="$1" t="$2" lb="${3:-Progress}"
    [[ "$c" =~ ^-?[0-9]+$ && "$t" =~ ^[0-9]+$ ]] || return 0
    (( t <= 0 )) && return 0
    (( c < 0 )) && c=0; (( c > t )) && c=$t
    local tw; tw=$(_get_term_width)
    local oh=$(( ${#lb} + ${#c} + ${#t} + 15 ))
    local w=$(( tw - oh ))
    (( w < 10 )) && w=10; (( w > 60 )) && w=60
    local pc=$((c * 100 / t)) 
	local fl=$((w * c / t)) 
	local em=$((w - fl))
    local bf="" be=""
    (( fl > 0 )) && { printf -v bf '%*s' "$fl" ''; bf="${bf// /=}"; }
    (( em > 0 )) && { printf -v be '%*s' "$em" ''; be="${be// /-}"; }
    printf "\r\033[K%b%s [%s%s] %d/%d (%d%%)%b" \
        "$C_CYAN" "$lb" "$bf" "$be" "$c" "$t" "$pc" "$C_RESET" >&2
    (( c == t )) && printf '\n' >&2
}

retry() {
    local mx="${MAX_RETRIES:-3}" dl=2 at=1
    while (( at <= mx )); do
        local rc=0; "$@" && return 0 || rc=$?
        case "$rc" in 2|126|127) return "$rc" ;; esac
        log "WARNING" "[retry] $at/$mx rc=$rc: $1"
        ((at++)); sleep "$dl"; ((dl *= 2)); ((dl > 60)) && dl=60
    done; _warn_count; return 1
}

retry_t() {
    local tm="$1"; shift
    local mx="${MAX_RETRIES:-3}" dl=2 at=1
    while (( at <= mx )); do
        local rc=0; _ptimeout "$tm" "$@" || rc=$?
        [[ $rc -eq 0 ]] && return 0
        case "$rc" in 2|126|127) return "$rc" ;; esac
        ((at++)); sleep "$dl"; ((dl *= 2)); ((dl > 60)) && dl=60
    done; _warn_count; return 1
}

# ══════════════════════════════════════════
# SMART BATCH SYSTEM (مشكلة 9: fallback محسّن)
# ══════════════════════════════════════════
_split_file() {
    local input_file="$1" batch_dir="$2" batch_size="$3" prefix="${4:-batch_}"
    mkdir -p "$batch_dir" 2>/dev/null
    [[ -f "$input_file" && -s "$input_file" ]] || return 1

    # Fallback 1: split (الأسرع)
    if command -v split &>/dev/null; then
        split -l "$batch_size" -d -a 3 \
            "$input_file" "${batch_dir}/${prefix}" 2>/dev/null && return 0
    fi

    # Fallback 2: awk (سريع كفاية)
    if command -v awk &>/dev/null; then
        awk -v bs="$batch_size" -v dir="$batch_dir" -v pfx="$prefix" '
        BEGIN { fn=0; cnt=0 }
        {
            if (cnt % bs == 0) { if (cnt > 0) close(outfile)
                outfile = sprintf("%s/%s%03d", dir, pfx, fn++) }
            print > outfile; cnt++
        }' "$input_file" 2>/dev/null && return 0
    fi

    # Fallback 3 (مشكلة 9): sed blocks بدل while read
    local total_lines
    total_lines=$(wc -l < "$input_file" 2>/dev/null)
    total_lines="${total_lines//[[:space:]]/}"
    [[ "$total_lines" =~ ^[0-9]+$ ]] || return 1
    (( total_lines == 0 )) && return 1

    local current_batch=0 start=1 end
    while (( start <= total_lines )); do
        end=$(( start + batch_size - 1 ))
        (( end > total_lines )) && end=$total_lines
        sed -n "${start},${end}p" "$input_file" \
            > "$(printf '%s/%s%03d' "$batch_dir" "$prefix" "$current_batch")" 2>/dev/null
        (( start = end + 1 ))
        (( current_batch++ ))
    done
}

# مشكلة 8: _run_batched مع retry + callback validation
_run_batched() {
    local input_file="$1" batch_size="$2" label="$3" callback="$4"
    shift 4
    local tc; tc=$(_safe_count "$input_file")
    (( tc == 0 )) && return 0

    # مشكلة 8: تحقق إن الـ callback معرّف
    if ! declare -F "$callback" &>/dev/null; then
        log "ERROR" "[$label] Callback '$callback' not defined"
        return 1
    fi

    if (( tc <= batch_size )); then
        log "INFO" "[$label] Processing $tc targets"
        # مشكلة 8: retry لو فشل
        local cb_rc=0
        "$callback" "$input_file" "$@" || cb_rc=$?
        if (( cb_rc != 0 )); then
            log "WARNING" "[$label] Failed (rc=$cb_rc), retrying..."
            _safe_sleep 2
            "$callback" "$input_file" "$@" || {
                log "WARNING" "[$label] Retry also failed"
                _warn_count
            }
        fi
        return 0
    fi

    local total_batches=$(( (tc + batch_size - 1) / batch_size ))
    local batch_num=0 batch_fails=0
    local batch_dir; batch_dir=$(_mktmp "${label}_bd") || return 1
    rm -f "$batch_dir"; mkdir -p "$batch_dir"
    log "INFO" "[$label] $tc targets → $total_batches batches (${batch_size}/batch)"
    _split_file "$input_file" "$batch_dir" "$batch_size" "${label}_"

    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a batch_files=("$batch_dir"/${label}_*); eval "$sv"
    if (( ${#batch_files[@]} == 0 )); then
        log "ERROR" "[$label] Split failed"; rm -rf "$batch_dir" 2>/dev/null; return 1
    fi

    local bf
    for bf in "${batch_files[@]}"; do
        ((batch_num++))
        local bc; bc=$(_safe_count "$bf"); (( bc == 0 )) && continue
        log "INFO" "[$label] Batch $batch_num/$total_batches ($bc targets)"
        show_prog "$batch_num" "$total_batches" "$label"

        # مشكلة 8: retry مرة واحدة لو فشل
        local cb_rc=0
        "$callback" "$bf" "$@" || cb_rc=$?
        if (( cb_rc != 0 )); then
            log "WARNING" "[$label] Batch $batch_num failed (rc=$cb_rc), retrying..."
            _safe_sleep 2
            "$callback" "$bf" "$@" || {
                ((batch_fails++))
                log "WARNING" "[$label] Batch $batch_num retry also failed"
            }
        fi

        if (( batch_fails > total_batches / 2 && batch_fails > 2 )); then
            log "ERROR" "[$label] Too many failures ($batch_fails/$batch_num)"; break
        fi
        _check_disk_ok "$batch_dir" || {
            log "WARNING" "[$label] Low disk at batch $batch_num"; break; }
        (( batch_num < total_batches )) && _safe_sleep 1
    done
    rm -rf "$batch_dir" 2>/dev/null
    (( batch_fails > 0 )) && { log "WARNING" "[$label] $batch_fails/$batch_num failed"; _warn_count; }
    log "SUCCESS" "[$label] Done ($batch_num batches)"
}

# ══════════════════════════════════════════
# ENUMERATION SOURCES
# ══════════════════════════════════════════
_en_sf() {
    command -v subfinder &>/dev/null || return 0
    local t; t=$(_mktmp sf) || return 0
    retry_t 120 subfinder -d "$1" -all -silent 2>/dev/null > "$t" || true
    sort -u -- "$t" > "$2/subfinder.txt" 2>/dev/null || true; rm -f -- "$t"
}
_en_am() {
    command -v amass &>/dev/null || return 0
    local t; t=$(_mktmp am) || return 0
    retry_t 300 amass enum -passive -norecursive -d "$1" 2>/dev/null > "$t" || true
    sort -u -- "$t" > "$2/amass.txt" 2>/dev/null || true; rm -f -- "$t"
}
_en_af() {
    command -v assetfinder &>/dev/null || return 0
    local t; t=$(_mktmp af) || return 0
    retry_t 120 assetfinder -subs-only "$1" 2>/dev/null > "$t" || true
    sort -u -- "$t" > "$2/assetfinder.txt" 2>/dev/null || true; rm -f -- "$t"
}
_en_fd() {
    command -v findomain &>/dev/null || return 0
    local t; t=$(_mktmp fd) || return 0
    retry_t 120 findomain -t "$1" -q 2>/dev/null > "$t" || true
    sort -u -- "$t" > "$2/findomain.txt" 2>/dev/null || true; rm -f -- "$t"
}
_en_crt() {
    local dom="$1" rd="$2"
    [[ "$dom" =~ ^[a-zA-Z0-9.\-]+$ ]] || { touch "$rd/crtsh.txt"; return 0; }
    local t; t=$(_mktmp cr) || { touch "$rd/crtsh.txt"; return 0; }
    local encoded_dom; encoded_dom=$(_url_encode "$dom")
    local mx=3 dl=5 at=1
    while (( at <= mx )); do
        _ptimeout 120 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 60 \
            "https://crt.sh/?q=%25.${encoded_dom}&output=json" > "$t" 2>/dev/null && break
        ((at++)); sleep "$dl"; ((dl *= 3)); ((dl > 60)) && dl=60
    done
    if [[ -s "$t" ]]; then
        local fc; fc=$(head -c 1 "$t" 2>/dev/null)
        [[ "$fc" == "[" ]] || { rm -f -- "$t"; touch "$rd/crtsh.txt"; return 0; }
        local p; p=$(_mktmp cp) || { rm -f -- "$t"; touch "$rd/crtsh.txt"; return 0; }
        if _safe_jq "$p" "$t" -r 'try .[].name_value catch empty' && [[ -s "$p" ]]; then
            sed 's/\*\.//g' "$p" | \
                grep -E '^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,63}$' | \
                sort -u > "$rd/crtsh.txt" 2>/dev/null || true
        else touch "$rd/crtsh.txt"; fi
        rm -f -- "$p"
    fi
    [[ -f "$rd/crtsh.txt" ]] || touch "$rd/crtsh.txt"; rm -f -- "$t"
}
_en_gh() {
    [[ -z "${GITHUB_TOKEN:-}" ]] && return 0
    command -v github-subdomains &>/dev/null || return 0
    local t; t=$(_mktmp gh) || return 0
    local tf; tf=$(_write_token_file "github" "$GITHUB_TOKEN") || return 0
    ( local _tok; _tok=$(<"$tf"); exec env GITHUB_TOKEN="$_tok" github-subdomains -d "$1" -raw
    ) > "$t" 2>/dev/null || true
    rm -f "$tf"; [[ -s "$t" ]] && sort -u -- "$t" > "$2/github.txt" || touch "$2/github.txt"
    rm -f -- "$t"
}
_en_ch() {
    [[ -z "${CHAOS_KEY:-}" ]] && return 0
    command -v chaos &>/dev/null || return 0
    local t; t=$(_mktmp ch) || return 0
    local tf; tf=$(_write_token_file "chaos" "$CHAOS_KEY") || return 0
    ( local _tok; _tok=$(<"$tf"); exec env PDCP_API_KEY="$_tok" chaos -d "$1" -silent
    ) > "$t" 2>/dev/null || true
    rm -f "$tf"; [[ -s "$t" ]] && sort -u -- "$t" > "$2/chaos.txt" || touch "$2/chaos.txt"
    rm -f -- "$t"
}
_en_rd() {
    command -v rapiddns-cli &>/dev/null || return 0
    validate_domain "$1" || return 0
    local t; t=$(_mktmp rd) || return 0
    retry_t 120 rapiddns-cli search "http://$1" --column subdomain -o text 2>/dev/null > "$t" || true
    [[ -s "$t" ]] && sort -u -- "$t" > "$2/rapiddns.txt" || touch "$2/rapiddns.txt"
    rm -f -- "$t"
}

# ══════════════════════════════════════════
# SecurityTrails API
# ══════════════════════════════════════════
_en_sectrails() {
    [[ -z "${SECURITYTRAILS_KEY:-}" ]] && return 0
    local dom="$1" rd="$2"
    validate_domain "$dom" || { touch "$rd/securitytrails.txt"; return 0; }
    log "DEBUG" "[sectrails] Querying: $dom"
    local tf; tf=$(_write_token_file "sectrails" "$SECURITYTRAILS_KEY") || {
        touch "$rd/securitytrails.txt"; return 0; }
    local _tok; _tok=$(_read_token_file "$tf") || {
        rm -f "$tf"; touch "$rd/securitytrails.txt"; return 0; }
    local encoded_dom; encoded_dom=$(_url_encode "$dom")

    # Subdomains
    local t_s; t_s=$(_mktmp sts) || { rm -f "$tf"; touch "$rd/securitytrails.txt"; return 0; }
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        -H "APIKEY: ${_tok}" \
        "https://api.securitytrails.com/v1/domain/${encoded_dom}/subdomains?children_only=false&include_inactive=true" \
        > "$t_s" 2>/dev/null
    if [[ -s "$t_s" ]]; then
        local fc; fc=$(head -c 1 "$t_s" 2>/dev/null)
        if [[ "$fc" == "{" ]]; then
            local err; err=$(jq -r '.message // empty' "$t_s" 2>/dev/null)
            if [[ -n "$err" ]]; then log "WARNING" "[sectrails] $err"
            else
                local p; p=$(_mktmp stsp) || true
                [[ -n "$p" ]] && _safe_jq "$p" "$t_s" -r '.subdomains[]? // empty' && [[ -s "$p" ]] && {
                    sed "s/$/.$dom/" "$p" | \
                        grep -E '^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,63}$' | \
                        sort -u > "$rd/securitytrails.txt" 2>/dev/null
                    log "SUCCESS" "[sectrails] $(_safe_count "$rd/securitytrails.txt") subdomains"
                }; rm -f -- "$p"
            fi
        fi
    fi; rm -f -- "$t_s"

    # DNS History
    local t_d; t_d=$(_mktmp std) || { rm -f "$tf"; return 0; }
    _safe_sleep "0.$((RANDOM % 5 + 3))"
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        -H "APIKEY: ${_tok}" \
        "https://api.securitytrails.com/v1/history/${encoded_dom}/dns/a" \
        > "$t_d" 2>/dev/null
    if [[ -s "$t_d" ]]; then
        local fc; fc=$(head -c 1 "$t_d" 2>/dev/null)
        if [[ "$fc" == "{" ]]; then
            local p; p=$(_mktmp stdp) || true
            [[ -n "$p" ]] && _safe_jq "$p" "$t_d" -r '.records[]?.values[]?.ip // empty' && [[ -s "$p" ]] && {
                while IFS= read -r ip; do validate_ip "$ip" && printf '%s\n' "$ip"; done < "$p" | \
                    sort -u > "$rd/securitytrails_ips.txt" 2>/dev/null
                log "SUCCESS" "[sectrails] $(_safe_count "$rd/securitytrails_ips.txt") historical IPs"
            }; rm -f -- "$p"
        fi
    fi; rm -f -- "$t_d"

    # Associated Domains
    local t_a; t_a=$(_mktmp sta) || { rm -f "$tf"; return 0; }
    _safe_sleep "0.$((RANDOM % 5 + 3))"
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        -H "APIKEY: ${_tok}" \
        "https://api.securitytrails.com/v1/domain/${encoded_dom}/associated" \
        > "$t_a" 2>/dev/null
    if [[ -s "$t_a" ]]; then
        local fc; fc=$(head -c 1 "$t_a" 2>/dev/null)
        if [[ "$fc" == "{" ]]; then
            local p; p=$(_mktmp stap) || true
            [[ -n "$p" ]] && _safe_jq "$p" "$t_a" -r '.records[]?.hostname // empty' && [[ -s "$p" ]] && {
                sort -u -- "$p" > "$rd/securitytrails_assoc.txt" 2>/dev/null
                log "SUCCESS" "[sectrails] $(_safe_count "$rd/securitytrails_assoc.txt") associated"
            }; rm -f -- "$p"
        fi
    fi; rm -f -- "$t_a"

    # WHOIS
    local t_w; t_w=$(_mktmp stw) || { rm -f "$tf"; return 0; }
    _safe_sleep "0.$((RANDOM % 5 + 3))"
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        -H "APIKEY: ${_tok}" \
        "https://api.securitytrails.com/v1/domain/${encoded_dom}/whois" \
        > "$t_w" 2>/dev/null
    if [[ -s "$t_w" ]]; then
        local fc; fc=$(head -c 1 "$t_w" 2>/dev/null)
        [[ "$fc" == "{" ]] && cp -- "$t_w" "$rd/securitytrails_whois.json" 2>/dev/null
    fi; rm -f -- "$t_w" "$tf"
    [[ -f "$rd/securitytrails.txt" ]] || touch "$rd/securitytrails.txt"
}

_en_sectrails_ip() {
    [[ -z "${SECURITYTRAILS_KEY:-}" ]] && return 0
    local ip="$1" rd="$2"; validate_ip "$ip" || return 0
    local tf; tf=$(_write_token_file "sectrails_ip" "$SECURITYTRAILS_KEY") || return 0
    local _tok; _tok=$(_read_token_file "$tf") || { rm -f "$tf"; return 0; }
    local t_ip; t_ip=$(_mktmp stip) || { rm -f "$tf"; return 0; }
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        -H "APIKEY: ${_tok}" -H 'Content-Type: application/json' \
        "https://api.securitytrails.com/v1/domains/list?include=attributes&scroll=false" \
        --data-binary "{\"filter\":{\"ipv4\":\"$ip\"}}" > "$t_ip" 2>/dev/null
    if [[ -s "$t_ip" ]]; then
        local fc; fc=$(head -c 1 "$t_ip" 2>/dev/null)
        if [[ "$fc" == "{" ]]; then
            local p; p=$(_mktmp stipp) || true
            [[ -n "$p" ]] && _safe_jq "$p" "$t_ip" -r '.records[]?.hostname // empty' && [[ -s "$p" ]] && {
                sort -u -- "$p" >> "$rd/securitytrails_reverse.txt" 2>/dev/null
                log "SUCCESS" "[sectrails] $(_safe_count "$rd/securitytrails_reverse.txt") domains on $ip"
            }; rm -f -- "$p"
        fi
    fi; rm -f -- "$t_ip" "$tf"
}

# ══════════════════════════════════════════
# IP & ASN HELPERS
# ══════════════════════════════════════════
_ip_rdns() {
    command -v dig &>/dev/null || { touch "$2/reverse_dns.txt"; return 0; }
    _ptimeout 30 dig -x "$1" +short +time=5 +tries=2 2>/dev/null > "$2/reverse_dns.txt" || true
}
_ip_asn() {
    command -v asnmap &>/dev/null || { touch "$2/asn_info.txt"; return 0; }
    printf '%s\n' "$1" | _ptimeout 60 asnmap -silent 2>/dev/null > "$2/asn_info.txt" || true
}
_ip_meta() {
    validate_ip "$1" || { printf '{}' > "$2/ip_metadata.json"; return 0; }
    _safe_sleep "0.$((RANDOM % 5 + 3))"
    _ptimeout 30 curl -fsS --max-time 15 --max-filesize "$MAX_RESPONSE_SIZE" \
        "https://ipinfo.io/$1/json" 2>/dev/null > "$2/ip_metadata.json" || \
        printf '{}' > "$2/ip_metadata.json"
}
_asn_wh() {
    command -v whois &>/dev/null || { touch "$2/asn_whois.txt"; return 0; }
    _ptimeout 60 whois -h whois.radb.net -- "-i origin $1" 2>/dev/null > "$2/asn_whois.txt" || true
}
_asn_bgp() {
    local t; t=$(_mktmp bg) || return 0
    _ptimeout 60 curl -fsS --max-filesize "$MAX_RESPONSE_SIZE" --max-time 30 \
        "https://api.bgpview.io/asn/${1#AS}/prefixes" 2>/dev/null > "$t" || true
    [[ -s "$t" ]] && _safe_jq "$2/cidr_bgp.txt" "$t" -r '.data.ipv4_prefixes[].prefix // empty' || true
    rm -f -- "$t"
}

# ══════════════════════════════════════════
# PASSIVE PROCESSING
# ══════════════════════════════════════════
proc_passive() {
    local od="$1" rd="$od/raw" ad="$od/assets"
    [[ "$ad" == *".."* ]] && return 1
    local all_sorted; all_sorted=$(_mktmp allsorted) || return 1
    _safe_cat_dir "$rd" ".txt" | sed '/^$/d' | sort -u > "$all_sorted"

    grep -E '^AS[0-9]+$' "$all_sorted" > "$ad/asns/all.txt" 2>/dev/null || : > "$ad/asns/all.txt"
    grep -E '^[0-9.]+/[0-9]{1,2}$' "$all_sorted" > "$ad/cidrs/all.txt" 2>/dev/null || : > "$ad/cidrs/all.txt"

    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$all_sorted" | \
        while IFS= read -r ip; do
            validate_ip "$ip" && ! is_private_ip "$ip" && printf '%s\n' "$ip"
        done > "$ad/ips/all.txt"
    [[ -s "$rd/securitytrails_ips.txt" ]] && {
        while IFS= read -r ip; do
            validate_ip "$ip" && ! is_private_ip "$ip" && printf '%s\n' "$ip"
        done < "$rd/securitytrails_ips.txt" >> "$ad/ips/all.txt"
    }

    grep -vE '^AS[0-9]+$|^[0-9.]+/[0-9]{1,2}$|^[0-9.]+$|^\*\.|[[:space:]]|@' "$all_sorted" | \
        grep '\.' > "$ad/subdomains/all.txt" 2>/dev/null || : > "$ad/subdomains/all.txt"
    [[ -s "$rd/securitytrails_assoc.txt" ]] && \
        cat "$rd/securitytrails_assoc.txt" >> "$ad/subdomains/all.txt"

    rm -f "$all_sorted"
    _par_sort "$ad/subdomains/all.txt" "$ad/ips/all.txt" "$ad/asns/all.txt" "$ad/cidrs/all.txt"
    [[ -n "$SCOPE_FILE" || -n "$OOS_FILE" ]] && \
        filter_scope "$ad/subdomains/all.txt" "$ad/subdomains/all.txt"
    log "SUCCESS" "S:$(_safe_count "$ad/subdomains/all.txt") I:$(_safe_count "$ad/ips/all.txt") A:$(_safe_count "$ad/asns/all.txt") C:$(_safe_count "$ad/cidrs/all.txt")"
}

# ══════════════════════════════════════════
# SETUP & DOMAIN ENUMERATION
# ══════════════════════════════════════════
setup_dirs() {
    local tgt="$1" od="$2"
    local fd="$od"
    [[ -d "$od" ]] && fd="${od}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$fd"/{raw,processed,screenshots,reports} \
             "$fd"/assets/{subdomains,ips,asns,cidrs} \
             "$fd"/temp 2>/dev/null || {
        log "ERROR" "[setup] mkdir failed: $fd"; rm -rf "$fd" 2>/dev/null; return 1
    }
    touch "$fd/temp/.wtest" 2>/dev/null || {
        log "ERROR" "[setup] Not writable: $fd"; rm -rf "$fd" 2>/dev/null; return 1
    }
    rm -f "$fd/temp/.wtest"
    local d; for d in subdomains ips asns cidrs; do
        touch "$fd/assets/$d/all.txt" || { rm -rf "$fd" 2>/dev/null; return 1; }
    done
    touch "$fd/processed/all_urls.txt" "$fd/processed/open_ports.txt" || {
        rm -rf "$fd" 2>/dev/null; return 1
    }
    printf '%s' "$fd"
}

# ══════════════════════════════════════════
# DNS RESOLUTION CALLBACKS
# ══════════════════════════════════════════
_massdns_batch_callback() {
    local batch_file="$1" rd="$2" resolvers="$3"
    [[ -f "$batch_file" && -f "$resolvers" ]] || return 1
    local batch_out; batch_out=$(_mktmp mdb) || return 1
    _ptimeout 300 massdns -r "$resolvers" -t A -o S \
        -w "$batch_out" "$batch_file" 2>/dev/null || {
        log "WARNING" "[massdns] Batch timed out"
    }
    if [[ -s "$batch_out" ]]; then
        grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$batch_out" 2>/dev/null | \
            sort -u >> "$rd/resolved.txt"
        cat "$batch_out" >> "$rd/massdns.txt"
    fi
    rm -f "$batch_out"
}

_dns_dig_callback() {
    local batch_file="$1" rd="$2" dj="$3"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp dgb) || return 1
    grep -E '^[a-zA-Z0-9.\-]+$' "$batch_file" | \
        _ptimeout 300 xargs -P "$dj" -I {} \
        dig +short +time=3 +tries=2 {} 2>/dev/null | \
        grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | \
        sort -u > "$batch_out" || true
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$rd/resolved.txt"
    rm -f "$batch_out"
}

# ══════════════════════════════════════════
# DOMAIN ENUMERATION
# ══════════════════════════════════════════
run_dom_enum() {
    local dom="$1" od="$2" tc="$3" rd="$od/raw"
    [[ "$USE_CACHE" != false ]] && \
        cache_get "d_$dom" > "$rd/cached.txt" 2>/dev/null && {
        log "INFO" "Cache hit"; return 0
    }
    run_par \
        _en_sf "$dom" "$rd" "$_SEP" \
        _en_am "$dom" "$rd" "$_SEP" \
        _en_af "$dom" "$rd" "$_SEP" \
        _en_fd "$dom" "$rd" "$_SEP" \
        _en_crt "$dom" "$rd" "$_SEP" \
        _en_gh "$dom" "$rd" "$_SEP" \
        _en_ch "$dom" "$rd" "$_SEP" \
        _en_rd "$dom" "$rd" "$_SEP" \
        _en_sectrails "$dom" "$rd"

    printf '%s\n' "$dom" "www.$dom" > "$rd/main.txt"
    _safe_cat_dir "$rd" ".txt" | sort -u > "$od/temp/all_raw.txt" || return 1
    awk '!/\*/&&!/[[:space:]]/&&!/@/&&/\./' "$od/temp/all_raw.txt" | \
        sort -u > "$od/temp/all_dom.txt" || true
    local dc; dc=$(_safe_count "$od/temp/all_dom.txt")

    : > "$rd/resolved.txt"
    : > "$rd/massdns.txt"

    if command -v massdns &>/dev/null && [[ -f "$RESOLVERS" ]]; then
        _run_batched "$od/temp/all_dom.txt" 50000 "massdns" \
            _massdns_batch_callback "$rd" "$RESOLVERS"
    elif command -v dig &>/dev/null; then
        local dj=$tc; ((dj > 50)) && dj=50; ((dj < 1)) && dj=1
        _run_batched "$od/temp/all_dom.txt" 50000 "dig" \
            _dns_dig_callback "$rd" "$dj"
    fi

    _sort_inplace "$rd/resolved.txt"

    if [[ "$USE_CACHE" != false && -s "$od/temp/all_raw.txt" ]]; then
        local _csz; _csz=$(wc -c < "$od/temp/all_raw.txt" 2>/dev/null)
        _csz="${_csz//[[:space:]]/}"
        [[ "$_csz" =~ ^[0-9]+$ ]] && (( _csz <= MAX_CACHE_SZ )) && \
            cache_set "d_$dom" < "$od/temp/all_raw.txt"
    fi
    log "SUCCESS" "$dc domains"
}

# ══════════════════════════════════════════
# IP & ASN ENUMERATION (مشكلة 14: local برا الـ loop)
# ══════════════════════════════════════════
run_ip_enum() {
    local ip="$1" od="$2" rd="$od/raw"
    run_par \
        _ip_rdns "$ip" "$rd" "$_SEP" \
        _ip_asn "$ip" "$rd" "$_SEP" \
        _ip_meta "$ip" "$rd" "$_SEP" \
        _en_sectrails_ip "$ip" "$rd"
    printf '%s\n' "$ip" > "$od/assets/ips/all.txt"
    grep -o 'AS[0-9]*' "$rd/asn_info.txt" 2>/dev/null > "$od/assets/asns/all.txt" || true
    {
        sort -u -- "$rd/reverse_dns.txt" 2>/dev/null
        [[ -s "$rd/securitytrails_reverse.txt" ]] && cat "$rd/securitytrails_reverse.txt"
    } | sort -u > "$od/assets/subdomains/all.txt" 2>/dev/null || true
}

run_asn_enum() {
    local asn="$1" od="$2" rd="$od/raw"
    run_par _asn_wh "$asn" "$rd" "$_SEP" _asn_bgp "$asn" "$rd"
    grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' "$rd/asn_whois.txt" 2>/dev/null \
        > "$rd/cidr_whois.txt" || true
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a cf=("$rd"/cidr_*.txt); eval "$sv"
    (( ${#cf[@]} )) && cat -- "${cf[@]}" | sort -u > "$od/assets/cidrs/all.txt" || \
        touch "$od/assets/cidrs/all.txt"
    printf '%s\n' "$asn" > "$od/assets/asns/all.txt"
    # مشكلة 14: local declarations برا الـ loop
    local cidr a b c d m
    while IFS= read -r cidr; do
        [[ -z "$cidr" ]] && continue
        IFS='./' read -r a b c d m <<< "$cidr"
        printf '%s.%s.%s.%s\n' "$a" "$b" "$c" "$d"
    done < "$od/assets/cidrs/all.txt" | sort -u > "$od/assets/ips/all.txt"
    log "SUCCESS" "CIDRs: $(_safe_count "$od/assets/cidrs/all.txt")"
}

run_active() {
    local tgt="$1" od="$2" wl="$3" rs="$4" tt="$5"
    [[ "$tt" == domain && -f "$wl" && -f "$rs" ]] || return 0
    command -v puredns &>/dev/null || return 0
    retry_t 600 puredns bruteforce "$wl" "$tgt" --resolvers "$rs" -q 2>/dev/null \
        > "$od/raw/puredns.txt" || true
    [[ -s "$od/raw/puredns.txt" ]] && {
        cat "$od/raw/puredns.txt" >> "$od/assets/subdomains/all.txt"
        _sort_inplace "$od/assets/subdomains/all.txt"
    }
}

# ══════════════════════════════════════════
# HTTPX BATCH SYSTEM
# ══════════════════════════════════════════
_httpx_batch_callback() {
    local batch_file="$1" od="$2" pts="$3" thr="$4" to="$5"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp hxb) || return 1
    local tc; tc=$(_safe_count "$batch_file")
    local batch_timeout=$(( tc * 2 + 120 ))
    (( batch_timeout > 3600 )) && batch_timeout=3600
    (( batch_timeout < 120 )) && batch_timeout=120

    _ptimeout "$batch_timeout" httpx -silent -l "$batch_file" \
        -p "$pts" -nc -title -status-code -content-length -content-type \
        -ip -cname -cdn -location -favicon -jarm \
        -threads "$thr" -timeout "$to" -rate-limit "$RATE_LIMIT" \
        -o "$batch_out" 2>/dev/null || {
        log "WARNING" "[httpx] Batch timed out (${batch_timeout}s)"
    }
    [[ -s "$batch_out" ]] && {
        cat "$batch_out" >> "$od/processed/fingerprint.txt"
        log "DEBUG" "[httpx] Batch: $(_safe_count "$batch_out") live"
    }
    rm -f "$batch_out"
}

fingerprint() {
    local od="$1" pts="$2" thr="${3:-$THREADS}"
    command -v httpx &>/dev/null || { log "ERROR" "httpx not found"; return 1; }

    : > "$od/temp/targets.txt"
    [[ -s "$od/assets/subdomains/all.txt" ]] && \
        cat -- "$od/assets/subdomains/all.txt" >> "$od/temp/targets.txt"
    [[ -s "$od/assets/ips/all.txt" ]] && \
        cat -- "$od/assets/ips/all.txt" >> "$od/temp/targets.txt"
    _sort_inplace "$od/temp/targets.txt"

    local tc; tc=$(_safe_count "$od/temp/targets.txt")
    (( tc == 0 )) && return 0

    local effective_timeout=$TIMEOUT
    (( tc > 2000 )) && effective_timeout=3
    (( tc > 5000 )) && effective_timeout=2

    : > "$od/processed/fingerprint.txt"

    log "INFO" "[httpx] $tc targets, timeout=${effective_timeout}s"

    _run_batched "$od/temp/targets.txt" "$MAX_FINGERPRINT_TARGETS" "httpx" \
        _httpx_batch_callback "$od" "$pts" "$thr" "$effective_timeout"

    if [[ -s "$od/processed/fingerprint.txt" ]]; then
        awk '{print $1}' "$od/processed/fingerprint.txt" | sort -u > "$od/processed/all_urls.txt"
        local live; live=$(_safe_count "$od/processed/all_urls.txt")
        log "SUCCESS" "[httpx] $live live from $tc targets"
        notify_finding "INFO" "$live live URLs"
    else
        touch "$od/processed/all_urls.txt"
        log "WARNING" "[httpx] No live targets"
    fi
}

# ══════════════════════════════════════════
# NAABU BATCH SYSTEM
# ══════════════════════════════════════════
_naabu_batch_callback() {
    local batch_file="$1" od="$2" pts="$3"
    [[ -f "$batch_file" ]] || return 1
    local tc; tc=$(_safe_count "$batch_file")
    local port_count
    port_count=$(printf '%s' "$pts" | tr ',' '\n' | wc -l)
    port_count="${port_count//[[:space:]]/}"
    [[ "$port_count" =~ ^[0-9]+$ ]] || port_count=7

    local batch_out; batch_out=$(_mktmp nbb) || return 1
    local naabu_to=$(( tc * port_count / RATE_LIMIT + 120 ))
    (( naabu_to > 3600 )) && naabu_to=3600
    (( naabu_to < 180 )) && naabu_to=180

    log "DEBUG" "[naabu] $tc × $port_count ports, timeout=${naabu_to}s"

    _ptimeout "$naabu_to" naabu -l "$batch_file" \
        -p "$pts" -silent -rate "$RATE_LIMIT" \
        -o "$batch_out" 2>/dev/null || {
        log "WARNING" "[naabu] Batch timed out (${naabu_to}s)"
    }
    [[ -s "$batch_out" ]] && {
        cat "$batch_out" >> "$od/processed/open_ports.txt"
        log "DEBUG" "[naabu] Batch: $(_safe_count "$batch_out") ports"
    }
    rm -f "$batch_out"
}

naabu_scan() {
    local od="$1" pts="$2"
    : > "$od/temp/scan_targets.txt"
    [[ -s "$od/assets/subdomains/all.txt" ]] && \
        cat -- "$od/assets/subdomains/all.txt" >> "$od/temp/scan_targets.txt"
    [[ -s "$od/assets/ips/all.txt" ]] && \
        cat -- "$od/assets/ips/all.txt" >> "$od/temp/scan_targets.txt"
    _sort_inplace "$od/temp/scan_targets.txt"
    [[ -s "$od/temp/scan_targets.txt" ]] || return 0
    command -v naabu &>/dev/null || return 0

    local tc; tc=$(_safe_count "$od/temp/scan_targets.txt")
    : > "$od/processed/open_ports.txt"

    log "INFO" "[naabu] $tc targets on $pts"

    _run_batched "$od/temp/scan_targets.txt" "$MAX_FINGERPRINT_TARGETS" "naabu" \
        _naabu_batch_callback "$od" "$pts"

    if [[ -s "$od/processed/open_ports.txt" ]]; then
        _sort_inplace "$od/processed/open_ports.txt"
        awk -F: '{print $1}' "$od/processed/open_ports.txt" | \
            sort -u > "$od/processed/hosts_ports.txt"
        local c; c=$(_safe_count "$od/processed/open_ports.txt")
        log "SUCCESS" "[naabu] $c open ports"
        (( c > 50 )) && notify_finding "WARNING" "$c ports"
    else
        log "INFO" "[naabu] No open ports"
    fi
}

# ══════════════════════════════════════════
# SPIDER BATCH SYSTEM
# ══════════════════════════════════════════
_spider_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    mkdir -p "$od/processed/spider"
    _ptimeout 600 gospider -S "$batch_file" \
        -o "$od/processed/spider" -c 10 -d 2 --sitemap --robots 2>/dev/null || {
        log "WARNING" "[spider] Batch timed out"
    }
}

spider() {
    local od="$1" tgt="$2" tt="$3"
    [[ -s "$od/processed/all_urls.txt" ]] || return 0
    command -v gospider &>/dev/null || return 0

    _run_batched "$od/processed/all_urls.txt" 500 "spider" \
        _spider_batch_callback "$od"

    [[ -d "$od/processed/spider" ]] || return 0
    local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
    shopt -s nullglob; local -a sf=("$od/processed/spider"/*); eval "$sv"
    (( ${#sf[@]} )) || return 0

    if [[ "$tt" == domain ]]; then
        local ed; ed=$(_escape_ere "$tgt")
        [[ "$ed" =~ ^[a-zA-Z0-9\\.\\-]+$ ]] || return 0
        grep -hoE "https?://([a-zA-Z0-9.\-]+\.)?${ed}" "${sf[@]}" 2>/dev/null | \
            sort -u > "$od/processed/spider_urls.txt" || true
        [[ -s "$od/processed/spider_urls.txt" ]] && {
            cut -d/ -f3 "$od/processed/spider_urls.txt" | \
                sort -u >> "$od/assets/subdomains/all.txt"
            _sort_inplace "$od/assets/subdomains/all.txt"
        }
    fi
    grep -hoE 'https?://[0-9]{1,3}(\.[0-9]{1,3}){3}[^ ]*' "${sf[@]}" 2>/dev/null | \
        cut -d/ -f3 | while IFS= read -r ip; do
            validate_ip "$ip" && printf '%s\n' "$ip"
        done | sort -u >> "$od/assets/ips/all.txt" || true
    _sort_inplace "$od/assets/ips/all.txt"
}

# ══════════════════════════════════════════
# SUBJACK BATCH SYSTEM (مشكلة 11: إصلاح _warn_count)
# ══════════════════════════════════════════
_subjack_batch_callback() {
    local batch_file="$1" od="$2" thr="$3"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp sjb) || return 1
    _ptimeout 300 subjack -w "$batch_file" -t "$thr" -timeout 30 \
        -o "$batch_out" -ssl -silent 2>/dev/null || {
        log "WARNING" "[subjack] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/subjack.txt"
    rm -f "$batch_out"
}

subjack_scan() {
    local od="$1"
    [[ -s "$od/assets/subdomains/all.txt" ]] || return 0
    command -v subjack &>/dev/null || return 0

    : > "$od/processed/subjack.txt"
    _run_batched "$od/assets/subdomains/all.txt" 5000 "subjack" \
        _subjack_batch_callback "$od" "$THREADS"

    [[ -s "$od/processed/subjack.txt" ]] && {
        _sort_inplace "$od/processed/subjack.txt"
        # مشكلة 11: _warn_count مكنتش بتعمل حاجة مفيدة هنا
        # استبدلناها بـ log + count صريح
        local tc; tc=$(_safe_count "$od/processed/subjack.txt")
        log "WARNING" "[subjack] $tc potential subdomain takeover(s) found!"
        notify_finding "HIGH" "$tc takeover(s)"
    }
}

# ══════════════════════════════════════════
# DNSX BATCH SYSTEM
# ══════════════════════════════════════════
_dnsx_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp dxb) || return 1
    _ptimeout 300 dnsx -l "$batch_file" \
        -a -aaaa -cname -ns -mx -txt -ptr -soa -resp -silent -json \
        -o "$batch_out" 2>/dev/null || {
        log "WARNING" "[dnsx] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/dnsx.json"
    rm -f "$batch_out"
}

dnsx_scan() {
    local od="$1"
    [[ -s "$od/assets/subdomains/all.txt" ]] || return 0
    command -v dnsx &>/dev/null || return 0

    : > "$od/processed/dnsx.json"
    _run_batched "$od/assets/subdomains/all.txt" 10000 "dnsx" \
        _dnsx_batch_callback "$od"

    [[ -s "$od/processed/dnsx.json" ]] || return 0
    local q; for q in mx ns txt; do
        [[ "$q" =~ ^[a-z]+$ ]] || continue
        _safe_jq "$od/processed/${q}_rec.txt" "$od/processed/dnsx.json" \
            -r "select(.${q}!=null)|.host+\" -> \"+(.${q}|join(\", \"))" || \
            touch "$od/processed/${q}_rec.txt"
    done
}

# ══════════════════════════════════════════
# ASNMAP CALLBACKS (مشكلة 10: معرّفة قبل mapcidr_scan)
# (مشكلة 12: callback منفصل لكل سياق)
# ══════════════════════════════════════════

# callback للاستخدام في mapcidr_scan - بيكتب في processed/cidr_asns.txt
_enrich_asnmap_cidr_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp enbc) || return 1
    _ptimeout 120 asnmap -silent < "$batch_file" 2>/dev/null > "$batch_out" || {
        log "WARNING" "[asnmap:cidr] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/cidr_asns.txt"
    rm -f "$batch_out"
}

# callback للاستخدام في enrich - بيكتب في raw/enrich_asn.txt
_enrich_asnmap_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp enb) || return 1
    _ptimeout 120 asnmap -silent < "$batch_file" 2>/dev/null > "$batch_out" || {
        log "WARNING" "[asnmap:enrich] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/raw/enrich_asn.txt"
    rm -f "$batch_out"
}

# ══════════════════════════════════════════
# MAPCIDR BATCH SYSTEM
# ══════════════════════════════════════════
_mapcidr_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp mcb) || return 1
    _ptimeout 120 mapcidr -l "$batch_file" -silent \
        -o "$batch_out" 2>/dev/null || {
        log "WARNING" "[mapcidr] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/cidrs.txt"
    rm -f "$batch_out"
}

mapcidr_scan() {
    local od="$1"
    [[ -s "$od/assets/ips/all.txt" ]] || return 0
    command -v mapcidr &>/dev/null || return 0

    : > "$od/processed/cidrs.txt"
    _run_batched "$od/assets/ips/all.txt" 10000 "mapcidr" \
        _mapcidr_batch_callback "$od"

    [[ -s "$od/processed/cidrs.txt" ]] && {
        _sort_inplace "$od/processed/cidrs.txt"
        command -v asnmap &>/dev/null && {
            : > "$od/processed/cidr_asns.txt"
            # مشكلة 10+12: بنستخدم الـ callback الصح اللي بيكتب في cidr_asns.txt
            _run_batched "$od/processed/cidrs.txt" 5000 "cidr_asn" \
                _enrich_asnmap_cidr_callback "$od"
            [[ -s "$od/processed/cidr_asns.txt" ]] && \
                _sort_inplace "$od/processed/cidr_asns.txt"
        }
    }
}

# ══════════════════════════════════════════
# SCREENSHOTS BATCH SYSTEM
# ══════════════════════════════════════════
_screenshots_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    mkdir -p "$od/screenshots"
    if command -v gowitness &>/dev/null; then
        _ptimeout 900 gowitness scan file -f "$batch_file" \
            --threads 10 --screenshot-path "$od/screenshots" 2>/dev/null || {
            log "WARNING" "[screenshots] Batch timed out"
        }
    elif command -v aquatone &>/dev/null; then
        cat -- "$batch_file" | \
            _ptimeout 900 aquatone -out "$od/screenshots" -silent 2>/dev/null || {
            log "WARNING" "[screenshots] Batch timed out"
        }
    fi
}

screenshots() {
    local od="$1"
    [[ -s "$od/processed/all_urls.txt" ]] || return 0
    command -v gowitness &>/dev/null || command -v aquatone &>/dev/null || return 0

    mkdir -p "$od/screenshots"
    _run_batched "$od/processed/all_urls.txt" 200 "screenshots" \
        _screenshots_batch_callback "$od"
}

# ══════════════════════════════════════════
# ENRICH BATCH SYSTEM
# ══════════════════════════════════════════
enrich() {
    local od="$1"
    [[ -s "$od/processed/fingerprint.txt" ]] && {
        grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' "$od/processed/fingerprint.txt" 2>/dev/null | \
            sort -u | while IFS= read -r ip; do
                validate_ip "$ip" && printf '%s\n' "$ip"
            done >> "$od/assets/ips/all.txt"
        _sort_inplace "$od/assets/ips/all.txt"
    }
    command -v asnmap &>/dev/null && [[ -s "$od/assets/ips/all.txt" ]] && {
        : > "$od/raw/enrich_asn.txt"
        # مشكلة 12: بنستخدم الـ callback اللي بيكتب في raw/enrich_asn.txt
        _run_batched "$od/assets/ips/all.txt" 5000 "enrich" \
            _enrich_asnmap_callback "$od"
        [[ -s "$od/raw/enrich_asn.txt" ]] && {
            grep -o 'AS[0-9]*' "$od/raw/enrich_asn.txt" 2>/dev/null | \
                sort -u >> "$od/assets/asns/all.txt" || true
            _sort_inplace "$od/assets/asns/all.txt"
        }
    }
}

# ══════════════════════════════════════════
# WAF DETECTION (مشكلة 13: إصلاح injection)
# ══════════════════════════════════════════
_waf_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp wfb) || return 1
    # مشكلة 13: while read + validation بدل xargs sh -c
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        # تحقق إن الـ URL آمن
        [[ "$url" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]] || continue
        _ptimeout 30 wafw00f "$url" 2>/dev/null | tail -1
    done < "$batch_file" > "$batch_out" 2>/dev/null || {
        log "WARNING" "[waf] Batch failed"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/waf_raw.txt"
    rm -f "$batch_out"
}

detect_waf() {
    local od="$1"
    [[ -s "$od/processed/all_urls.txt" ]] || return 0
    command -v wafw00f &>/dev/null || return 0

    : > "$od/processed/waf_raw.txt"
    _run_batched "$od/processed/all_urls.txt" 50 "waf" \
        _waf_batch_callback "$od"

    [[ -s "$od/processed/waf_raw.txt" ]] && {
        sort -u "$od/processed/waf_raw.txt" > "$od/processed/waf_results.txt"
        rm -f "$od/processed/waf_raw.txt"
        local c; c=$(grep -cv 'No WAF' "$od/processed/waf_results.txt" 2>/dev/null) || c=0
        (( c > 0 )) && notify_finding "INFO" "$c WAF detected"
        log "SUCCESS" "[waf] $(_safe_count "$od/processed/waf_results.txt") results"
    }
}

# ══════════════════════════════════════════
# TECH DETECTION BATCH SYSTEM
# ══════════════════════════════════════════
_tech_webanalyze_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp tcb) || return 1
    _ptimeout 300 webanalyze -hosts "$batch_file" -output csv 2>/dev/null \
        > "$batch_out" || {
        log "WARNING" "[tech] Batch timed out"
    }
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/technologies.csv"
    rm -f "$batch_out"
}

_tech_whatweb_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp twb) || return 1
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        # مشكلة 15: validation للـ URL
        [[ "$url" =~ ^https?://[a-zA-Z0-9._:/-]+$ ]] || continue
        _ptimeout 30 whatweb --no-errors -q "$url" 2>/dev/null >> "$batch_out" || true
    done < "$batch_file"
    [[ -s "$batch_out" ]] && cat "$batch_out" >> "$od/processed/technologies.txt"
    rm -f "$batch_out"
}

detect_tech() {
    local od="$1"
    [[ -s "$od/processed/all_urls.txt" ]] || return 0

    if command -v webanalyze &>/dev/null; then
        : > "$od/processed/technologies.csv"
        _run_batched "$od/processed/all_urls.txt" 100 "tech" \
            _tech_webanalyze_callback "$od"
    elif command -v whatweb &>/dev/null; then
        : > "$od/processed/technologies.txt"
        _run_batched "$od/processed/all_urls.txt" 30 "whatweb" \
            _tech_whatweb_callback "$od"
    fi
}

# ══════════════════════════════════════════
# NUCLEI BATCH SYSTEM
# ══════════════════════════════════════════
_nuclei_batch_callback() {
    local batch_file="$1" od="$2"
    [[ -f "$batch_file" ]] || return 1
    local batch_out; batch_out=$(_mktmp ncb) || return 1

    local tc; tc=$(_safe_count "$batch_file")
    local nuclei_to=$(( tc * 10 + 300 ))
    (( nuclei_to > 7200 )) && nuclei_to=7200
    (( nuclei_to < 300 )) && nuclei_to=300

    _ptimeout "$nuclei_to" nuclei -l "$batch_file" \
        -severity low,medium,high,critical -silent -nc \
        -rate-limit "$RATE_LIMIT" \
        -o "$batch_out" 2>/dev/null || {
        log "WARNING" "[nuclei] Batch timed out (${nuclei_to}s)"
    }
    [[ -s "$batch_out" ]] && {
        cat "$batch_out" >> "$od/processed/nuclei_results.txt"
        log "DEBUG" "[nuclei] Batch: $(_safe_count "$batch_out") findings"
    }
    rm -f "$batch_out"
}

run_nuclei() {
    local od="$1"
    [[ -s "$od/processed/all_urls.txt" ]] || return 0
    command -v nuclei &>/dev/null || return 0

    local url_count; url_count=$(_safe_count "$od/processed/all_urls.txt")
    log "INFO" "[nuclei] Scanning $url_count URLs"

    : > "$od/processed/nuclei_results.txt"

    _run_batched "$od/processed/all_urls.txt" 1000 "nuclei" \
        _nuclei_batch_callback "$od"

    [[ -s "$od/processed/nuclei_results.txt" ]] && {
        local cc; cc=$(grep -ci 'critical' "$od/processed/nuclei_results.txt" 2>/dev/null) || cc=0
        (( cc > 0 )) && notify_finding "CRITICAL" "$cc critical vulns"
        local hc; hc=$(grep -ci 'high' "$od/processed/nuclei_results.txt" 2>/dev/null) || hc=0
        (( hc > 0 )) && notify_finding "HIGH" "$hc high vulns"
        log "SUCCESS" "[nuclei] $(_safe_count "$od/processed/nuclei_results.txt") findings"
    }
}

# ══════════════════════════════════════════
# CLOUD DETECTION
# ══════════════════════════════════════════
detect_cloud() {
    local od="$1" tgt="$2"
    [[ -s "$od/assets/subdomains/all.txt" ]] || return 0
    local cf="$od/processed/cloud_assets.txt"
    : > "$cf"
    local -a cloud_patterns=(
        '\.s3\.amazonaws\.com|\.s3-[a-z0-9\-]+\.amazonaws\.com'
        '\.blob\.core\.windows\.net|\.azurewebsites\.net|\.azure-api\.net'
        '\.storage\.googleapis\.com|\.appspot\.com|\.cloudfunctions\.net'
        '\.cloudfront\.net|\.herokuapp\.com|\.netlify\.app|\.vercel\.app'
        '\.firebaseapp\.com|\.web\.app|\.digitaloceanspaces\.com'
        '\.cdn\.cloudflare\.net|\.workers\.dev'
    )
    local pattern
    for pattern in "${cloud_patterns[@]}"; do
        grep -iE "$pattern" "$od/assets/subdomains/all.txt" 2>/dev/null >> "$cf" || true
    done
    _sort_inplace "$cf"
    local c; c=$(_safe_count "$cf")
    (( c > 0 )) && {
        notify_finding "INFO" "$c cloud assets"
        log "SUCCESS" "[cloud] $c assets found"
    }
}
# ══════════════════════════════════════════
# ANALYSIS & REPORTS
# ══════════════════════════════════════════
analyze() {
    local od="$1" f="$od/reports/analysis.txt"
    local ns ni nu np
    ns=$(_safe_count "$od/assets/subdomains/all.txt")
    ni=$(_safe_count "$od/assets/ips/all.txt")
    nu=$(_safe_count "$od/processed/all_urls.txt")
    np=$(_safe_count "$od/processed/open_ports.txt")
    printf 'Analysis v%s\nSubdomains: %s\nIPs: %s\nURLs: %s\nPorts: %s\n' \
        "$VERSION" "$ns" "$ni" "$nu" "$np" > "$f"

    # مشكلة 13: استخدام _safe_jq بدل jq المباشر
    if [[ -f "$od/raw/securitytrails_whois.json" ]]; then
        printf '\n--- SecurityTrails WHOIS ---\n' >> "$f"
        _safe_jq /dev/stdout "$od/raw/securitytrails_whois.json" \
            -r '.result // empty | to_entries[] | "\(.key): \(.value)"' \
            >> "$f" 2>/dev/null || true
    fi
    if [[ -s "$od/raw/securitytrails_assoc.txt" ]]; then
        printf '\n--- Associated Domains (%s) ---\n' \
            "$(_safe_count "$od/raw/securitytrails_assoc.txt")" >> "$f"
        head -20 "$od/raw/securitytrails_assoc.txt" >> "$f"
    fi
}

gen_report() {
    local od="$1" tgt="$2" tt="$3"
    local md="$od/reports/summary.md" js="$od/reports/summary.json"
    _sync_counters
    local ns ni na nc nu np
    ns=$(_safe_count "$od/assets/subdomains/all.txt")
    ni=$(_safe_count "$od/assets/ips/all.txt")
    na=$(_safe_count "$od/assets/asns/all.txt")
    nc=$(_safe_count "$od/assets/cidrs/all.txt")
    nu=$(_safe_count "$od/processed/all_urls.txt")
    np=$(_safe_count "$od/processed/open_ports.txt")
    local now_epoch; now_epoch=$(date +%s 2>/dev/null) || now_epoch=$START_EPOCH
    local el=$(( now_epoch - START_EPOCH )); (( el < 0 )) && el=0
    local nv=0 cl=0 wf=0 tc=0 st_subs=0 st_ips=0 st_assoc=0
    [[ -f "$od/processed/nuclei_results.txt" ]] && nv=$(_safe_count "$od/processed/nuclei_results.txt")
    [[ -f "$od/processed/cloud_assets.txt" ]] && cl=$(_safe_count "$od/processed/cloud_assets.txt")
    [[ -f "$od/processed/waf_results.txt" ]] && wf=$(_safe_count "$od/processed/waf_results.txt")
    [[ -f "$od/processed/technologies.csv" ]] && tc=$(_safe_count "$od/processed/technologies.csv")
    [[ -f "$od/processed/technologies.txt" && "$tc" -eq 0 ]] && \
        tc=$(_safe_count "$od/processed/technologies.txt")

    [[ -f "$od/raw/securitytrails.txt" ]] && st_subs=$(_safe_count "$od/raw/securitytrails.txt")
    [[ -f "$od/raw/securitytrails_ips.txt" ]] && st_ips=$(_safe_count "$od/raw/securitytrails_ips.txt")
    [[ -f "$od/raw/securitytrails_assoc.txt" ]] && st_assoc=$(_safe_count "$od/raw/securitytrails_assoc.txt")

    local jt je
    jt=$(_mktmp rj); je=$(_mktmp re)
    if [[ -n "$jt" && -n "$je" ]] && jq -n \
        --arg tool TheN0thing --arg ver "$VERSION" \
        --arg ts "$(date -Iseconds 2>/dev/null || date +%Y-%m-%dT%H:%M:%S)" \
        --argjson dur "$el" --arg tgt "$tgt" --arg tt "$tt" \
        --argjson subs "$ns" --argjson ips "$ni" --argjson asns "$na" --argjson cidrs "$nc" \
        --argjson urls "$nu" --argjson ports "$np" --argjson vulns "$nv" \
        --argjson cloud "$cl" --argjson waf "$wf" --argjson tech "$tc" \
        --argjson st_subs "$st_subs" --argjson st_ips "$st_ips" --argjson st_assoc "$st_assoc" \
        --argjson errs "$ERROR_COUNT" --argjson warns "$WARNING_COUNT" --arg lf "$LOG_FILE" \
        '{meta:{tool:$tool,version:$ver,timestamp:$ts,duration:$dur,target:$tgt,type:$tt},summary:{subdomains:$subs,ips:$ips,asns:$asns,cidrs:$cidrs,urls:$urls,ports:$ports,vulns:$vulns,cloud:$cloud,waf:$waf,tech:$tech},securitytrails:{subdomains:$st_subs,historical_ips:$st_ips,associated_domains:$st_assoc},health:{errors:$errs,warnings:$warns,log:$lf}}' \
        > "$jt" 2> "$je" && [[ -s "$jt" ]]; then
        mv -- "$jt" "$js"
    else
        local ed="unknown"
        [[ -s "$je" ]] && ed=$(head -1 "$je" 2>/dev/null)
        log "WARNING" "[report] JSON: $ed"
        printf '{"error":"failed"}\n' > "$js"
    fi
    rm -f -- "$jt" "$je" 2>/dev/null

    cat > "$md" << MDEOF
# Report: \`$tgt\` ($tt) ${el}s v$VERSION $(date "+%Y-%m-%d %H:%M:%S")

| Metric | Count |
|--------|-------|
| Subdomains | $ns |
| IPs | $ni |
| ASNs | $na |
| CIDRs | $nc |
| URLs | $nu |
| Ports | $np |
| Vulns | $nv |
| Cloud | $cl |
| WAF | $wf |
| Tech | $tc |

## SecurityTrails
| Source | Count |
|--------|-------|
| ST Subdomains | $st_subs |
| ST Historical IPs | $st_ips |
| ST Associated Domains | $st_assoc |

MDEOF
    [[ -s "$od/assets/subdomains/all.txt" ]] && {
        printf '## Top Subdomains\n```\n' >> "$md"
        head -20 -- "$od/assets/subdomains/all.txt" >> "$md"
        printf '```\n\n' >> "$md"
    }
    [[ -s "$od/raw/securitytrails_assoc.txt" ]] && {
        printf '## Associated Domains (SecurityTrails)\n```\n' >> "$md"
        head -20 -- "$od/raw/securitytrails_assoc.txt" >> "$md"
        printf '```\n\n' >> "$md"
    }
    printf 'Errors: %d | Warnings: %d\n---\n*TheN0thing v%s*\n' \
        "$ERROR_COUNT" "$WARNING_COUNT" "$VERSION" >> "$md"
    log "SUCCESS" "Reports: $md $js"
}

_html_escape() {
    local i="$1"
    i=$(printf '%s' "$i" | tr -d '\0')
    i="${i//&/&amp;}"; i="${i//</&lt;}"; i="${i//>/&gt;}"
    i="${i//\"/&quot;}"; i="${i//\'/&#x27;}"; i="${i//\`/&#96;}"
    printf '%s' "$i"
}

_html_escape_file() {
    local file="$1" ml="${2:-50}"
    [[ -f "$file" ]] || return 0
    head -n "$ml" -- "$file" 2>/dev/null | tr -d '\0\r' | sed \
        -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' \
        -e 's/"/\&quot;/g' -e "s/'/\&#x27;/g" -e 's/`/\&#96;/g'
}

gen_html_report() {
    local od="$1" tgt="$2" tt="$3" html="$od/reports/report.html"
    _sync_counters
    local ns ni na nc nu np
    ns=$(_safe_count "$od/assets/subdomains/all.txt")
    ni=$(_safe_count "$od/assets/ips/all.txt")
    na=$(_safe_count "$od/assets/asns/all.txt")
    nc=$(_safe_count "$od/assets/cidrs/all.txt")
    nu=$(_safe_count "$od/processed/all_urls.txt")
    np=$(_safe_count "$od/processed/open_ports.txt")
    local now_epoch; now_epoch=$(date +%s 2>/dev/null) || now_epoch=$START_EPOCH
    local el=$(( now_epoch - START_EPOCH )); (( el < 0 )) && el=0
    [[ "$ns" =~ ^[0-9]+$ ]] || ns=0
    [[ "$ni" =~ ^[0-9]+$ ]] || ni=0
    [[ "$na" =~ ^[0-9]+$ ]] || na=0
    [[ "$nc" =~ ^[0-9]+$ ]] || nc=0
    [[ "$nu" =~ ^[0-9]+$ ]] || nu=0
    [[ "$np" =~ ^[0-9]+$ ]] || np=0

    local st_subs=0 st_ips=0 st_assoc=0
    [[ -f "$od/raw/securitytrails.txt" ]] && st_subs=$(_safe_count "$od/raw/securitytrails.txt")
    [[ -f "$od/raw/securitytrails_ips.txt" ]] && st_ips=$(_safe_count "$od/raw/securitytrails_ips.txt")
    [[ -f "$od/raw/securitytrails_assoc.txt" ]] && st_assoc=$(_safe_count "$od/raw/securitytrails_assoc.txt")

    # مشكلة 12: escape كل القيم اللي بتتحط في HTML
    local st stt sv_escaped
    st=$(_html_escape "$tgt")
    stt=$(_html_escape "$tt")
    sv_escaped=$(_html_escape "$VERSION")
    local date_escaped
    date_escaped=$(_html_escape "$(date "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")")

    cat > "$html" << HTMLEOF
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none';">
<title>TheN0thing Report - ${st}</title>
<style>:root{--bg:#0a0a0f;--cd:#12121a;--br:#1e1e2e;--tx:#c9d1d9;--ac:#58a6ff;--gn:#3fb950;--yl:#d29922;--rd:#f85149}*{margin:0;padding:0;box-sizing:border-box}body{background:var(--bg);color:var(--tx);font-family:system-ui,sans-serif;padding:2rem}.c{max-width:1200px;margin:0 auto}.hd{text-align:center;padding:2rem 0;border-bottom:1px solid var(--br)}.hd h1{color:var(--ac)}.g{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:2rem 0}.cd{background:var(--cd);border:1px solid var(--br);border-radius:12px;padding:1.5rem;text-align:center}.cd .n{font-size:2rem;font-weight:700;color:var(--ac)}.cd .l{color:#666;font-size:.8rem;margin-top:.5rem}.cd.st .n{color:var(--gn)}.s{background:var(--cd);border:1px solid var(--br);border-radius:12px;padding:1.5rem;margin:1rem 0}.s h2{color:var(--ac);margin-bottom:1rem}.s h3{color:var(--gn);margin:1rem 0 .5rem}pre{background:#0d1117;padding:1rem;border-radius:8px;overflow:auto;font-size:.85rem;max-height:400px;white-space:pre-wrap;word-break:break-all}.ft{text-align:center;padding:2rem 0;color:#444;font-size:.8rem}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;margin:2px}.badge.crit{background:#f8514933;color:var(--rd)}.badge.high{background:#d2992233;color:var(--yl)}.badge.info{background:#58a6ff33;color:var(--ac)}</style></head><body><div class="c">
<div class="hd"><h1>TheN0thing Report</h1><div style="color:#666;font-size:.9rem">${st} (${stt}) | ${el}s | ${date_escaped} | v${sv_escaped}</div></div>
<div class="g"><div class="cd"><div class="n">${ns}</div><div class="l">Subdomains</div></div><div class="cd"><div class="n">${ni}</div><div class="l">IPs</div></div><div class="cd"><div class="n">${na}</div><div class="l">ASNs</div></div><div class="cd"><div class="n">${nc}</div><div class="l">CIDRs</div></div><div class="cd"><div class="n">${nu}</div><div class="l">URLs</div></div><div class="cd"><div class="n">${np}</div><div class="l">Ports</div></div></div>
HTMLEOF

    # SecurityTrails section
    if (( st_subs > 0 || st_ips > 0 || st_assoc > 0 )); then
        cat >> "$html" << STEOF
<div class="s"><h2>SecurityTrails Intelligence</h2>
<div class="g"><div class="cd st"><div class="n">${st_subs}</div><div class="l">ST Subdomains</div></div><div class="cd st"><div class="n">${st_ips}</div><div class="l">Historical IPs</div></div><div class="cd st"><div class="n">${st_assoc}</div><div class="l">Associated Domains</div></div></div>
STEOF
        [[ -s "$od/raw/securitytrails_assoc.txt" ]] && {
            printf '<h3>Associated Domains</h3><pre>' >> "$html"
            _html_escape_file "$od/raw/securitytrails_assoc.txt" 30 >> "$html"
            printf '</pre>' >> "$html"
        }
        printf '</div>\n' >> "$html"
    fi

    # مشكلة 12: الـ label ثابت لكن لازم نتأكد إن الـ count رقم
    local sec file label
    for sec in \
        "assets/subdomains/all.txt:Subdomains" \
        "processed/fingerprint.txt:Services" \
        "processed/open_ports.txt:Ports" \
        "processed/subjack.txt:Takeovers" \
        "processed/nuclei_results.txt:Vulnerabilities" \
        "processed/cloud_assets.txt:Cloud Assets" \
        "processed/waf_results.txt:WAF Detection" \
        "processed/technologies.csv:Technologies" \
        "processed/technologies.txt:Technologies"; do
        file="${sec%%:*}"; label="${sec#*:}"
        [[ -s "$od/$file" ]] || continue
        local fc; fc=$(_safe_count "$od/$file")
        [[ "$fc" =~ ^[0-9]+$ ]] || fc=0
        # label ثابت وآمن، بس نعمله escape برضو للحماية
        printf '<div class="s"><h2>%s <span class="badge info">%s</span></h2><pre>' \
            "$(_html_escape "$label")" "$fc" >> "$html"
        # مشكلة 12: المحتوى بيتعمله escape عبر _html_escape_file
        _html_escape_file "$od/$file" 50 >> "$html"
        printf '</pre></div>\n' >> "$html"
    done

    printf '<div class="s"><h2>Health</h2><p>Errors: %d | Warnings: %d | Duration: %ds</p></div>' \
        "$ERROR_COUNT" "$WARNING_COUNT" "$el" >> "$html"
    printf '<div class="ft">TheN0thing v%s</div>' \
        "$sv_escaped" >> "$html"
    printf '</div></body></html>' >> "$html"
    log "SUCCESS" "HTML: $html"
}

# مشكلة 17: gen_multi مع escaping
gen_multi() {
    local pd="$1" inf="$2" rf="$pd/summary.md"
    local tot
    tot=$(grep -vcE '^[[:space:]]*#|^[[:space:]]*$' "$inf" 2>/dev/null) || tot=0
    tot="${tot//[[:space:]]/}"; [[ "$tot" =~ ^[0-9]+$ ]] || tot=0
    printf '# Multi (%s) v%s %s\n\n| Target | Subs | IPs | URLs | Ports |\n|--------|------|-----|------|-------|\n' \
        "$tot" "$VERSION" "$(date "+%Y-%m-%d %H:%M:%S")" > "$rf"
    local td bn
    for td in "$pd"/*/; do
        [[ -d "$td" && ! "$td" =~ reports/$ ]] || continue
        bn=$(basename "$td")
        # مشكلة 17: sanitize الـ target name في markdown
        # Markdown injection أقل خطورة من HTML بس برضو نحمي
        bn="${bn//|/}"  # شيل pipe characters اللي ممكن تكسر الـ table
        bn="${bn//[^a-zA-Z0-9._-]/}"  # خلّي حروف آمنة بس
        printf '| %s | %s | %s | %s | %s |\n' \
            "$bn" \
            "$(_safe_count "$td/assets/subdomains/all.txt")" \
            "$(_safe_count "$td/assets/ips/all.txt")" \
            "$(_safe_count "$td/processed/all_urls.txt")" \
            "$(_safe_count "$td/processed/open_ports.txt")" >> "$rf"
    done
}

# ══════════════════════════════════════════
# PROCESS TARGET (مشكلة 11: resume + output تضارب)
# (مشكلة 16: whitelist names)
# (مشكلة 19: phase counter)
# ══════════════════════════════════════════
process_target() {
    local _cfgname="$1"
    # مشكلة 16: توسيع الـ whitelist لتشمل _sscan
    [[ "$_cfgname" =~ ^_(iscan|mscan|sscan)$ ]] || {
        log "ERROR" "[process_target] Rejected name: $_cfgname"
        return 1
    }
    local _decl_output
    _decl_output=$(declare -p "$_cfgname" 2>/dev/null) || {
        log "ERROR" "[process_target] Undeclared: $_cfgname"
        return 1
    }
    [[ "$_decl_output" == "declare -A $_cfgname="* ]] || {
        log "ERROR" "[process_target] Not assoc array: $_cfgname"
        return 1
    }
    local -n _pt_cfg="$_cfgname"
    local tgt="${_pt_cfg[target]}" od="${_pt_cfg[output_dir]}"
    local wl="${_pt_cfg[wordlist]:-$WORDLISTS}" rs="${_pt_cfg[resolvers]:-$RESOLVERS}"
    local thr="${_pt_cfg[threads]:-$THREADS}" pts="${_pt_cfg[ports]:-$WEB_PORTS}"
    local ss="${_pt_cfg[screenshots]:-false}" fast="${_pt_cfg[fast]:-false}"
    local tt="${_pt_cfg[target_type]}"
    tgt=$(sanitize_target "$tgt") || return 1
    acquire_lock "$tgt" || return 1
    local _lt="$tgt" _lh=true ok=true
    case "$tt" in
        domain) validate_domain "$tgt" || { log "ERROR" "Invalid domain: $tgt"; ok=false; } ;;
        ip) validate_ip "$tgt" || { log "ERROR" "Invalid IP: $tgt"; ok=false; } ;;
        asn) validate_asn "$tgt" || { log "ERROR" "Invalid ASN: $tgt"; ok=false; } ;;
        *) log "ERROR" "Unsupported type: $tt"; ok=false ;;
    esac
    [[ "$ok" == false ]] && {
        [[ "$_lh" == true ]] && { release_lock "$_lt"; _lh=false; }
        return 1
    }

    # مشكلة 11: معالجة التضارب بين --resume و -o
    if [[ -n "$RESUME_DIR" && -d "$RESUME_DIR" ]]; then
        # لو المستخدم حدد -o مع --resume، نحذّره
        if [[ -n "${_pt_cfg[output_dir]}" && "${_pt_cfg[output_dir]}" != "$RESUME_DIR" ]]; then
            log "WARNING" "[resume] --resume overrides -o (using: $RESUME_DIR)"
        fi
        od="$RESUME_DIR"
        # تحقق إن الـ resume dir فيه الـ structure المطلوب
        if [[ ! -d "$od/raw" || ! -d "$od/assets" ]]; then
            log "ERROR" "[resume] Invalid resume dir (missing raw/ or assets/): $od"
            [[ "$_lh" == true ]] && { release_lock "$_lt"; _lh=false; }
            return 1
        fi
        log "INFO" "Resuming from: $od"
    else
        od=$(setup_dirs "$tgt" "$od") || {
            log "ERROR" "setup_dirs failed"
            [[ "$_lh" == true ]] && { release_lock "$_lt"; _lh=false; }
            return 1
        }
        [[ -z "$od" || ! -d "$od" ]] && {
            log "ERROR" "Output dir invalid"
            [[ "$_lh" == true ]] && { release_lock "$_lt"; _lh=false; }
            return 1
        }
    fi

    log "INFO" "=== $tgt ($tt) T:$thr R:$RATE_LIMIT ==="
    [[ -n "$SECURITYTRAILS_KEY" ]] && log "INFO" "SecurityTrails: enabled"
    send_notification "Started" "$tgt ($tt)"

    local scan_id=""
    [[ "$DB_EXPORT" == true ]] && scan_id=$(db_start_scan "$tgt" "$tt" "${SCAN_PROFILE:-default}")

    # مشكلة 19: phase counter ثابت بغض النظر عن fast mode
    # كل phase عندها رقم ثابت مش بيتغير
    local -r PH_PASSIVE=1 PH_ACTIVE=2 PH_SERVICES=3 PH_DEEP=4 PH_EXTENDED=5 PH_SCREENSHOTS=6 PH_REPORTS=7

    # Phase 1: Passive
    if should_run_phase "$od" "$PH_PASSIVE"; then
        log "INFO" "P${PH_PASSIVE}: Passive Enumeration"
        case "$tt" in
            domain) run_dom_enum "$tgt" "$od" "$thr" ;;
            ip) run_ip_enum "$tgt" "$od" ;;
            asn) run_asn_enum "$tgt" "$od" ;;
        esac
        run_critical "proc" proc_passive "$od" || true
        run_plugins "post_passive" "$od"
        save_checkpoint "$od" "$PH_PASSIVE"
        log "SUCCESS" "P${PH_PASSIVE} complete"
    else
        log "INFO" "P${PH_PASSIVE}: Skipped (resume)"
    fi

    # Phase 2: Active
    if [[ "$fast" != true && "$fast" != passive ]]; then
        if should_run_phase "$od" "$PH_ACTIVE"; then
            log "INFO" "P${PH_ACTIVE}: Active Enumeration"
            run_active "$tgt" "$od" "$wl" "$rs" "$tt"
            run_plugins "post_active" "$od"
            save_checkpoint "$od" "$PH_ACTIVE"
            log "SUCCESS" "P${PH_ACTIVE} complete"
        else
            log "INFO" "P${PH_ACTIVE}: Skipped (resume)"
        fi
    fi

    # Phase 3: Services
    if [[ "$fast" != passive ]]; then
        if should_run_phase "$od" "$PH_SERVICES"; then
            log "INFO" "P${PH_SERVICES}: Service Discovery"
            fingerprint "$od" "$pts" "$thr"
            enrich "$od"
            save_checkpoint "$od" "$PH_SERVICES"
            log "SUCCESS" "P${PH_SERVICES} complete"
        else
            log "INFO" "P${PH_SERVICES}: Skipped (resume)"
        fi

        # Phase 4: Deep Scan
        if [[ "$fast" != true ]]; then
            if should_run_phase "$od" "$PH_DEEP"; then
                log "INFO" "P${PH_DEEP}: Deep Scan"
                run_par \
                    subjack_scan "$od" "$_SEP" \
                    dnsx_scan "$od" "$_SEP" \
                    mapcidr_scan "$od" "$_SEP" \
                    naabu_scan "$od" "$pts" "$_SEP" \
                    spider "$od" "$tgt" "$tt"
                save_checkpoint "$od" "$PH_DEEP"
                log "SUCCESS" "P${PH_DEEP} complete"
            else
                log "INFO" "P${PH_DEEP}: Skipped (resume)"
            fi

            # Phase 5: Extended
            if should_run_phase "$od" "$PH_EXTENDED"; then
                log "INFO" "P${PH_EXTENDED}: Extended Analysis"
                run_par \
                    detect_waf "$od" "$_SEP" \
                    detect_tech "$od" "$_SEP" \
                    run_nuclei "$od" "$_SEP" \
                    detect_cloud "$od" "$tgt"
                run_plugins "post_scan" "$od"
                save_checkpoint "$od" "$PH_EXTENDED"
                log "SUCCESS" "P${PH_EXTENDED} complete"
            else
                log "INFO" "P${PH_EXTENDED}: Skipped (resume)"
            fi
        fi

        # Phase 6: Screenshots
        [[ "$ss" == true ]] && should_run_phase "$od" "$PH_SCREENSHOTS" && {
            log "INFO" "P${PH_SCREENSHOTS}: Screenshots"
            screenshots "$od"
            save_checkpoint "$od" "$PH_SCREENSHOTS"
            log "SUCCESS" "P${PH_SCREENSHOTS} complete"
        }
    fi

    # Phase 7: Reports (دايماً بيشتغل)
    log "INFO" "P${PH_REPORTS}: Reports"
    _sync_counters
    analyze "$od"
    gen_report "$od" "$tgt" "$tt"
    gen_html_report "$od" "$tgt" "$tt"
    run_plugins "report" "$od"
    save_checkpoint "$od" "$PH_REPORTS"

    [[ -n "$scan_id" ]] && {
        db_end_scan "$scan_id" "$od"
        db_import_assets "$scan_id" "$od"
    }
    [[ "$_lh" == true ]] && { release_lock "$_lt"; _lh=false; }
    _prune; CHILD_PIDS=()
    send_notification "Done" "$tgt S:$(_safe_count "$od/assets/subdomains/all.txt") U:$(_safe_count "$od/processed/all_urls.txt")"
    log "SUCCESS" "$tgt -> $od"
}

# ══════════════════════════════════════════
# INTERACTIVE MODE (مشكلة 14 + 20)
# ══════════════════════════════════════════
interactive_mode() {
    log "INFO" "Interactive mode"
    printf '%b\n  TheN0thing v%s\n\n%b' "$C_CYAN" "$VERSION" "$C_RESET"
    local cmd
    while true; do
        printf '%bN0%b> ' "$C_GREEN" "$C_RESET" >&2
        IFS= read -r cmd || break
        local cn="${cmd%% *}"; cn="${cn//[[:space:]]/}"
        local ca="${cmd#* }"; [[ "$ca" == "$cn" ]] && ca=""
        case "$cn" in
            ""|help)
                printf '  scan|scan-fast|scan-full <t> | history | assets [type]\n' >&2
                printf '  plugins | schedules | config | status | clear | exit\n' >&2
                printf '  sectrails <domain>  - SecurityTrails lookup\n' >&2
                ;;
            scan|scan-fast|scan-full)
                [[ -z "$ca" ]] && { log "ERROR" "Need target"; continue; }
                local _t; _t=$(sanitize_target "$ca") || continue
                local _tt; _tt=$(detect_type "$_t")
                [[ "$_tt" == unknown ]] && continue
                local _od; _od=$(_val_opath "output/$_t") || continue
                local _f=false _s=false _p="$WEB_PORTS"
                case "$cn" in
                    scan-fast) _f=true ;;
                    scan-full) _s=true; _p="$EXT_PORTS" ;;
                esac
                unset _iscan 2>/dev/null || true
                declare -A _iscan=(
                    [target]="$_t" [output_dir]="$_od"
                    [wordlist]="$WORDLISTS" [resolvers]="$RESOLVERS"
                    [threads]="$THREADS" [ports]="$_p"
                    [screenshots]="$_s" [fast]="$_f" [target_type]="$_tt"
                )
                process_target _iscan || true
                unset _iscan 2>/dev/null || true
                ;;
            sectrails)
                [[ -z "$ca" ]] && { log "ERROR" "Need domain"; continue; }
                [[ -z "$SECURITYTRAILS_KEY" ]] && { log "ERROR" "SECURITYTRAILS_KEY not set"; continue; }
                local _st; _st=$(sanitize_target "$ca") || continue
                validate_domain "$_st" || { log "ERROR" "Invalid domain"; continue; }
                # مشكلة 20: cleanup مضمون عبر trap أو explicit cleanup
                local _stdir; _stdir=$(_mktmp stdir) || continue
                rm -f "$_stdir"; mkdir -p "$_stdir" 2>/dev/null || {
                    log "ERROR" "Cannot create temp dir"; continue
                }
                # ننفذ في subshell عشان لو حصل error الـ cleanup يشتغل
                (
                    _en_sectrails "$_st" "$_stdir"
                ) || true
                printf '\n%b--- SecurityTrails: %s ---%b\n' "$C_CYAN" "$_st" "$C_RESET" >&2
                [[ -s "$_stdir/securitytrails.txt" ]] && {
                    printf '%bSubdomains:%b %s\n' "$C_GREEN" "$C_RESET" \
                        "$(_safe_count "$_stdir/securitytrails.txt")" >&2
                    head -10 "$_stdir/securitytrails.txt" >&2
                }
                [[ -s "$_stdir/securitytrails_ips.txt" ]] && {
                    printf '%bHistorical IPs:%b %s\n' "$C_GREEN" "$C_RESET" \
                        "$(_safe_count "$_stdir/securitytrails_ips.txt")" >&2
                    head -10 "$_stdir/securitytrails_ips.txt" >&2
                }
                [[ -s "$_stdir/securitytrails_assoc.txt" ]] && {
                    printf '%bAssociated:%b %s\n' "$C_GREEN" "$C_RESET" \
                        "$(_safe_count "$_stdir/securitytrails_assoc.txt")" >&2
                    head -10 "$_stdir/securitytrails_assoc.txt" >&2
                }
                # مشكلة 20: cleanup دايماً
                rm -rf "$_stdir" 2>/dev/null
                ;;
            history)
                [[ "$DB_EXPORT" == true ]] && db_show_history || log "WARNING" "DB off (use --db)"
                ;;
            assets)
                local atype="${ca//[[:space:]]/}"
                [[ -z "$atype" ]] && atype="subdomain"
                case "$atype" in
                    subdomain|ip|asn|cidr) ;;
                    *) log "ERROR" "Bad type: $atype"; continue ;;
                esac
                [[ "$DB_EXPORT" == true ]] && db_show_assets "$atype" || log "WARNING" "DB off"
                ;;
            plugins)
                local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
                shopt -s nullglob; local -a pls=("${PLUGIN_DIR}"/*.sh); eval "$sv"
                (( ${#pls[@]} )) && {
                    local pf; for pf in "${pls[@]}"; do
                        printf '  %s\n' "$(basename "$pf" .sh)" >&2
                    done
                } || printf '  None\n' >&2
                ;;
            schedules) list_schedules ;;
            config)
                printf '  T=%s TO=%s R=%s RL=%s\n' \
                    "$THREADS" "$TIMEOUT" "$MAX_RETRIES" "$RATE_LIMIT" >&2
                printf '  SecurityTrails: %s\n' \
                    "$([[ -n "$SECURITYTRAILS_KEY" ]] && echo "enabled" || echo "disabled")" >&2
                ;;
            status)
                _sync_counters
                # مشكلة 14: START_TIME مش معرّف - استخدام START_EPOCH
                local now_s; now_s=$(date +%s 2>/dev/null) || now_s=$START_EPOCH
                local uptime_s=$(( now_s - START_EPOCH ))
                (( uptime_s < 0 )) && uptime_s=0
                printf '  v%s PID=%s Up=%ss E=%d W=%d\n' \
                    "$VERSION" "$$" "$uptime_s" \
                    "$ERROR_COUNT" "$WARNING_COUNT" >&2
                ;;
            clear) clear ;;
            exit|quit) break ;;
            *) printf '  Unknown. Type "help"\n' >&2 ;;
        esac
    done
    log "INFO" "Session ended"
}

# ══════════════════════════════════════════
# BANNER & USAGE
# ══════════════════════════════════════════
banner() {
    printf "%b" "$C_GREEN"
    cat << 'B'
  ████████╗██╗  ██╗███████╗███╗   ██╗ ██████╗ ████████╗██╗  ██╗██╗███╗   ██╗ ██████╗
  ╚══██╔══╝██║  ██║██╔════╝████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║██║████╗  ██║██╔════╝
     ██║   ███████║█████╗  ██╔██╗ ██║██║   ██║   ██║   ███████║██║██╔██╗ ██║██║  ███╗
     ██║   ██╔══██║██╔══╝  ██║╚██╗██║██║   ██║   ██║   ██╔══██║██║██║╚██╗██║██║   ██║
     ██║   ██║  ██║███████╗██║ ╚████║╚██████╔╝   ██║   ██║  ██║██║██║ ╚████║╚██████╔╝
     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝
B
    printf "%b  v%s%b\n\n" "$C_CYAN" "$VERSION" "$C_RESET"
}

usage() {
    banner
    cat << EOF
${C_BOLD}USAGE${C_RESET}  $SCRIPT_NAME [OPTS] <target> | --file FILE | --interactive
  -o DIR -w FILE -r FILE -t NUM -p PORTS -a -s -f -v --all-options
  --type domain|ip|asn --file FILE --profile NAME --scope FILE --out-of-scope FILE
  --notify slack|discord|telegram --webhook-url URL --bot-token T --chat-id ID
  --db --db-history --db-assets [type] --db-query SQL
  --create-plugin NAME --list-plugins --schedule 'CRON' target --list-schedules
  --remove-schedule ID --config FILE --log-level LVL --no-cache --no-color
  --rate-limit NUM --resume DIR --diff OLD NEW --interactive --check-update --self-update

${C_BOLD}API KEYS${C_RESET}
  Set in ~/.config/then0thing/api_tokens.conf or environment:
  SECURITYTRAILS_KEY  GITHUB_TOKEN  CHAOS_KEY  SHODAN_KEY
  CENSYS_API_ID  CENSYS_API_SECRET  GITLAB_TOKEN  SPYSE_API_TOKEN

${C_BOLD}PROFILES${C_RESET}
  stealth   - Slow & quiet (T:10 R:10)
  passive   - Passive only (T:50 R:50)
  default   - Balanced (T:100 R:150)
  bounty    - Bug bounty (T:200 R:300)
  aggressive- Fast & loud (T:300 R:500)
  ci        - CI/CD pipeline (T:50 R:100)

${C_BOLD}EXAMPLES${C_RESET}
  $SCRIPT_NAME example.com
  $SCRIPT_NAME example.com --profile bounty -a -s --db
  $SCRIPT_NAME --file targets.txt --profile bounty --notify telegram --bot-token T --chat-id ID
  $SCRIPT_NAME --resume output/example.com -v
  $SCRIPT_NAME --interactive
EOF
    exit 0
}

# ══════════════════════════════════════════
# ARGUMENT PARSING (مشكلة 15: --db-assets shift)
# ══════════════════════════════════════════
_PARSED_TGT="" _PARSED_OD="" _PARSED_WL="" _PARSED_RS=""
_PARSED_THR="" _PARSED_PTS="" _PARSED_SS="" _PARSED_FAST=""
_PARSED_TT="" _PARSED_INF="" _PARSED_ALLOP="" _PARSED_CCFG=""

parse_args() {
    local tgt="" od="" wl="$WORDLISTS" rs="$RESOLVERS" thr="$THREADS" pts="$WEB_PORTS"
    local ss=false fast=false tt="" inf="" allop=false ccfg=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                od=$(_val_opath "$2") || exit 1; shift 2 ;;
            -w|--wordlist)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                wl=$(_val_file "$2" WL) || exit 1; shift 2 ;;
            -r|--resolvers)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                rs=$(_val_file "$2" RS) || exit 1; shift 2 ;;
            -t|--threads)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^[0-9]+$ ]] || { log "ERROR" "Invalid threads: $2"; exit 1; }
                thr=$(_clamp T "$2" 1 "$MAX_THREADS_LIMIT"); shift 2 ;;
            -p|--ports)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                _val_ports "$2" || exit 1
                pts="${2#,}"; pts="${pts%,}"; shift 2 ;;
            --rate-limit)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^[0-9]+$ ]] || { log "ERROR" "Invalid rate-limit: $2"; exit 1; }
                RATE_LIMIT=$(_clamp RL "$2" 1 "$MAX_RATE_LIMIT"); shift 2 ;;
            -a|--all-ports)  pts="$EXT_PORTS"; shift ;;
            -s|--screenshot) ss=true; shift ;;
            -f|--fast)       fast=true; shift ;;
            -v|--verbose)    LOG_LEVEL=DEBUG; shift ;;
            --type)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^(domain|ip|asn)$ ]] || { log "ERROR" "Invalid type: $2"; exit 1; }
                tt="$2"; shift 2 ;;
            --file)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                inf="$2"; shift 2 ;;
            --all-options) allop=true; shift ;;
            --config)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                ccfg=$(_val_file "$2" Cfg) || exit 1; shift 2 ;;
            --log-level)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$ ]] || { log "ERROR" "Invalid log level: $2"; exit 1; }
                LOG_LEVEL="$2"; shift 2 ;;
            --no-cache) USE_CACHE=false; shift ;;
            --no-color) NOCOLOR=1; _setup_colors; shift ;;
            --profile)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                SCAN_PROFILE="$2"; shift 2 ;;
            --scope)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                SCOPE_FILE=$(_val_file "$2" Scope) || exit 1; shift 2 ;;
            --out-of-scope)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                OOS_FILE=$(_val_file "$2" OOS) || exit 1; shift 2 ;;
            --notify)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^(slack|discord|telegram)$ ]] || { log "ERROR" "Invalid notify: $2"; exit 1; }
                NOTIFY_METHOD="$2"; shift 2 ;;
            --webhook-url)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                _validate_url "$2" || { log "ERROR" "Invalid webhook URL"; exit 1; }
                NOTIFY_WEBHOOK="$2"; shift 2 ;;
            --bot-token)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^[a-zA-Z0-9:_-]+$ ]] || { log "ERROR" "Invalid bot token"; exit 1; }
                NOTIFY_BOT_TOKEN="$2"; shift 2 ;;
            --chat-id)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ "$2" =~ ^-?[0-9]+$ ]] || { log "ERROR" "Invalid chat ID"; exit 1; }
                NOTIFY_CHAT_ID="$2"; shift 2 ;;
            --resume)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing value for $1"; exit 1; }
                [[ -d "$2" ]] || { log "ERROR" "Resume dir not found: $2"; exit 1; }
                RESUME_DIR="$2"; shift 2 ;;
            --diff)
                [[ $# -lt 3 ]] && { log "ERROR" "Need two dirs for diff"; exit 1; }
                DIFF_OLD="$2"; DIFF_NEW="$3"; shift 3 ;;
            --interactive) INTERACTIVE_MODE=true; shift ;;
            --db) DB_EXPORT=true; shift ;;
            --db-history)
                DB_EXPORT=true; banner; db_init; db_show_history; exit 0 ;;
            --db-assets)
                DB_EXPORT=true; banner; db_init
                local at="subdomain"
                # مشكلة 15: shift logic مظبوطة
                if [[ $# -ge 2 && "$2" != -* ]]; then
                    [[ "$2" =~ ^(subdomain|ip|asn|cidr)$ ]] || { log "ERROR" "Bad asset type: $2"; exit 1; }
                    at="$2"; shift  # shift الـ type بس
                fi
                shift  # shift الـ --db-assets نفسه
                db_show_assets "$at"; exit 0 ;;
            --db-query)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing query"; exit 1; }
                DB_EXPORT=true; db_init; db_query "$2"; exit 0 ;;
            --create-plugin)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing plugin name"; exit 1; }
                create_plugin_template "$2"; exit 0 ;;
            --list-plugins)
                banner
                local sv; sv=$(shopt -p nullglob 2>/dev/null) || sv="shopt -u nullglob"
                shopt -s nullglob; local -a pls=("${PLUGIN_DIR}"/*.sh); eval "$sv"
                (( ${#pls[@]} )) && {
                    local pf; for pf in "${pls[@]}"; do printf '  %s\n' "$(basename "$pf" .sh)"; done
                } || printf '  None\n'
                exit 0 ;;
            --schedule)
                [[ $# -lt 3 ]] && { log "ERROR" "Need cron expr + target"; exit 1; }
                setup_schedule "$2" "$3" "${4:-}"; exit 0 ;;
            --list-schedules) banner; list_schedules; exit 0 ;;
            --remove-schedule)
                [[ $# -lt 2 ]] && { log "ERROR" "Missing schedule ID"; exit 1; }
                remove_schedule "$2"; exit 0 ;;
            --check-update)
                AUTO_UPDATE=true; banner; check_update; exit 0 ;;
            --self-update) banner; self_update; exit $? ;;
            -h|--help) usage ;;
            -*) log "ERROR" "Unknown option: $1"; usage ;;
            *)
                [[ -z "$tgt" ]] && { tgt="$1"; shift; } || { log "ERROR" "Extra arg: $1"; usage; }
                ;;
        esac
    done
    _PARSED_TGT="$tgt" _PARSED_OD="$od" _PARSED_WL="$wl"
    _PARSED_RS="$rs" _PARSED_THR="$thr" _PARSED_PTS="$pts"
    _PARSED_SS="$ss" _PARSED_FAST="$fast" _PARSED_TT="$tt"
    _PARSED_INF="$inf" _PARSED_ALLOP="$allop" _PARSED_CCFG="$ccfg"
}

# ══════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════
main() {
    parse_args "$@"
    local tgt="$_PARSED_TGT" inf="$_PARSED_INF"
    local od="$_PARSED_OD" wl="$_PARSED_WL"
    local rs="$_PARSED_RS" thr="$_PARSED_THR"
    local pts="$_PARSED_PTS" ss="$_PARSED_SS"
    local fast="$_PARSED_FAST" tt="$_PARSED_TT"
    local allop="$_PARSED_ALLOP" ccfg="$_PARSED_CCFG"
    [[ -n "$ccfg" ]] && CONFIG_FILE="$ccfg"
    load_config
    _load_scope_patterns
    [[ -n "$SCAN_PROFILE" ]] && {
        apply_profile "$SCAN_PROFILE" || exit 1
        thr="$THREADS"
        [[ -n "${PROFILE_FAST:-}" ]] && fast="$PROFILE_FAST"
    }
    [[ "$allop" == true ]] && { pts="$EXT_PORTS"; ss=true; LOG_LEVEL=DEBUG; }

    [[ -n "$DIFF_OLD" && -n "$DIFF_NEW" ]] && {
        banner
        [[ -d "$DIFF_OLD" && -d "$DIFF_NEW" ]] || { log "ERROR" "Dirs missing"; exit 1; }
        run_diff "$DIFF_OLD" "$DIFF_NEW"
        exit 0
    }
    [[ "$INTERACTIVE_MODE" == true ]] && {
        banner; check_deps || exit 1; db_init; load_plugins
        interactive_mode; exit 0
    }
    [[ -z "$tgt" && -z "$inf" ]] && { log "ERROR" "No target specified"; usage; }
    banner; check_deps || exit 1; cache_purge; db_init; load_plugins
    [[ "$AUTO_UPDATE" == true ]] && check_update

    if [[ -n "$inf" ]]; then
        local inf_r; inf_r=$(_val_file "$inf" Input) || exit 1
        local pd; pd=$(_val_opath "output/multi_$(date +%Y%m%d_%H%M%S)") || exit 1
        mkdir -p "$pd" 2>/dev/null || true
        local tot pr=0
        tot=$(grep -vcE '^[[:space:]]*#|^[[:space:]]*$' "$inf_r" 2>/dev/null) || tot=0
        tot="${tot//[[:space:]]/}"; [[ "$tot" =~ ^[0-9]+$ ]] || tot=0
        (( tot > MAX_TARGETS )) && { log "ERROR" "$tot > $MAX_TARGETS limit"; exit 1; }
        local ln
        while IFS= read -r ln || [[ -n "$ln" ]]; do
            [[ -z "$ln" || "$ln" =~ ^[[:space:]]*# ]] && continue
            local dfree; dfree=$(_get_disk_free_kb "$pd")
            (( dfree < 524288 )) && { log "CRITICAL" "Low disk space"; break; }
            local ct="${ln//[[:space:]]/}"
            (( ${#ct} > 253 )) && { ((pr++)); continue; }
            local st2; st2=$(sanitize_target "$ct") || { ((pr++)); continue; }
            local ct2="$tt"
            [[ -z "$ct2" ]] && ct2=$(detect_type "$st2")
            [[ "$ct2" == unknown || "$ct2" == ip_range ]] && { ((pr++)); continue; }
            local to; to=$(_val_opath "$pd/$st2") || { ((pr++)); continue; }
            unset _mscan 2>/dev/null || true
            declare -A _mscan=(
                [target]="$st2" [output_dir]="$to"
                [wordlist]="$wl" [resolvers]="$rs"
                [threads]="$thr" [ports]="$pts"
                [screenshots]="$ss" [fast]="$fast" [target_type]="$ct2"
            )
            process_target _mscan || true
            unset _mscan 2>/dev/null || true
            ((pr++))
            show_prog "$pr" "$tot" Targets
        done < "$inf_r"
        gen_multi "$pd" "$inf_r"
        log "SUCCESS" "All targets -> $pd"
    else
        [[ -z "$tt" ]] && {
            tt=$(detect_type "$tgt")
            [[ "$tt" == unknown ]] && { log "ERROR" "Unknown target type: $tgt"; exit 1; }
            [[ "$tt" == ip_range ]] && { log "ERROR" "IP ranges not supported directly"; exit 1; }
        }
        [[ -z "$od" ]] && { od=$(_val_opath "output/$tgt") || exit 1; }
        unset _sscan 2>/dev/null || true
        declare -A _sscan=(
            [target]="$tgt" [output_dir]="$od"
            [wordlist]="$wl" [resolvers]="$rs"
            [threads]="$thr" [ports]="$pts"
            [screenshots]="$ss" [fast]="$fast" [target_type]="$tt"
        )
        process_target _sscan || exit 1
        unset _sscan 2>/dev/null || true
    fi
    rotate_logs; _sync_counters
    local now_epoch; now_epoch=$(date +%s 2>/dev/null) || now_epoch=$START_EPOCH
    local elapsed=$(( now_epoch - START_EPOCH )); (( elapsed < 0 )) && elapsed=0
    log "SUCCESS" "Completed in ${elapsed}s | E:$ERROR_COUNT W:$WARNING_COUNT"
    send_notification "Complete" "${elapsed}s E:$ERROR_COUNT W:$WARNING_COUNT"
}

main "$@"
