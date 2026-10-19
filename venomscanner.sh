#!/usr/bin/env bash
# venomscanner.sh - Hacker-style network scanner (host discovery + TCP port scan)
# Pure bash: uses ping and /dev/tcp, no nmap required.
# Only scan networks and hosts you own or have written permission to test.

set -u

VERSION="2.1"
TIMEOUT=1
JOBS=50
PORTS="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
SKIP_PING=0
VERSION_SCAN=0
BANNER_WAIT=2
OUTFILE=""
TARGET=""
USE_COLOR=0
[[ -t 1 ]] && USE_COLOR=1
RISKY_PORTS=" 21 23 135 139 445 3389 5900 "

# ------------------------------------------------------------------ colors
setup_colors() {
    if (( USE_COLOR )); then
        G=$'\e[38;5;46m'   # neon green
        DG=$'\e[38;5;34m'  # dark green
        R=$'\e[38;5;196m'  # red
        Y=$'\e[38;5;226m'  # yellow
        C=$'\e[38;5;51m'   # cyan
        GR=$'\e[38;5;240m' # grey
        B=$'\e[1m'
        X=$'\e[0m'
    else
        G=""; DG=""; R=""; Y=""; C=""; GR=""; B=""; X=""
    fi
}
setup_colors

# ------------------------------------------------------------------ ui
banner() {
    local line
    local art=(
' __     __                            '
' \ \   / /__ _ __   ___  _ __ ___     '
'  \ \ / / _ \  _ \ / _ \|  _   _ \    '
'   \ V /  __/ | | | (_) | | | | | |   '
'    \_/ \___|_| |_|\___/|_| |_| |_|   '
    )
    echo
    for line in "${art[@]}"; do
        printf '%s%s%s\n' "$G" "$line" "$X"
        [[ -t 1 ]] && sleep 0.04
    done
    printf '%s    S  C  A  N  N  E  R   %sv%s%s\n' "$B$C" "$GR" "$VERSION" "$X"
    printf '%s    ─────────────────────────────────────%s\n' "$DG" "$X"
    printf '%s    [!] authorized targets only. you are responsible.%s\n\n' "$Y" "$X"
}

typewrite() {
    local text=$1 i
    if [[ -t 1 ]]; then
        for (( i = 0; i < ${#text}; i++ )); do
            printf '%s' "${text:i:1}"; sleep 0.012
        done
        echo
    else
        echo "$text"
    fi
}

usage() {
    banner
    cat <<EOF
${B}USAGE${X}
  venomscanner [options] <target>

${B}TARGET${X}
  Single IP (192.168.1.10), CIDR (192.168.1.0/24), or hostname

${B}OPTIONS${X}
  -p <ports>   Ports: list and/or ranges, e.g. 22,80,443 or 1-1024
               (default: common ports)
  -t <secs>    Timeout per probe in seconds (default: $TIMEOUT)
  -j <num>     Parallel jobs (default: $JOBS)
  -sV          Service/version detection via banner grabbing (like nmap -sV)
  -n           No ping; treat every host as up (for hosts blocking ICMP)
  -o <file>    Save results to a file (colors stripped)
  -c           Disable colors and animations
  -h           Show this help

${B}EXAMPLES${X}
  venomscanner 192.168.1.0/24
  venomscanner -p 1-1024 192.168.1.10
  venomscanner -n -p 22,80,443 -o results.txt 10.0.0.0/28
  venomscanner -sV -p 1-1024 192.168.1.57
EOF
}

die() { printf '%s[x] Error:%s %s\n' "$R" "$X" "$*" >&2; exit 1; }

hide_cursor() { [[ -t 1 ]] && printf '\e[?25l'; }
show_cursor() { [[ -t 1 ]] && printf '\e[?25h'; }

SPIN=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
SPIN_I=0

draw_progress() {
    [[ -t 1 ]] || return 0
    local done_n pct width=32 filled bar="" i
    done_n=$(find "$DONE" -type f 2>/dev/null | wc -l)
    (( TOTAL > 0 )) || return 0
    pct=$(( done_n * 100 / TOTAL ))
    filled=$(( done_n * width / TOTAL ))
    for (( i = 0; i < width; i++ )); do
        if (( i < filled )); then bar+="█"; else bar+="░"; fi
    done
    SPIN_I=$(( (SPIN_I + 1) % ${#SPIN[@]} ))
    printf '\r%s%s%s %sSCANNING%s %s[%s%s%s]%s %3d%%  %s%d/%d hosts%s ' \
        "$C" "${SPIN[$SPIN_I]}" "$X" "$B$G" "$X" "$DG" "$G" "$bar" "$DG" "$X" \
        "$pct" "$GR" "$done_n" "$TOTAL" "$X"
}

# ------------------------------------------------------------------ net helpers
ip2int() {
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
    local n=$1
    echo "$(( (n >> 24) & 255 )).$(( (n >> 16) & 255 )).$(( (n >> 8) & 255 )).$(( n & 255 ))"
}

valid_ip() {
    local ip=$1 o
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    for o in $ip; do (( o <= 255 )) || return 1; done
}

expand_target() {
    local t=$1
    if [[ $t == */* ]]; then
        local base=${t%/*} bits=${t#*/}
        valid_ip "$base" || die "Invalid IP in CIDR: $base"
        [[ $bits =~ ^[0-9]+$ ]] && (( bits >= 16 && bits <= 32 )) \
            || die "CIDR prefix must be between 16 and 32"
        local mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
        local net=$(( $(ip2int "$base") & mask ))
        local count=$(( 1 << (32 - bits) )) i start=0 end
        end=$count
        if (( bits < 31 )); then start=1; end=$(( count - 1 )); fi
        for (( i = start; i < end; i++ )); do int2ip $(( net + i )); done
    elif valid_ip "$t"; then
        echo "$t"
    else
        local ip
        ip=$(getent ahostsv4 "$t" | awk 'NR==1{print $1}')
        [[ -n $ip ]] || die "Cannot resolve hostname: $t"
        echo "$ip"
    fi
}

expand_ports() {
    local spec=$1 part
    local IFS=,
    for part in $spec; do
        if [[ $part =~ ^[0-9]+$ ]]; then
            (( part >= 1 && part <= 65535 )) || die "Bad port: $part"
            echo "$part"
        elif [[ $part =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local lo=${BASH_REMATCH[1]} hi=${BASH_REMATCH[2]}
            (( lo >= 1 && hi <= 65535 && lo <= hi )) || die "Bad range: $part"
            seq "$lo" "$hi"
        else
            die "Bad port spec: $part"
        fi
    done
}

host_up()   { ping -c 1 -W "$TIMEOUT" "$1" >/dev/null 2>&1; }
port_open() { timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }

service_name() {
    local name
    name=$(getent services "$1/tcp" 2>/dev/null | awk '{print $1}')
    echo "${name:-unknown}"
}

# ---- service / version detection (banner grabbing) ----
HTTP_PROBE='HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: venomscanner\r\nConnection: close\r\n\r\n'

grab_banner() {
    local ip=$1 port=$2 payload=$3
    timeout $(( BANNER_WAIT * 3 + TIMEOUT + 2 )) bash -c '
        exec 3<>"/dev/tcp/$1/$2" || exit 1
        [[ -n $3 ]] && printf "%b" "$3" >&3
        n=0
        while IFS= read -r -t "$4" line <&3 || [[ -n $line ]]; do
            printf "%s\n" "$line"; line=""
            (( ++n >= 30 )) && break
        done
    ' _ "$ip" "$port" "$payload" "$BANNER_WAIT" 2>/dev/null
}

# sets SVC_NAME and SVC_VER from a port + raw banner
identify_service() {
    local port=$1 b=$2 first h v
    SVC_NAME=""; SVC_VER=""
    first=${b%%$'\n'*}; first=${first%$'\r'}
    case $b in
        SSH-*)
            SVC_NAME=ssh
            v=${first#SSH-}
            SVC_VER="${v#*-}"; SVC_VER="${SVC_VER//_/ } (protocol ${v%%-*})" ;;
        HTTP/*)
            SVC_NAME=http
            h=$(grep -i '^Server:' <<<"$b" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
            SVC_VER=$h ;;
        220*)
            v=${first#220}; v=${v#[ -]}
            if grep -qiE 'smtp' <<<"$first" || [[ $port == 25 || $port == 587 || $port == 465 ]]; then
                SVC_NAME=smtp
            else
                SVC_NAME=ftp
            fi
            SVC_VER=$(sed -E 's/^\((.*)\)$/\1/' <<<"$v") ;;
        +OK*)    SVC_NAME=pop3; SVC_VER=${first#+OK } ;;
        "* OK"*) SVC_NAME=imap; SVC_VER=${first#\* OK } ;;
        +PONG*)  SVC_NAME=redis ;;
        *)
            v=$(grep -aoE '[0-9]+\.[0-9]+\.[0-9]+[-A-Za-z0-9._]*' <<<"$b" | head -1)
            if [[ $port == 3306 && -n $v ]]; then
                SVC_NAME=mysql; SVC_VER=$v
                grep -qi mariadb <<<"$b" && SVC_VER="MariaDB $v"
            elif [[ $port == 5432 ]]; then
                SVC_NAME=postgresql
            elif [[ -n $first ]] && [[ $first =~ ^[[:print:]]+$ ]]; then
                SVC_VER=${first:0:60}
            fi ;;
    esac
}

# detect_version <ip> <port>  -> sets SVC_NAME / SVC_VER
detect_version() {
    local ip=$1 port=$2 b="" probe
    probe=${HTTP_PROBE/target/$ip}
    case $port in
        80|8000|8008|8080|8888)
            b=$(grab_banner "$ip" "$port" "$probe") ;;
        443|8443)
            if command -v curl >/dev/null; then
                b=$(curl -skI -m 4 "https://$ip:$port/" 2>/dev/null | tr -d '\r')
                identify_service "$port" "$b"
                [[ -n $SVC_NAME ]] && SVC_NAME="ssl/$SVC_NAME" || SVC_NAME="ssl/http"
                return
            fi ;;
        6379)
            b=$(grab_banner "$ip" "$port" 'PING\r\n') ;;
        *)
            b=$(grab_banner "$ip" "$port" "")
            [[ -n $b ]] || b=$(grab_banner "$ip" "$port" "$probe") ;;
    esac
    identify_service "$port" "$b"
}

# Scan one host. Result file lines: "<port> <service>". File exists = host up.
scan_host() {
    local ip=$1 p svc ver
    if (( SKIP_PING == 1 )) || host_up "$ip"; then
        : >"$RES/$ip"
        for p in "${PORT_LIST[@]}"; do
            if port_open "$ip" "$p"; then
                svc=$(service_name "$p"); ver="-"
                if (( VERSION_SCAN )); then
                    detect_version "$ip" "$p"
                    [[ -n $SVC_NAME ]] && svc=$SVC_NAME
                    [[ -n $SVC_VER ]] && ver=${SVC_VER//|/ }
                fi
                echo "$p|$svc|$ver" >>"$RES/$ip"
            fi
        done
    fi
    : >"$DONE/$ip"
}

# ------------------------------------------------------------------ report
report() {
    local f ip up=0 open_total=0 risky=0 port svc tag col n
    printf '%s╔══════════════════════════════════════════════════╗%s\n' "$G" "$X"
    printf '%s║%s  VENOMSCANNER REPORT                             %s║%s\n' "$G" "$B" "$G" "$X"
    printf '%s╚══════════════════════════════════════════════════╝%s\n' "$G" "$X"
    printf '%s target :%s %s\n' "$GR" "$X" "$TARGET"
    printf '%s date   :%s %s\n\n' "$GR" "$X" "$(date '+%F %T')"

    for f in $(ls "$RES" 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n); do
        ip=$f
        up=$(( up + 1 ))
        printf '%s┌─[ %s%s%s%s ]──────── %s● ALIVE%s\n' "$DG" "$B" "$C" "$ip" "$DG" "$G" "$X"
        n=0
        if (( VERSION_SCAN )); then
            printf '%s│%s  %s%-9s %-7s %-12s %s%s\n' "$DG" "$X" "$B$GR" "PORT" "STATE" "SERVICE" "VERSION" "$X"
        fi
        while IFS='|' read -r port svc ver; do
            [[ -n $port ]] || continue
            n=$(( n + 1 )); open_total=$(( open_total + 1 ))
            if [[ $RISKY_PORTS == *" $port "* ]]; then
                col=$R; tag="OPEN ⚠"; risky=$(( risky + 1 ))
            else
                col=$G; tag="OPEN  "
            fi
            if (( VERSION_SCAN )); then
                printf '%s│%s  %s%-9s%s %s%-7s%s %s%-12s%s %s%s%s\n' "$DG" "$X" "$col" "$port/tcp" "$X" "$col" "open" "$X" "$GR" "$svc" "$X" "$C" "$ver" "$X"
            else
                printf '%s│%s  %s%-6s%s %s%s%s  %s%s%s\n' "$DG" "$X" "$col" "$port/tcp" "$X" "$col" "$tag" "$X" "$GR" "$svc" "$X"
            fi
        done <"$RES/$f"
        (( n )) || printf '%s│%s  %sno open ports found (of %d scanned)%s\n' "$DG" "$X" "$GR" "${#PORT_LIST[@]}" "$X"
        printf '%s└──────────────────────────────────────%s\n\n' "$DG" "$X"
    done

    printf '%s━━━━━━━━━━━━━━━━━━ SUMMARY ━━━━━━━━━━━━━━━━━━━━━%s\n' "$G" "$X"
    printf '  %sHosts up    :%s %s%d%s / %d\n' "$GR" "$X" "$B$G" "$up" "$X" "$TOTAL"
    printf '  %sOpen ports  :%s %s%d%s\n' "$GR" "$X" "$B$G" "$open_total" "$X"
    printf '  %sRisky ports :%s %s%d%s  %s(telnet/ftp/smb/rdp/vnc)%s\n' "$GR" "$X" "$B$R" "$risky" "$X" "$GR" "$X"
    printf '  %sElapsed     :%s %ds\n' "$GR" "$X" "$(( SECONDS - START ))"
    printf '%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n' "$G" "$X"
}

strip_ansi() { sed -E $'s/\e\\[[0-9;?]*[a-zA-Z]//g'; }

# ------------------------------------------------------------------ main
_args=()
for _a in "$@"; do [[ $_a == -sV ]] && _a=-V; _args+=("$_a"); done
set -- ${_args[@]+"${_args[@]}"}

while getopts ":p:t:j:no:chV" opt; do
    case $opt in
        p) PORTS=$OPTARG ;;
        t) TIMEOUT=$OPTARG ;;
        j) JOBS=$OPTARG ;;
        n) SKIP_PING=1 ;;
        V) VERSION_SCAN=1 ;;
        o) OUTFILE=$OPTARG ;;
        c) USE_COLOR=0; NO_ANIM=1 ;;
        h) setup_colors; usage; exit 0 ;;
        :) die "Option -$OPTARG requires an argument" ;;
        \?) die "Unknown option: -$OPTARG" ;;
    esac
done
shift $((OPTIND - 1))
setup_colors
TARGET=${1:-}
# Friendly: "venomscanner -p 192.168.1.57" -> treat the IP/host given to -p as the target
if [[ -z $TARGET && $PORTS == *.* ]]; then
    TARGET=$PORTS
    PORTS="21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080"
fi
[[ -n $TARGET ]] || { usage; exit 1; }
[[ $TIMEOUT =~ ^[0-9]+$ && $JOBS =~ ^[0-9]+$ ]] && (( JOBS >= 1 )) \
    || die "Timeout and jobs must be positive integers"

for cmd in timeout getent seq awk find; do
    command -v "$cmd" >/dev/null || die "Required command not found: $cmd"
done
if (( SKIP_PING == 0 )) && ! command -v ping >/dev/null; then
    die "ping not found; install iputils-ping or use -n to skip host discovery"
fi

mapfile -t HOSTS < <(expand_target "$TARGET")
mapfile -t PORT_LIST < <(expand_ports "$PORTS")
(( ${#HOSTS[@]} )) || exit 1
(( ${#PORT_LIST[@]} )) || exit 1
TOTAL=${#HOSTS[@]}

WORK=$(mktemp -d) || die "Cannot create temp dir"
RES="$WORK/res"; DONE="$WORK/done"
mkdir -p "$RES" "$DONE"
cleanup() { show_cursor; jobs -rp | xargs -r kill 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
trap 'echo; printf "%s[!] Interrupted.%s\n" "$R" "$X"; exit 130' INT TERM

banner
typewrite "${G}[+]${X} target     : ${TARGET}"
typewrite "${G}[+]${X} hosts      : ${TOTAL}"
typewrite "${G}[+]${X} ports/host : ${#PORT_LIST[@]}"
typewrite "${G}[+]${X} threads    : ${JOBS}   timeout: ${TIMEOUT}s   ping: $(( SKIP_PING ? 0 : 1 ))   version-scan: $(( VERSION_SCAN ))"
echo
hide_cursor
START=$SECONDS

for ip in "${HOSTS[@]}"; do
    while (( $(jobs -rp | wc -l) >= JOBS )); do draw_progress; sleep 0.1; done
    scan_host "$ip" &
done
while (( $(jobs -rp | wc -l) > 0 )); do draw_progress; sleep 0.1; done
wait
draw_progress
[[ -t 1 ]] && printf '\r\e[K%s[✔] scan complete%s\n\n' "$G" "$X"
show_cursor

if [[ -n $OUTFILE ]]; then
    report | tee >(strip_ansi >"$OUTFILE")
    sleep 0.2
    printf '%s[+] saved to %s%s\n' "$G" "$OUTFILE" "$X"
else
    report
fi
