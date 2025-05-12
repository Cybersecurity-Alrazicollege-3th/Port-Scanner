#!/bin/bash

# 🎨 الألوان (لتحسين الإخراج)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m'

# 💡 تعليمات الاستخدام
usage() {
    echo -e "${YELLOW}"
    echo "==============================================="
    echo "             Port Scanner Tool"
    echo "==============================================="
    echo -e "${NC}"
    echo -e "${YELLOW}Usage:${NC}"
    echo -e "  $0 <target_ip_or_domain> <start_port-end_port> [options]"
    echo -e ""
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  --timeout=<seconds>      Set timeout for each port scan (default: 1)"
    echo -e "  --json                   Output results in JSON format"
    echo -e "  --single-port=<port>     Scan a single port instead of a range"
    echo -e ""
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0 8.8.8.8 20-80 --timeout=2"
    echo -e "  $0 192.168.1.1 --single-port=22 --json"
    echo -e ""
    echo -e "${YELLOW}Description:${NC}"
    echo -e "  This script scans the specified ports on the target IP or domain"
    echo -e "  and outputs the results to a file. Open ports and their services"
    echo -e "  are highlighted for easy identification."
    echo -e "${YELLOW}===============================================${NC}"
    exit 1
}

# 🛠️ الإعدادات الافتراضية
TIMEOUT=1
OUTPUT_JSON=false
SINGLE_PORT=""

# 🧠 معالجة الخيارات
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --timeout=*)
            TIMEOUT="${1#*=}"
            shift
            ;;
        --json)
            OUTPUT_JSON=true
            shift
            ;;
        --single-port=*)
            SINGLE_PORT="${1#*=}"
            shift
            ;;
        --help)
            usage
            ;;
        -*|--*)
            echo -e "${RED}Unknown option $1${NC}"
            usage
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL_ARGS[@]}" # إعادة ترتيب المتغيرات

# التحقق من الإدخال
if [ -z "$SINGLE_PORT" ] && [ ${#POSITIONAL_ARGS[@]} -lt 2 ]; then
    usage
fi

TARGET="${POSITIONAL_ARGS[0]}"
PORT_RANGE="${POSITIONAL_ARGS[1]}"
OUTPUT_FILE="scan_results_$(date +%Y%m%d_%H%M%S).txt"

if [ -n "$SINGLE_PORT" ]; then
    START_PORT=$SINGLE_PORT
    END_PORT=$SINGLE_PORT
else
    START_PORT=$(echo "$PORT_RANGE" | cut -d'-' -f1)
    END_PORT=$(echo "$PORT_RANGE" | cut -d'-' -f2)
    
    if ! [[ "$START_PORT" =~ ^[0-9]+$ && "$END_PORT" =~ ^[0-9]+$ && "$START_PORT" -le "$END_PORT" ]]; then
        echo "❌ Invalid port range. Use format like 20-80"
        exit 2
    fi
fi

# 🧠 قاعدة بيانات للخدمات
declare -A SERVICES=(
    [7]="Echo" [9]="Discard" [13]="Daytime" [17]="QOTD"
    [19]="Chargen" [37]="Time" [49]="TACACS" [69]="TFTP"
    [70]="Gopher" [79]="Finger" [88]="Kerberos" [111]="RPCBind"
    [113]="Ident" [119]="NNTP" [123]="NTP" [161]="SNMP"
    [162]="SNMP Trap" [389]="LDAP" [445]="SMB" [514]="Syslog"
    [515]="LPD" [520]="RIP" [546]="DHCPv6 Client" [547]="DHCPv6 Server"
    [636]="LDAPS" [873]="rsync" [993]="IMAPS" [995]="POP3S"
    [1080]="SOCKS Proxy" [1194]="OpenVPN" [1433]="MSSQL" [1521]="Oracle DB"
    [2049]="NFS" [3128]="Squid Proxy" [3306]="MySQL" [3389]="RDP"
    [3690]="Subversion" [5060]="SIP" [5432]="PostgreSQL" [5900]="VNC"
    [6379]="Redis" [8080]="HTTP Alternate" [8443]="HTTPS Alternate" [8883]="MQTT over SSL"
)


declare -A VULNS=(
    [21]="Anonymous FTP vulnerability"
    [22]="Weak SSH configuration (e.g., weak ciphers)"
    [23]="Telnet is insecure (plaintext credentials)"
    [25]="Open SMTP relay may allow spam"
    [53]="DNS Cache Poisoning possible"
    [80]="HTTP may be vulnerable to XSS, SQLi"
    [110]="POP3 credentials may be sent in plaintext"
    [111]="RPC Bind vulnerable to DDoS"
    [139]="NetBIOS/SMB vulnerable on older Windows"
    [143]="IMAP may allow plaintext login"
    [389]="LDAP vulnerable to anonymous bind"
    [443]="HTTPS weak cipher suites (SSL/TLS)"
    [445]="SMB vulnerable (EternalBlue, SMBGhost)"
    [465]="SMTPS may allow weak ciphers"
    [514]="Syslog without encryption (plaintext)"
    [587]="SMTP Submission vulnerable to weak auth"
    [631]="IPP may allow printer enumeration"
    [993]="IMAPS weak SSL/TLS settings"
    [995]="POP3S weak SSL/TLS settings"
    [1433]="MSSQL vulnerable to brute-force login"
    [1521]="Oracle DB may allow remote login"
    [2049]="NFS may allow unauthorized access"
    [3306]="MySQL may allow remote access"
    [3389]="RDP vulnerable to brute-force or weak ciphers"
    [5060]="SIP may allow call interception (VoIP)"
    [5432]="PostgreSQL may allow remote access"
    [5900]="VNC may allow unauthorized access"
    [6379]="Redis exposed without authentication"
    [8080]="HTTP Proxy may be open to abuse"
    [8443]="HTTPS weak SSL/TLS settings (alternate)"
    [9200]="Elasticsearch may allow unauthorized access"
    [27017]="MongoDB exposed without authentication"
)


TOTAL_PORTS=$((END_PORT - START_PORT + 1))
CHECKED_PORTS=0
OPEN_PORTS=()

# 📊 دالة لعرض شريط التقدم
show_progress() {
    local width=50
    local progress=$((CHECKED_PORTS * 100 / TOTAL_PORTS))
    local bar=""
    local -i i

    for ((i=0; i<width; i++)); do
        if (( i < progress * width / 100 )); then
            bar+="="
        else
            bar+=" "
        fi
    done

    printf "\r🔍 Scanning: [%-${width}s] %3d%% (%d/%d)" "$bar" "$progress" "$CHECKED_PORTS" "$TOTAL_PORTS"
}

# التعامل مع إيقاف الفحص
trap "echo -e '\n\n${YELLOW}Scan interrupted. Results saved so far in ${OUTPUT_FILE}.${NC}'; exit" SIGINT

# 🔍 بدء الفحص
echo "🔍 Scanning $TARGET from port $START_PORT to $END_PORT..."
echo "Results will be saved in $OUTPUT_FILE"
echo "---- Scan started at $(date) ----" > "$OUTPUT_FILE"
START_TIME=$(date +%s)
RESULTS=()

scan_port() {
    local port=$1
    service=${SERVICES[$port]:-"Unknown"}
    if timeout "$TIMEOUT" bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null; then
        # إضافة لون خاص عند العثور على اسم الخدمة
        if [ "$service" == "Unknown" ]; then
            colored_service="${GRAY}$service${NC}"
        else
            colored_service="${CYAN}$service${NC}"
        fi
        echo -e "\r🔍 Port $port (${colored_service}) - Status: ${GREEN}OPEN 🔓${NC}"
        echo -e "Port $port OPEN\tService: $service" >> "$OUTPUT_FILE"
        RESULTS+=("{\"port\":$port,\"status\":\"open\",\"service\":\"$service\"}")
        OPEN_PORTS+=("$port ($service)") # إضافة المنفذ المفتوح واسم الخدمة إلى القائمة
        if [ -n "${VULNS[$port]}" ]; then
            echo -e "    [!] Warning: ${VULNS[$port]}" | tee -a "$OUTPUT_FILE"
        fi
    else
        # إضافة لون خاص عند عدم العثور على اسم الخدمة
        if [ "$service" == "Unknown" ]; then
            colored_service="${GRAY}$service${NC}"
        else
            colored_service="${CYAN}$service${NC}"
        fi
        echo -e "\r🔍 Port $port (${colored_service}) - Status: ${RED}CLOSED 🔒${NC}"
        echo -e "Port $port CLOSED\tService: $service" >> "$OUTPUT_FILE"
        RESULTS+=("{\"port\":$port,\"status\":\"closed\",\"service\":\"$service\"}")
    fi
    CHECKED_PORTS=$((CHECKED_PORTS + 1))
    show_progress # تحديث شريط التقدم بعد كل فحص
}

# فحص المنافذ
for ((port=START_PORT; port<=END_PORT; port++)); do
    scan_port "$port"
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
echo -e "\n✅ Scan completed in $DURATION seconds." | tee -a "$OUTPUT_FILE"

# عرض قائمة المنافذ المفتوحة وأسمائها في النهاية
if [ ${#OPEN_PORTS[@]} -gt 0 ]; then
    echo -e "\n${GREEN}Open Ports:${NC}"
    for open_port in "${OPEN_PORTS[@]}"; do
        echo -e "  🔓 ${GREEN}$open_port${NC}"
    done
else
    echo -e "\n${YELLOW}No open ports found.${NC}"
fi

# إخراج النتائج بصيغة JSON
if [ "$OUTPUT_JSON" = true ]; then
    echo -e "[\n$(IFS=,; echo "${RESULTS[*]}")\n]" > "results.json"
    echo "📄 Results saved in results.json"
fi
