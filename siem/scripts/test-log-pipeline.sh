#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# test-log-pipeline.sh
#
# End-to-end log pipeline smoke test:
#
#   1. Find a running frontend pod in the apps namespace
#   2. Emit 10 structured JSON log lines into it (via kubectl exec)
#   3. Poll Elasticsearch every 3 s for up to 30 s to confirm the events arrived
#   4. Print a PASS/FAIL result with the count of matched documents
#
# Pipeline under test:
#
#   frontend pod stdout
#     → kubelet writes to /var/log/containers/
#       → Filebeat autodiscover picks up the new lines
#         → decode_json_fields decodes the JSON message
#           → Logstash beats input on port 5044
#             → Logstash filter (JSON decode, @timestamp, metadata)
#               → Elasticsearch index securecloud-logs-YYYY.MM.dd
#                 → this script queries the index and verifies arrival
#
# Expected end-to-end latency:
#   Filebeat harvest interval (0–10 s) + Logstash batch flush (0–5 s) = ≤15 s.
#   The 30-second window gives 2× headroom.
#
# Prerequisites:
#   - kubectl configured and pointing at the target cluster
#   - frontend Deployment running in the apps namespace
#   - Filebeat DaemonSet running in siem namespace
#   - Logstash running in siem namespace
#   - Elasticsearch running in siem namespace
#   - python3 in PATH (for JSON parsing of ES response)
#
# Usage:
#   bash siem/scripts/test-log-pipeline.sh
#   bash siem/scripts/test-log-pipeline.sh --namespace apps --timeout 60
#   bash siem/scripts/test-log-pipeline.sh --es-pod securecloud-es-master-0
#   bash siem/scripts/test-log-pipeline.sh --verbose
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Defaults ───────────────────────────────────────────────────────────────────
APP_NAMESPACE="apps"
SIEM_NAMESPACE="siem"
TIMEOUT=30          # seconds to wait for events to appear in ES
POLL_INTERVAL=3     # seconds between ES query polls
NUM_EVENTS=10       # number of test log lines to emit
VERBOSE=false
ES_POD=""           # override to skip auto-detection

# Unique tag per test run so we can find our events precisely in a busy cluster
TEST_RUN_ID="securecloud-logtest-$(date +%s)-${RANDOM}"

# ── CLI args ───────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace)      APP_NAMESPACE="$2";  shift 2 ;;
    --siem-namespace) SIEM_NAMESPACE="$2"; shift 2 ;;
    --timeout)        TIMEOUT="$2";        shift 2 ;;
    --es-pod)         ES_POD="$2";         shift 2 ;;
    --verbose|-v)     VERBOSE=true;        shift ;;
    --help|-h)
      echo "Usage: $0 [--namespace NS] [--timeout SEC] [--es-pod POD] [--verbose]"
      echo ""
      echo "Options:"
      echo "  --namespace NS       App namespace to find frontend pod (default: apps)"
      echo "  --siem-namespace NS  SIEM namespace for ES + Filebeat (default: siem)"
      echo "  --timeout SEC        Seconds to wait for events in ES (default: 30)"
      echo "  --es-pod POD         Elasticsearch pod name (auto-detected if omitted)"
      echo "  --verbose            Show full ES query responses"
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Log Pipeline Smoke Test — SecureCloud-BD            ${RESET}"
echo -e "${BOLD}══════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Test run ID : ${YELLOW}${TEST_RUN_ID}${RESET}"
echo -e "  Events      : ${NUM_EVENTS} JSON log lines"
echo -e "  Timeout     : ${TIMEOUT}s"
echo -e "  App NS      : ${APP_NAMESPACE}"
echo -e "  SIEM NS     : ${SIEM_NAMESPACE}"
echo ""

# ── Preflight ──────────────────────────────────────────────────────────────────
info "Running preflight checks..."

command -v kubectl &>/dev/null  || die "kubectl not found."
command -v python3 &>/dev/null  || die "python3 not found (needed for JSON parsing)."

kubectl cluster-info &>/dev/null || die "Cannot reach cluster."

# ── Step 1: Find a frontend pod ────────────────────────────────────────────────
info "Finding a running frontend pod in namespace '${APP_NAMESPACE}'..."

FRONTEND_POD=$(kubectl get pods \
  -n "${APP_NAMESPACE}" \
  -l "app=frontend" \
  --field-selector="status.phase=Running" \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${FRONTEND_POD}" ]]; then
  # Try without the label (in case the label differs)
  FRONTEND_POD=$(kubectl get pods \
    -n "${APP_NAMESPACE}" \
    --field-selector="status.phase=Running" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

  if [[ -z "${FRONTEND_POD}" ]]; then
    die "No running pods found in namespace '${APP_NAMESPACE}'.
  Start the demo app first:
    kubectl apply -k infra/apps/manifests/
  Or specify a different namespace:
    $0 --namespace <ns>"
  fi

  warn "No pod with app=frontend label; using first available pod: ${FRONTEND_POD}"
else
  success "Found frontend pod: ${FRONTEND_POD}"
fi

# Verify the pod has a shell
kubectl exec -n "${APP_NAMESPACE}" "${FRONTEND_POD}" -- sh -c 'echo ok' &>/dev/null || \
  die "Cannot exec into pod ${FRONTEND_POD}. Is it running?"

# ── Step 2: Find the Elasticsearch pod ────────────────────────────────────────
if [[ -z "${ES_POD}" ]]; then
  info "Auto-detecting Elasticsearch pod in namespace '${SIEM_NAMESPACE}'..."

  ES_POD=$(kubectl get pods \
    -n "${SIEM_NAMESPACE}" \
    -l "app=securecloud-es-master" \
    --field-selector="status.phase=Running" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

  if [[ -z "${ES_POD}" ]]; then
    # Try the legacy label from the raw manifest
    ES_POD=$(kubectl get pods \
      -n "${SIEM_NAMESPACE}" \
      -l "app=elasticsearch" \
      --field-selector="status.phase=Running" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
  fi

  if [[ -z "${ES_POD}" ]]; then
    die "No running Elasticsearch pod found in namespace '${SIEM_NAMESPACE}'.
  Install ELK first:
    bash siem/elk/install-elk.sh
  Or specify the pod directly:
    $0 --es-pod <pod-name>"
  fi

  success "Found Elasticsearch pod: ${ES_POD}"
else
  info "Using specified Elasticsearch pod: ${ES_POD}"
fi

# Verify ES is reachable
ES_HEALTH=$(kubectl exec -n "${SIEM_NAMESPACE}" "${ES_POD}" -- \
  curl -s "http://localhost:9200/_cluster/health" 2>/dev/null | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" \
  2>/dev/null || echo "unreachable")

if [[ "${ES_HEALTH}" == "unreachable" ]]; then
  die "Elasticsearch is not responding at http://localhost:9200 inside ${ES_POD}."
fi

if [[ "${ES_HEALTH}" == "red" ]]; then
  warn "Elasticsearch cluster health is RED. Test may produce unreliable results."
else
  success "Elasticsearch cluster health: ${ES_HEALTH}"
fi

# ── Step 3: Verify Filebeat is running ────────────────────────────────────────
info "Checking Filebeat DaemonSet..."
FB_DESIRED=$(kubectl get daemonset filebeat -n "${SIEM_NAMESPACE}" \
  -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo "0")
FB_READY=$(kubectl get daemonset filebeat -n "${SIEM_NAMESPACE}" \
  -o jsonpath='{.status.numberReady}' 2>/dev/null || echo "0")

if [[ "${FB_READY}" == "0" ]]; then
  warn "Filebeat DaemonSet shows 0 ready pods (desired: ${FB_DESIRED})."
  warn "Events may not be collected. Continuing anyway..."
else
  success "Filebeat: ${FB_READY}/${FB_DESIRED} pods ready."
fi

# ── Step 4: Emit test log lines from the frontend pod ─────────────────────────
echo ""
info "Emitting ${NUM_EVENTS} structured JSON log lines from pod ${FRONTEND_POD}..."
echo ""

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build and execute the log emission command in the pod.
# Each line is a JSON object with:
#   - test_run_id: unique per test run (used as search key)
#   - seq:         sequence number 1..N (used to count arrivals)
#   - level:       always "INFO" so it doesn't alarm Falco
#   - message:     human-readable description
#   - timestamp:   RFC3339 timestamp from inside the pod
#   - component:   identifies the source in Kibana
kubectl exec -n "${APP_NAMESPACE}" "${FRONTEND_POD}" -- sh -c "
  i=1
  while [ \$i -le ${NUM_EVENTS} ]; do
    printf '{\"level\":\"INFO\",\"message\":\"log-pipeline-test event %d of ${NUM_EVENTS}\",\"test_run_id\":\"${TEST_RUN_ID}\",\"seq\":%d,\"component\":\"frontend\",\"namespace\":\"${APP_NAMESPACE}\",\"timestamp\":\"'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'\"}\\n' \$i \$i
    sleep 0.1
    i=\$(( i + 1 ))
  done
"

success "Emitted ${NUM_EVENTS} log lines. Waiting for them to flow through the pipeline..."
echo ""
echo -e "  Path: ${CYAN}pod stdout${RESET} → ${CYAN}kubelet log${RESET} → ${CYAN}Filebeat${RESET} → ${CYAN}Logstash${RESET} → ${CYAN}Elasticsearch${RESET}"
echo ""

# ── Step 5: Poll Elasticsearch for the test events ────────────────────────────
# Query: match documents where test_run_id equals our unique tag.
# We search securecloud-logs-* to match the daily rolling index pattern.
ES_QUERY=$(cat <<EOF
{
  "query": {
    "bool": {
      "should": [
        { "term": { "test_run_id": "${TEST_RUN_ID}" } },
        { "term": { "test_run_id.keyword": "${TEST_RUN_ID}" } }
      ],
      "minimum_should_match": 1
    }
  },
  "_source": ["test_run_id", "seq", "message", "@timestamp", "kubernetes.pod.name"],
  "size": ${NUM_EVENTS},
  "sort": [{ "seq": "asc" }]
}
EOF
)

info "Polling Elasticsearch (every ${POLL_INTERVAL}s, timeout ${TIMEOUT}s)..."
echo ""

ELAPSED=0
FOUND=0
PASS=false

while [[ ${ELAPSED} -lt ${TIMEOUT} ]]; do
  # Run the search inside the ES pod (avoids needing an exposed NodePort)
  RAW_RESPONSE=$(kubectl exec -n "${SIEM_NAMESPACE}" "${ES_POD}" -- \
    curl -s -X GET "http://localhost:9200/securecloud-logs-*/_search" \
    -H "Content-Type: application/json" \
    -d "${ES_QUERY}" 2>/dev/null || echo '{"hits":{"total":{"value":0},"hits":[]}}')

  # Parse the hit count with python3
  FOUND=$(echo "${RAW_RESPONSE}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    total = d.get('hits', {}).get('total', {})
    if isinstance(total, dict):
        print(total.get('value', 0))
    else:
        print(total)
except Exception as e:
    print(0)
" 2>/dev/null || echo "0")

  if $VERBOSE; then
    echo -e "  ${CYAN}[${ELAPSED}s]${RESET} ES response:"
    echo "${RAW_RESPONSE}" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    hits = d.get('hits', {}).get('hits', [])
    for h in hits:
        src = h.get('_source', {})
        print(f\"    seq={src.get('seq','?')} ts={src.get('@timestamp','?')} msg={src.get('message','?')[:60]}\")
except:
    print('    (parse error)')
" 2>/dev/null || true
  fi

  printf "  [%3ds] Documents found in Elasticsearch: %s / %s\r" \
    "${ELAPSED}" "${FOUND}" "${NUM_EVENTS}"

  if [[ "${FOUND}" -ge "${NUM_EVENTS}" ]]; then
    PASS=true
    break
  fi

  sleep "${POLL_INTERVAL}"
  ELAPSED=$(( ELAPSED + POLL_INTERVAL ))
done

echo ""  # clear the \r line

# ── Step 6: Show detailed results ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"

if "${PASS}"; then
  echo -e "${GREEN}${BOLD}  ✓ PASS — Log pipeline is working${RESET}"
  echo ""
  echo -e "  All ${NUM_EVENTS} test events arrived in Elasticsearch within ${ELAPSED}s."
  echo ""

  # Show the arrived events
  echo -e "  ${BOLD}Arrived events (from ES):${RESET}"
  kubectl exec -n "${SIEM_NAMESPACE}" "${ES_POD}" -- \
    curl -s -X GET "http://localhost:9200/securecloud-logs-*/_search" \
    -H "Content-Type: application/json" \
    -d "${ES_QUERY}" 2>/dev/null | \
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    hits = d.get('hits', {}).get('hits', [])
    for h in hits:
        src = h.get('_source', {})
        seq = src.get('seq', '?')
        ts  = src.get('@timestamp', src.get('timestamp', '?'))
        pod = src.get('kubernetes', {}).get('pod', {}).get('name', src.get('kubernetes.pod.name', '?'))
        print(f'    [{seq:>2}] {ts}  pod={pod}')
except Exception as e:
    print(f'    (parse error: {e})')
" 2>/dev/null || true

  echo ""
  echo -e "  ${BOLD}Index status:${RESET}"
  kubectl exec -n "${SIEM_NAMESPACE}" "${ES_POD}" -- \
    curl -s "http://localhost:9200/securecloud-logs-*/_count" 2>/dev/null | \
    python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'    securecloud-logs-*: {d.get(\"count\", \"?\")} total documents')
" 2>/dev/null || true

else
  echo -e "${RED}${BOLD}  ✗ FAIL — Log pipeline timeout${RESET}"
  echo ""
  echo -e "  Only ${FOUND} of ${NUM_EVENTS} test events found in Elasticsearch after ${TIMEOUT}s."
  echo ""
  echo -e "  ${BOLD}Diagnostic steps:${RESET}"
  echo ""
  echo -e "  1. Check Filebeat is running and tailing logs:"
  echo -e "     ${CYAN}kubectl get pods -n ${SIEM_NAMESPACE} -l app=filebeat${RESET}"
  echo -e "     ${CYAN}kubectl logs -n ${SIEM_NAMESPACE} -l app=filebeat --tail=50${RESET}"
  echo ""
  echo -e "  2. Check Filebeat registry (confirms it found the pod's log file):"
  echo -e "     ${CYAN}kubectl exec -n ${SIEM_NAMESPACE} \$(kubectl get pod -n ${SIEM_NAMESPACE} -l app=filebeat -o name | head -1) -- cat /usr/share/filebeat/data/registry/filebeat/log.json 2>/dev/null | python3 -m json.tool | head -40${RESET}"
  echo ""
  echo -e "  3. Check Logstash is receiving beats input:"
  echo -e "     ${CYAN}kubectl logs -n ${SIEM_NAMESPACE} -l app=securecloud-ls --tail=50${RESET}"
  echo -e "     ${CYAN}kubectl exec -n ${SIEM_NAMESPACE} securecloud-ls-0 -- curl -s http://localhost:9600/_node/stats/pipelines | python3 -m json.tool | grep -A2 'events'${RESET}"
  echo ""
  echo -e "  4. Check Elasticsearch index exists:"
  echo -e "     ${CYAN}kubectl exec -n ${SIEM_NAMESPACE} ${ES_POD} -- curl -s http://localhost:9200/_cat/indices?v${RESET}"
  echo ""
  echo -e "  5. Check Filebeat autodiscover found the frontend pod:"
  echo -e "     ${CYAN}kubectl exec -n ${SIEM_NAMESPACE} \$(kubectl get pod -n ${SIEM_NAMESPACE} -l app=filebeat -o name | head -1) -- filebeat test output 2>&1 | tail -20${RESET}"
  echo ""
  echo -e "  6. Manual search for the test run ID:"
  echo -e "     ${CYAN}kubectl exec -n ${SIEM_NAMESPACE} ${ES_POD} -- curl -s 'http://localhost:9200/securecloud-logs-*/_search?q=test_run_id:${TEST_RUN_ID}&size=5' | python3 -m json.tool${RESET}"
  echo ""
  echo -e "  7. Increase timeout and retry:"
  echo -e "     ${CYAN}$0 --timeout 120 --verbose${RESET}"

  exit 1
fi

echo -e "${BOLD}──────────────────────────────────────────────────────${RESET}"
echo ""
