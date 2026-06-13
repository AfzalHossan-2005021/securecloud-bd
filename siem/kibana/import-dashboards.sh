#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# import-dashboards.sh
#
# Imports all SecureCloud-BD Kibana saved objects (index patterns, dashboards,
# visualizations, saved searches) via the Kibana Saved Objects Import API.
#
# Objects are imported in dependency order:
#   1. index-patterns.json  — must exist before visualizations can reference them
#   2. overview-dashboard.json  — 5 visualizations + 1 dashboard
#   3. threat-dashboard.json    — 1 saved search + 3 visualizations + 1 dashboard
#   4. network-dashboard.json   — 2 visualizations + 1 dashboard
#
# Import API:
#   POST /api/saved_objects/_import
#   Content-Type: multipart/form-data
#   Query param: ?overwrite=true  — replaces existing objects with the same ID
#   Header: kbn-xsrf: true       — required for all mutating Kibana API calls
#
# The files use NDJSON format (one JSON object per line), which is the same
# format produced by Kibana's export UI (Stack Management → Saved Objects →
# Export). You can round-trip: export from Kibana → edit offline → re-import.
#
# Prerequisites:
#   - Kibana running and reachable at KIBANA_URL (default: NodePort 30601)
#   - curl installed
#   - Elasticsearch running with the securecloud-logs-*, falco-alerts-*,
#     and ml-scores-* indices (or at least one document so the index exists)
#
# Usage:
#   bash siem/kibana/import-dashboards.sh
#   bash siem/kibana/import-dashboards.sh --kibana-url http://localhost:5601
#   bash siem/kibana/import-dashboards.sh --port-forward   # auto port-forward
#   bash siem/kibana/import-dashboards.sh --dry-run
#   bash siem/kibana/import-dashboards.sh --delete-existing
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
KIBANA_URL=""          # auto-detected below if empty
SIEM_NAMESPACE="siem"
KB_RELEASE="securecloud-kb"
LOCAL_PORT="5601"      # used when --port-forward
DRY_RUN=false
PORT_FORWARD=false
DELETE_EXISTING=false
PF_PID=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARDS_DIR="${SCRIPT_DIR}/dashboards"

# Import order matters: index-patterns must come before visualizations.
IMPORT_FILES=(
  "${DASHBOARDS_DIR}/index-patterns.json"
  "${DASHBOARDS_DIR}/overview-dashboard.json"
  "${DASHBOARDS_DIR}/threat-dashboard.json"
  "${DASHBOARDS_DIR}/network-dashboard.json"
)

# ── CLI args ───────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kibana-url)      KIBANA_URL="$2"; shift 2 ;;
    --port-forward)    PORT_FORWARD=true; shift ;;
    --namespace)       SIEM_NAMESPACE="$2"; shift 2 ;;
    --dry-run)         DRY_RUN=true; shift ;;
    --delete-existing) DELETE_EXISTING=true; shift ;;
    --help|-h)
      echo "Usage: $0 [--kibana-url URL] [--port-forward] [--dry-run] [--delete-existing]"
      echo ""
      echo "  --kibana-url URL    Kibana base URL (default: auto-detect via minikube ip)"
      echo "  --port-forward      kubectl port-forward to localhost:5601 before importing"
      echo "  --dry-run           Print what would be imported without calling the API"
      echo "  --delete-existing   Delete all existing saved objects before importing"
      exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# ── Preflight ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Kibana Dashboard Import — SecureCloud-BD          ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""

command -v curl &>/dev/null || die "curl not found."

# Verify all dashboard files exist
for f in "${IMPORT_FILES[@]}"; do
  [[ -f "$f" ]] || die "Dashboard file not found: $f\n  Run from the repo root or check the path."
done

# ── Resolve Kibana URL ────────────────────────────────────────────────────────
cleanup_pf() {
  if [[ -n "${PF_PID}" ]]; then
    kill "${PF_PID}" 2>/dev/null || true
    info "Port-forward process stopped."
  fi
}
trap cleanup_pf EXIT

if [[ -n "${KIBANA_URL}" ]]; then
  info "Using provided Kibana URL: ${KIBANA_URL}"

elif "${PORT_FORWARD}"; then
  info "Setting up kubectl port-forward to Kibana..."
  command -v kubectl &>/dev/null || die "kubectl not found (needed for --port-forward)."

  kubectl port-forward \
    -n "${SIEM_NAMESPACE}" \
    "svc/${KB_RELEASE}" \
    "${LOCAL_PORT}:5601" \
    &>/dev/null &
  PF_PID=$!
  KIBANA_URL="http://localhost:${LOCAL_PORT}"

  info "Waiting for port-forward to be ready..."
  for i in $(seq 1 20); do
    if curl -s --max-time 2 "${KIBANA_URL}/api/status" &>/dev/null; then
      break
    fi
    sleep 1
    if [[ $i -eq 20 ]]; then
      die "Timed out waiting for Kibana port-forward. Is the pod running?\n  kubectl get pods -n ${SIEM_NAMESPACE} -l app=${KB_RELEASE}"
    fi
  done
  success "Port-forward ready at ${KIBANA_URL}"

else
  # Auto-detect via minikube NodePort
  if command -v minikube &>/dev/null; then
    MINIKUBE_IP=$(minikube ip 2>/dev/null || echo "")
    if [[ -n "${MINIKUBE_IP}" ]]; then
      KIBANA_URL="http://${MINIKUBE_IP}:30601"
      info "Auto-detected Kibana URL (Minikube NodePort): ${KIBANA_URL}"
    fi
  fi

  if [[ -z "${KIBANA_URL}" ]]; then
    # Try kubectl node IP
    if command -v kubectl &>/dev/null; then
      NODE_IP=$(kubectl get nodes \
        -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' \
        2>/dev/null || echo "")
      if [[ -n "${NODE_IP}" ]]; then
        KIBANA_URL="http://${NODE_IP}:30601"
        info "Auto-detected Kibana URL (Node IP): ${KIBANA_URL}"
      fi
    fi
  fi

  if [[ -z "${KIBANA_URL}" ]]; then
    die "Could not detect Kibana URL. Specify with --kibana-url or use --port-forward.\n  Example: $0 --kibana-url http://192.168.49.2:30601"
  fi
fi

# ── Wait for Kibana to be ready ───────────────────────────────────────────────
info "Checking Kibana availability at ${KIBANA_URL}..."
MAX_WAIT=60
ELAPSED=0
until curl -s --max-time 5 "${KIBANA_URL}/api/status" | \
    python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('status',{}).get('overall',{}).get('level')=='available' else 1)" \
    2>/dev/null; do
  if [[ ${ELAPSED} -ge ${MAX_WAIT} ]]; then
    die "Kibana is not responding at ${KIBANA_URL} after ${MAX_WAIT}s.\n  Check: kubectl get pods -n ${SIEM_NAMESPACE} -l app=${KB_RELEASE}"
  fi
  printf "  [%2ds] Waiting for Kibana...\r" "${ELAPSED}"
  sleep 3
  ELAPSED=$(( ELAPSED + 3 ))
done
echo ""
success "Kibana is ready."

# ── Optionally delete all existing saved objects ───────────────────────────────
if "${DELETE_EXISTING}"; then
  warn "Deleting all existing saved objects (dashboards, visualizations, index-patterns)..."
  for obj_type in dashboard visualization search index-pattern; do
    if "${DRY_RUN}"; then
      info "[DRY-RUN] Would delete all saved objects of type: ${obj_type}"
    else
      # Find all IDs of this type and delete them
      IDS=$(curl -s \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        "${KIBANA_URL}/api/saved_objects/_find?type=${obj_type}&per_page=100" | \
        python3 -c "
import sys, json
d = json.load(sys.stdin)
for o in d.get('saved_objects', []):
    print(o['id'])
" 2>/dev/null || true)
      for id in ${IDS}; do
        curl -s -X DELETE \
          -H "kbn-xsrf: true" \
          "${KIBANA_URL}/api/saved_objects/${obj_type}/${id}?force=true" \
          &>/dev/null || true
      done
    fi
  done
  success "Existing saved objects deleted."
fi

# ── Import function ────────────────────────────────────────────────────────────
import_file() {
  local file="$1"
  local label
  label="$(basename "${file}")"

  if "${DRY_RUN}"; then
    # Count how many objects are in the file
    local count
    count=$(wc -l < "${file}" | tr -d ' ')
    info "[DRY-RUN] Would import ${count} saved object(s) from ${label}"
    return 0
  fi

  local response http_code body

  # The Import API expects multipart/form-data with the NDJSON file.
  # --write-out captures the HTTP status code separately from the body.
  response=$(curl -s \
    --write-out "\n%{http_code}" \
    -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    -F "file=@${file};type=application/ndjson" \
    2>/dev/null)

  http_code=$(echo "${response}" | tail -1)
  body=$(echo "${response}" | head -n -1)

  if [[ "${http_code}" != "200" ]]; then
    error "Import of ${label} failed (HTTP ${http_code})."
    error "Response: ${body}"
    return 1
  fi

  # Parse the response to check for per-object errors
  local success_count error_count errors
  success_count=$(echo "${body}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len([x for x in d.get('successResults', []) if True]) + (d.get('successCount', 0)))
" 2>/dev/null || echo "?")

  error_count=$(echo "${body}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
errs = d.get('errors', [])
print(len(errs))
" 2>/dev/null || echo "0")

  errors=$(echo "${body}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for e in d.get('errors', []):
    t = e.get('type','?')
    i = e.get('id','?')
    msg = e.get('error', {}).get('message', str(e.get('error','')))
    print(f'  [{t}/{i}] {msg}')
" 2>/dev/null || echo "  (could not parse errors)")

  if [[ "${error_count}" != "0" && "${error_count}" != "?" ]]; then
    warn "Imported ${label} with ${error_count} error(s) (${success_count} succeeded):"
    echo "${errors}"
  else
    success "Imported ${label}: ${success_count} object(s) created/updated."
  fi
}

# ── Import all files in order ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Importing saved objects...${RESET}"
echo ""

TOTAL_FILES=${#IMPORT_FILES[@]}
CURRENT=0

for file in "${IMPORT_FILES[@]}"; do
  CURRENT=$(( CURRENT + 1 ))
  echo -e "  [${CURRENT}/${TOTAL_FILES}] $(basename "${file}")"
  import_file "${file}"
done

# ── Verify objects are present ─────────────────────────────────────────────────
if ! "${DRY_RUN}"; then
  echo ""
  info "Verifying imported objects..."

  for obj_type in index-pattern dashboard visualization search; do
    count=$(curl -s \
      -H "kbn-xsrf: true" \
      "${KIBANA_URL}/api/saved_objects/_find?type=${obj_type}&per_page=1" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" \
      2>/dev/null || echo "?")
    echo -e "    ${obj_type}: ${GREEN}${count}${RESET} objects"
  done
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
success "Dashboard import complete."
echo ""
echo -e "  Open Kibana: ${CYAN}${KIBANA_URL}${RESET}"
echo ""
echo -e "  ${BOLD}Dashboards:${RESET}"
echo -e "    ${CYAN}${KIBANA_URL}/app/dashboards${RESET}"
echo ""
echo -e "  ${BOLD}Individual dashboards (navigate after opening Kibana):${RESET}"
echo -e "    • SecureCloud — Overview        (all events, namespace breakdown, top pods)"
echo -e "    • SecureCloud — Threat Detection (Falco live feed, ML anomaly scores)"
echo -e "    • SecureCloud — Network Visibility (policy violations, pod-to-pod matrix)"
echo ""
echo -e "  ${BOLD}Index patterns created:${RESET}"
echo -e "    • securecloud-logs-*    (Kubernetes + app container logs)"
echo -e "    • falco-alerts-*        (Falco security alerts via Sidekick)"
echo -e "    • securecloud-falco-*   (Falco events via Logstash pipeline)"
echo -e "    • securecloud-zeek-*    (Zeek network flow data)"
echo -e "    • ml-scores-*           (ML ensemble anomaly scores from threat-api)"
echo ""
echo -e "  ${BOLD}To re-import after editing a dashboard file:${RESET}"
echo -e "    ${CYAN}$0 --kibana-url ${KIBANA_URL}${RESET}"
echo ""
echo -e "  ${BOLD}To export your changes back to files:${RESET}"
echo -e "    Stack Management → Saved Objects → select all → Export NDJSON"
echo -e "    Replace the files in ${DASHBOARDS_DIR}/"
echo ""
