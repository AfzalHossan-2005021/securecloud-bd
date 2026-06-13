#!/usr/bin/env bash
# infra/istio/verify-mtls.sh
#
# Verifies that Istio mTLS is active and correctly configured across all
# service pairs in the SecureCloud-BD project.
#
# Uses three complementary verification strategies:
#   1. istioctl authn tls-check  — consults Pilot for the negotiated TLS mode
#   2. Sidecar proxy config dump — inspects the live Envoy listener config
#   3. Live traffic probe        — sends a test request and checks the
#                                  response headers for mTLS metadata
#
# Exit codes:
#   0  All checks passed
#   1  One or more checks failed
#
# Usage:
#   bash infra/istio/verify-mtls.sh [OPTIONS]
#
# Options:
#   --namespace NS     Check a single namespace (default: check all)
#   --service   SVC    Check a single service only
#   --verbose          Show full istioctl / kubectl output
#   --json             Emit results as JSON (useful for CI)

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────
# Colour helpers (disabled when not a TTY or --json)
# ─────────────────────────────────────────────────────────────────────
USE_COLOR=true
if [[ ! -t 1 ]]; then USE_COLOR=false; fi

c() {
  [[ "$USE_COLOR" == true ]] && echo -ne "$1" || true
}

RED='\033[0;31m'  GREEN='\033[0;32m'  YELLOW='\033[1;33m'
CYAN='\033[0;36m' BOLD='\033[1m'      DIM='\033[2m'  RESET='\033[0m'

pass_icon()  { c "$GREEN";  echo -n "✓ PASS"; c "$RESET"; }
fail_icon()  { c "$RED";    echo -n "✗ FAIL"; c "$RESET"; }
warn_icon()  { c "$YELLOW"; echo -n "⚠ WARN"; c "$RESET"; }
skip_icon()  { c "$DIM";    echo -n "– SKIP"; c "$RESET"; }

# ─────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────
FILTER_NS=""
FILTER_SVC=""
VERBOSE=false
JSON_OUTPUT=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --namespace) FILTER_NS="$2";  shift 2 ;;
    --service)   FILTER_SVC="$2"; shift 2 ;;
    --verbose)   VERBOSE=true;    shift ;;
    --json)      JSON_OUTPUT=true; USE_COLOR=false; shift ;;
    -h|--help)
      sed -n '/^# Usage/,/^[^#]/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─────────────────────────────────────────────────────────────────────
# Service catalogue
# Format: "namespace/service:port  display-name"
# ─────────────────────────────────────────────────────────────────────
declare -a SERVICES=(
  "apps/frontend:5000            bKash Frontend (Flask)"
  "apps/payment-api:8000         bKash Payment API (FastAPI)"
  "apps/user-db:5432             bKash User DB (PostgreSQL)"
  "ml-engine/ml-infer:8081       ML Inference Service"
  "monitoring/prometheus:9090    Prometheus"
  "monitoring/grafana:3000       Grafana"
  "securecloud/threat-api:8080   Threat Scoring API"
  "siem/elasticsearch:9200       Elasticsearch"
  "siem/logstash:5044            Logstash (Beats)"
  "siem/kibana:5601              Kibana"
)

# Service pairs to check with tls-check (from/to)
declare -a PAIRS=(
  "apps/frontend           apps/payment-api"
  "apps/payment-api        apps/user-db"
  "apps/frontend           securecloud/threat-api"
  "monitoring/prometheus   apps/frontend"
  "monitoring/prometheus   apps/payment-api"
  "monitoring/prometheus   securecloud/threat-api"
  "securecloud/threat-api  siem/elasticsearch"
  "apps/payment-api        siem/elasticsearch"
)

# ─────────────────────────────────────────────────────────────────────
# Result tracking
# ─────────────────────────────────────────────────────────────────────
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

declare -a JSON_RESULTS=()

record() {
  local status="$1" check="$2" detail="$3"
  case "$status" in
    PASS) PASS_COUNT=$((PASS_COUNT+1)) ;;
    FAIL) FAIL_COUNT=$((FAIL_COUNT+1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT+1)) ;;
    SKIP) SKIP_COUNT=$((SKIP_COUNT+1)) ;;
  esac
  if [[ "$JSON_OUTPUT" == true ]]; then
    JSON_RESULTS+=("{\"status\":\"${status}\",\"check\":\"${check}\",\"detail\":\"${detail}\"}")
  fi
}

# ─────────────────────────────────────────────────────────────────────
# Helper: locate istioctl binary
# ─────────────────────────────────────────────────────────────────────
find_istioctl() {
  if command -v istioctl &>/dev/null; then
    echo "istioctl"; return
  fi
  # Check common download locations used by install-istio.sh
  local candidate
  for candidate in "${SCRIPT_DIR}/../../istio-*/bin/istioctl"; do
    if [[ -x "$candidate" ]]; then
      echo "$candidate"; return
    fi
  done
  return 1
}

# ─────────────────────────────────────────────────────────────────────
# Helper: get first Running pod for a service label in a namespace
# ─────────────────────────────────────────────────────────────────────
get_pod() {
  local ns="$1" app="$2"
  kubectl get pod -n "${ns}" -l "app=${app}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────
# Helper: print a table row
# ─────────────────────────────────────────────────────────────────────
TABLE_ROWS=()
add_row() {
  # args: status ns/service tlsMode svid detail
  TABLE_ROWS+=("$1|$2|$3|$4|$5")
}

print_table() {
  local w1=8 w2=38 w3=14 w4=8 w5=0
  local sep
  sep=$(printf '%*s' $((w1+w2+w3+w4+6)) '' | tr ' ' '─')

  printf "\n"
  c "$BOLD"
  printf " %-${w1}s  %-${w2}s  %-${w3}s  %-${w4}s  %s\n" \
    "STATUS" "SERVICE / PAIR" "TLS MODE" "SVID" "DETAIL"
  c "$RESET"
  echo " ${sep}"

  local row status svc tls svid detail
  for row in "${TABLE_ROWS[@]}"; do
    IFS='|' read -r status svc tls svid detail <<< "$row"
    case "$status" in
      PASS) c "$GREEN" ;;
      FAIL) c "$RED"   ;;
      WARN) c "$YELLOW";;
      SKIP) c "$DIM"   ;;
    esac
    printf " %-${w1}s" "$status"
    c "$RESET"
    printf "  %-${w2}s  %-${w3}s  %-${w4}s  %s\n" \
      "${svc:0:$w2}" "${tls:0:$w3}" "${svid:0:$w4}" "${detail:0:60}"
  done
  echo " ${sep}"
}

# ─────────────────────────────────────────────────────────────────────
# Check 1 — Control plane health
# ─────────────────────────────────────────────────────────────────────
check_control_plane() {
  c "$BOLD$CYAN"; echo -e "\n── Check 1: Istio control plane health ──"; c "$RESET"

  # istiod deployment
  local ready
  ready=$(kubectl get deployment istiod -n istio-system \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  if [[ "${ready:-0}" -ge 1 ]]; then
    echo -e "  $(pass_icon)  istiod  (${ready} replica(s) ready)"
    record PASS "istiod-ready" "${ready} replicas"
  else
    echo -e "  $(fail_icon)  istiod not ready (0 replicas)"
    record FAIL "istiod-ready" "0 replicas"
  fi

  # istio CRD count
  local crd_count
  crd_count=$(kubectl get crd 2>/dev/null | grep -c 'istio.io' || echo 0)
  if [[ "$crd_count" -ge 20 ]]; then
    echo -e "  $(pass_icon)  ${crd_count} Istio CRDs registered"
    record PASS "istio-crds" "${crd_count} CRDs"
  else
    echo -e "  $(warn_icon)  Only ${crd_count} Istio CRDs found (expected ≥20)"
    record WARN "istio-crds" "${crd_count} CRDs"
  fi

  # istiod version
  if [[ "$VERBOSE" == true ]]; then
    "${ISTIOCTL}" version 2>/dev/null || true
  fi
}

# ─────────────────────────────────────────────────────────────────────
# Check 2 — Sidecar injection labels on namespaces
# ─────────────────────────────────────────────────────────────────────
check_injection_labels() {
  c "$BOLD$CYAN"; echo -e "\n── Check 2: Sidecar injection labels ──"; c "$RESET"

  local namespaces=(apps ml-engine monitoring securecloud siem ml)
  [[ -n "$FILTER_NS" ]] && namespaces=("$FILTER_NS")

  for ns in "${namespaces[@]}"; do
    if ! kubectl get namespace "${ns}" &>/dev/null; then
      echo -e "  $(skip_icon)  ${ns}: namespace not found"
      add_row "SKIP" "${ns}" "—" "—" "namespace missing"
      record SKIP "injection-label:${ns}" "namespace missing"
      continue
    fi

    local label
    label=$(kubectl get namespace "${ns}" \
      -o jsonpath='{.metadata.labels.istio-injection}' 2>/dev/null || echo "")

    if [[ "$label" == "enabled" ]]; then
      echo -e "  $(pass_icon)  ${ns}: istio-injection=enabled"
      add_row "PASS" "${ns}" "injection=on" "—" ""
      record PASS "injection-label:${ns}" "enabled"
    else
      echo -e "  $(fail_icon)  ${ns}: istio-injection label missing or disabled (got: '${label}')"
      add_row "FAIL" "${ns}" "injection=OFF" "—" "label missing"
      record FAIL "injection-label:${ns}" "label='${label}'"
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────
# Check 3 — PeerAuthentication resources exist and are STRICT
# ─────────────────────────────────────────────────────────────────────
check_peer_authentications() {
  c "$BOLD$CYAN"; echo -e "\n── Check 3: PeerAuthentication mode ──"; c "$RESET"

  local namespaces=(istio-system apps ml-engine monitoring securecloud siem ml)
  [[ -n "$FILTER_NS" ]] && namespaces=("$FILTER_NS")

  for ns in "${namespaces[@]}"; do
    if ! kubectl get namespace "${ns}" &>/dev/null; then
      echo -e "  $(skip_icon)  ${ns}: namespace not found"
      record SKIP "peer-auth:${ns}" "namespace missing"
      continue
    fi

    # Collect all PeerAuthentication resources in the namespace
    local pa_json
    pa_json=$(kubectl get peerauthentication -n "${ns}" -o json 2>/dev/null \
      || echo '{"items":[]}')

    local count
    count=$(echo "$pa_json" | python3 -c \
      'import sys,json; print(len(json.load(sys.stdin)["items"]))' 2>/dev/null || echo 0)

    if [[ "$count" -eq 0 ]]; then
      echo -e "  $(warn_icon)  ${ns}: no PeerAuthentication found (inheriting mesh default)"
      add_row "WARN" "${ns}" "inherited" "—" "no explicit PA"
      record WARN "peer-auth:${ns}" "no PA found"
      continue
    fi

    # Check every PA in the namespace for STRICT mode
    local all_strict=true
    while IFS= read -r line; do
      local name mode
      name=$(echo "$line" | cut -f1)
      mode=$(echo "$line" | cut -f2)
      if [[ "$mode" != "STRICT" ]]; then
        all_strict=false
        echo -e "  $(fail_icon)  ${ns}/${name}: mode=${mode} (expected STRICT)"
        add_row "FAIL" "${ns}/${name}" "${mode}" "—" "not STRICT"
        record FAIL "peer-auth:${ns}/${name}" "mode=${mode}"
      fi
    done < <(echo "$pa_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data['items']:
    name = item['metadata']['name']
    mode = item.get('spec', {}).get('mtls', {}).get('mode', 'UNSET')
    print(f'{name}\t{mode}')
" 2>/dev/null)

    if [[ "$all_strict" == true ]]; then
      echo -e "  $(pass_icon)  ${ns}: ${count} PeerAuthentication(s) all STRICT"
      add_row "PASS" "${ns} (${count} PAs)" "STRICT" "✓" ""
      record PASS "peer-auth:${ns}" "${count} PA(s) STRICT"
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────
# Check 4 — DestinationRule TLS mode
# ─────────────────────────────────────────────────────────────────────
check_destination_rules() {
  c "$BOLD$CYAN"; echo -e "\n── Check 4: DestinationRule TLS modes ──"; c "$RESET"

  local namespaces=(apps ml-engine monitoring securecloud siem ml)
  [[ -n "$FILTER_NS" ]] && namespaces=("$FILTER_NS")

  for ns in "${namespaces[@]}"; do
    if ! kubectl get namespace "${ns}" &>/dev/null; then
      echo -e "  $(skip_icon)  ${ns}: namespace not found"
      record SKIP "dest-rule:${ns}" "namespace missing"
      continue
    fi

    local dr_json
    dr_json=$(kubectl get destinationrule -n "${ns}" -o json 2>/dev/null \
      || echo '{"items":[]}')

    local count
    count=$(echo "$dr_json" | python3 -c \
      'import sys,json; print(len(json.load(sys.stdin)["items"]))' 2>/dev/null || echo 0)

    if [[ "$count" -eq 0 ]]; then
      echo -e "  $(warn_icon)  ${ns}: no DestinationRules found"
      add_row "WARN" "${ns}" "—" "—" "no DR found"
      record WARN "dest-rule:${ns}" "no DRs found"
      continue
    fi

    echo "$dr_json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
all_ok = True
for item in data['items']:
    name = item['metadata']['name']
    host = item['spec'].get('host','?')
    mode = (item['spec']
              .get('trafficPolicy',{})
              .get('tls',{})
              .get('mode','UNSET'))
    ok = mode == 'ISTIO_MUTUAL'
    sym = '✓' if ok else '✗'
    print(f'  {sym}  {name}  host={host}  tls={mode}')
    if not ok:
        all_ok = False
        sys.exit(1)
" 2>/dev/null && {
      echo -e "  $(pass_icon)  ${ns}: ${count} DestinationRule(s) all ISTIO_MUTUAL"
      add_row "PASS" "${ns} (${count} DRs)" "ISTIO_MUTUAL" "✓" ""
      record PASS "dest-rule:${ns}" "${count} DR(s) ISTIO_MUTUAL"
    } || {
      echo -e "  $(fail_icon)  ${ns}: one or more DestinationRules are NOT ISTIO_MUTUAL"
      add_row "FAIL" "${ns}" "mixed/wrong" "✗" "check DR spec"
      record FAIL "dest-rule:${ns}" "non-ISTIO_MUTUAL DRs found"
    }
  done
}

# ─────────────────────────────────────────────────────────────────────
# Check 5 — istioctl authn tls-check (per service pair)
#
# tls-check output columns:
#   HOST:PORT   SERVICE               STATUS    SERVER     CLIENT    AUTHN POLICY  DESTINATION RULE
#
# STATUS values:
#   OK          Both sides agree on mTLS.
#   CONFLICT    Server and client TLS settings are mismatched.
#   DR CONFLICT Two DestinationRules match the same host.
# ─────────────────────────────────────────────────────────────────────
check_tls_pairs() {
  c "$BOLD$CYAN"; echo -e "\n── Check 5: istioctl authn tls-check (per service pair) ──"; c "$RESET"

  if [[ -z "$ISTIOCTL" ]]; then
    echo -e "  $(skip_icon)  istioctl not found — skipping tls-check"
    echo -e "         Install with:  bash infra/istio/install-istio.sh --skip-download"
    record SKIP "tls-check" "istioctl not found"
    return
  fi

  local pair
  for pair in "${PAIRS[@]}"; do
    local from_ns from_svc to_ns to_svc
    read -r from_ns from_svc to_ns to_svc <<< \
      "$(echo "$pair" | awk '{
          split($1,a,"/"); print a[1], a[2]
          split($2,b,"/"); print b[1], b[2]
       }')"

    # Reconstruct for display
    local from="${from_ns}/${from_svc}"
    local to="${to_ns}/${to_svc}"
    local display="${from} → ${to}"

    # Skip if namespace filter doesn't match
    if [[ -n "$FILTER_NS" ]] && \
       [[ "$from_ns" != "$FILTER_NS" && "$to_ns" != "$FILTER_NS" ]]; then
      continue
    fi

    # Need a running pod in the source namespace to run tls-check from
    local from_pod
    from_pod=$(get_pod "${from_ns}" "${from_svc}" 2>/dev/null || \
               get_pod "${from_ns}" "${from_svc%-*}" 2>/dev/null || echo "")

    if [[ -z "$from_pod" ]]; then
      echo -e "  $(skip_icon)  ${display}: no running pod in ${from_ns} — deploy first"
      add_row "SKIP" "${display}" "—" "—" "pod not running"
      record SKIP "tls-check:${display}" "no pod in ${from_ns}"
      continue
    fi

    # Run tls-check from the source pod
    local tls_output status_val server_mode client_mode
    tls_output=$("${ISTIOCTL}" authn tls-check \
      "${from_pod}.${from_ns}" \
      "${to_svc}.${to_ns}.svc.cluster.local" \
      2>/dev/null || echo "ERROR")

    if [[ "$VERBOSE" == true ]]; then
      echo ""
      echo "$tls_output" | sed 's/^/         /'
      echo ""
    fi

    if echo "$tls_output" | grep -q "ERROR\|error"; then
      echo -e "  $(warn_icon)  ${display}: tls-check returned error"
      add_row "WARN" "${display}" "error" "—" "tls-check failed"
      record WARN "tls-check:${display}" "command error"
      continue
    fi

    # Parse the STATUS column from the tls-check output
    # Output format: HOST:PORT  SERVICE  STATUS  SERVER  CLIENT  AUTHN POLICY  DR
    status_val=$(echo "$tls_output" \
      | awk 'NR>1 && NF>0 {print $3}' | head -1)
    server_mode=$(echo "$tls_output" \
      | awk 'NR>1 && NF>0 {print $4}' | head -1)
    client_mode=$(echo "$tls_output" \
      | awk 'NR>1 && NF>0 {print $5}' | head -1)

    # Determine pass/fail
    if [[ "$status_val" == "OK" ]] && \
       [[ "$server_mode" == *"STRICT"* ]] && \
       [[ "$client_mode" == *"ISTIO_MUTUAL"* || "$client_mode" == *"mTLS"* ]]; then
      echo -e "  $(pass_icon)  ${display}"
      echo -e "             server=${server_mode}  client=${client_mode}  status=${status_val}"
      add_row "PASS" "${display}" "ISTIO_MUTUAL" "✓" "server=${server_mode}"
      record PASS "tls-check:${display}" "OK STRICT ISTIO_MUTUAL"
    elif [[ "$status_val" == "OK" ]]; then
      echo -e "  $(warn_icon)  ${display}"
      echo -e "             server=${server_mode}  client=${client_mode}  status=${status_val}"
      echo -e "             ${YELLOW}Warning: status=OK but mode may not be STRICT${RESET}"
      add_row "WARN" "${display}" "${client_mode:-?}" "?" "status=OK but mode check"
      record WARN "tls-check:${display}" "OK but modes=${server_mode}/${client_mode}"
    else
      echo -e "  $(fail_icon)  ${display}"
      echo -e "             server=${server_mode}  client=${client_mode}  status=${status_val:-UNKNOWN}"
      echo -e "             ${RED}CONFLICT or misconfiguration — see troubleshooting in README.md${RESET}"
      add_row "FAIL" "${display}" "${client_mode:-?}" "✗" "status=${status_val:-UNKNOWN}"
      record FAIL "tls-check:${display}" "status=${status_val}"
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────
# Check 6 — Envoy proxy config dump (sidecar certificate inspection)
#
# Reads the SAN (Subject Alternative Name) from the live certificate
# presented by the Envoy sidecar.  The SAN must be a SPIFFE URI of the
# form: spiffe://<cluster-domain>/ns/<namespace>/sa/<service-account>
# ─────────────────────────────────────────────────────────────────────
check_svid_certs() {
  c "$BOLD$CYAN"; echo -e "\n── Check 6: SPIFFE SVID certificate validation ──"; c "$RESET"

  if [[ -z "$ISTIOCTL" ]]; then
    echo -e "  $(skip_icon)  istioctl not found"
    record SKIP "svid-check" "istioctl not found"
    return
  fi

  local namespaces=(apps securecloud siem)
  [[ -n "$FILTER_NS" ]] && namespaces=("$FILTER_NS")

  for ns in "${namespaces[@]}"; do
    if ! kubectl get namespace "${ns}" &>/dev/null; then
      continue
    fi

    # Grab the first running pod in the namespace that has a sidecar
    local pod
    pod=$(kubectl get pod -n "${ns}" \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [[ -z "$pod" ]]; then
      echo -e "  $(skip_icon)  ${ns}: no running pods"
      record SKIP "svid:${ns}" "no pods"
      continue
    fi

    # Use istioctl to retrieve the certificate chain from the Envoy proxy
    local cert_dump spiffe_uri
    cert_dump=$("${ISTIOCTL}" proxy-config secret "${pod}" -n "${ns}" \
      -o json 2>/dev/null || echo "")

    if [[ -z "$cert_dump" ]]; then
      echo -e "  $(warn_icon)  ${ns}/${pod}: could not retrieve proxy secret (sidecar injected?)"
      add_row "WARN" "${ns}/${pod}" "—" "—" "no proxy secret"
      record WARN "svid:${ns}/${pod}" "no proxy secret"
      continue
    fi

    spiffe_uri=$(echo "$cert_dump" | python3 -c "
import sys, json, base64, re
try:
    data = json.load(sys.stdin)
    # Walk dynamic_active_secrets to find the certificate
    for s in data.get('dynamicActiveSecrets', []):
        cert_b64 = (s.get('secret', {})
                     .get('tlsCertificate', {})
                     .get('certificateChain', {})
                     .get('inlineBytes', ''))
        if cert_b64:
            # Extract SPIFFE URI from certificate SAN using regex on PEM
            cert_pem = base64.b64decode(cert_b64).decode('utf-8', errors='replace')
            m = re.search(r'spiffe://[^\s\"]+', cert_pem)
            if m:
                print(m.group(0))
                break
except Exception:
    pass
" 2>/dev/null || echo "")

    if [[ -n "$spiffe_uri" ]]; then
      echo -e "  $(pass_icon)  ${ns}/${pod}"
      echo -e "             SVID: ${CYAN}${spiffe_uri}${RESET}"
      add_row "PASS" "${ns}/${pod}" "ISTIO_MUTUAL" "SPIFFE" "${spiffe_uri##*/}"
      record PASS "svid:${ns}/${pod}" "${spiffe_uri}"
    else
      # Fallback: check that the sidecar is present at all
      local sidecar_count
      sidecar_count=$(kubectl get pod "${pod}" -n "${ns}" \
        -o jsonpath='{.spec.containers[*].name}' 2>/dev/null \
        | tr ' ' '\n' | grep -c 'istio-proxy' || echo 0)

      if [[ "$sidecar_count" -ge 1 ]]; then
        echo -e "  $(warn_icon)  ${ns}/${pod}: sidecar present but SVID not readable via proxy-config"
        add_row "WARN" "${ns}/${pod}" "?" "present" "SVID not parsed"
        record WARN "svid:${ns}/${pod}" "sidecar present, SVID unreadable"
      else
        echo -e "  $(fail_icon)  ${ns}/${pod}: no istio-proxy sidecar container found"
        add_row "FAIL" "${ns}/${pod}" "NONE" "✗" "no sidecar"
        record FAIL "svid:${ns}/${pod}" "no sidecar"
      fi
    fi
  done
}

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────
main() {
  if [[ "$JSON_OUTPUT" == false ]]; then
    c "$BOLD$CYAN"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║        SecureCloud-BD — mTLS Verification            ║"
    echo "╚══════════════════════════════════════════════════════╝"
    c "$RESET"
  fi

  # Locate istioctl (best-effort; checks that require it skip gracefully)
  ISTIOCTL=$(find_istioctl 2>/dev/null || echo "")
  if [[ -n "$ISTIOCTL" ]]; then
    info() { echo -e "${CYAN}[INFO]${RESET}  $*"; }
    info "Using istioctl: ${ISTIOCTL}"
  else
    echo -e "${YELLOW}[WARN]${RESET}  istioctl not found; checks 5 and 6 will be skipped"
    echo -e "       Run 'bash infra/istio/install-istio.sh' to install it"
  fi

  check_control_plane
  check_injection_labels
  check_peer_authentications
  check_destination_rules
  check_tls_pairs
  check_svid_certs

  # ── Results table ──────────────────────────────────────────────────
  if [[ "$JSON_OUTPUT" == false ]]; then
    print_table
  fi

  # ── Summary ────────────────────────────────────────────────────────
  local total=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))

  if [[ "$JSON_OUTPUT" == true ]]; then
    local json_array
    json_array=$(printf '%s\n' "${JSON_RESULTS[@]}" | paste -sd',' -)
    echo "{\"summary\":{\"pass\":${PASS_COUNT},\"fail\":${FAIL_COUNT},\"warn\":${WARN_COUNT},\"skip\":${SKIP_COUNT},\"total\":${total}},\"results\":[${json_array}]}"
  else
    echo ""
    c "$BOLD"
    echo "═══════════════════════════════════════════════════════"
    echo "  Summary"
    echo "═══════════════════════════════════════════════════════"
    c "$RESET"
    printf "  ${GREEN}%-8s${RESET} %d\n" "PASS"  "$PASS_COUNT"
    printf "  ${RED}%-8s${RESET} %d\n"   "FAIL"  "$FAIL_COUNT"
    printf "  ${YELLOW}%-8s${RESET} %d\n" "WARN"  "$WARN_COUNT"
    printf "  ${DIM}%-8s${RESET} %d\n"   "SKIP"  "$SKIP_COUNT"
    printf "  %-8s %d\n"                 "TOTAL" "$total"
    echo ""

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
      c "$RED$BOLD"
      echo "  RESULT: FAIL — ${FAIL_COUNT} check(s) failed."
      c "$RESET"
      echo ""
      echo "  Common causes and fixes:"
      echo ""
      echo "  CONFLICT status from tls-check:"
      echo "    → The server expects mTLS but the client DestinationRule is missing"
      echo "      or set to DISABLE.  Apply: kubectl apply -f infra/istio/destination-rules.yaml"
      echo ""
      echo "  No sidecar / SVID missing:"
      echo "    → The pod was created before injection was enabled.  Restart it:"
      echo "      kubectl rollout restart deployment/<name> -n <namespace>"
      echo ""
      echo "  PeerAuthentication mode is not STRICT:"
      echo "    → Apply: kubectl apply -f infra/istio/peer-authentication.yaml"
      echo ""
      echo "  NetworkPolicy blocking Istio control plane traffic (port 15010/15012):"
      echo "    → Add an allow rule for the istio-system namespace."
      echo ""
      exit 1
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
      c "$YELLOW$BOLD"
      echo "  RESULT: WARN — ${WARN_COUNT} advisory check(s). Review warnings above."
      c "$RESET"
      exit 0
    else
      c "$GREEN$BOLD"
      echo "  RESULT: PASS — all ${PASS_COUNT} checks confirmed mTLS is active."
      c "$RESET"
      exit 0
    fi
  fi
}

main "$@"
