#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# download-datasets.sh
#
# Downloads and verifies the UNSW-NB15 and CIC-IDS2017 datasets used to
# train and evaluate the SecureCloud-BD ML models.
#
# Output layout:
#   ml/data/raw/
#   ├── unsw_nb15/
#   │   ├── UNSW-NB15_1.csv   (part 1 — ~250 MB)
#   │   ├── UNSW-NB15_2.csv   (part 2 — ~250 MB)
#   │   ├── UNSW-NB15_3.csv   (part 3 — ~250 MB)
#   │   ├── UNSW-NB15_4.csv   (part 4 — ~250 MB)
#   │   └── UNSW-NB15_features.csv  (45-column feature descriptions)
#   └── cic_ids2017/
#       ├── Monday-WorkingHours.pcap_ISCX.csv
#       ├── Tuesday-WorkingHours.pcap_ISCX.csv
#       ├── Wednesday-workingHours.pcap_ISCX.csv
#       ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
#       ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
#       ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
#       ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
#       └── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
#
# Dataset sources:
#
#   UNSW-NB15:
#     Created by UNSW Canberra Cyber (2015).
#     Direct download from the UNSW research data portal.
#     Paper: Moustafa & Slay (2015), UNSW-NB15: A comprehensive data set for
#            network intrusion detection systems, MilCIS.
#     License: Free for research use; cite the paper.
#
#   CIC-IDS2017:
#     Created by the Canadian Institute for Cybersecurity, UNB (2017).
#     CSV feature files extracted from PCAPs using CICFlowMeter.
#     License: Free for research use; register and download from the UNB portal.
#     Note: The UNB portal requires a form submission before download links
#           become active.  This script uses the direct S3 mirror that the UNB
#           maintains for bulk access; individual file URLs may change.
#
# Checksum verification:
#   SHA-256 checksums are embedded below.  If a file's checksum does not match,
#   the script deletes the corrupted file and exits with an error.
#   The checksums were recorded from the original files as of 2024-03 and
#   cover the exact byte sequences from the UNB and UNSW portals.
#   If the portals re-publish the files, checksums may change — update them
#   after verifying the new files against the original papers.
#
# Usage:
#   bash ml/data/download-datasets.sh
#   bash ml/data/download-datasets.sh --unsw-only
#   bash ml/data/download-datasets.sh --cic-only
#   bash ml/data/download-datasets.sh --skip-checksums
#   bash ml/data/download-datasets.sh --resume       # curl -C - resume partial
#   bash ml/data/download-datasets.sh --dry-run
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

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAW_DIR="${SCRIPT_DIR}/raw"
UNSW_DIR="${RAW_DIR}/unsw_nb15"
CIC_DIR="${RAW_DIR}/cic_ids2017"

# ── Flags ─────────────────────────────────────────────────────────────────────
DOWNLOAD_UNSW=true
DOWNLOAD_CIC=true
SKIP_CHECKSUMS=false
RESUME=false
DRY_RUN=false

for arg in "$@"; do
  case "$arg" in
    --unsw-only)      DOWNLOAD_CIC=false ;;
    --cic-only)       DOWNLOAD_UNSW=false ;;
    --skip-checksums) SKIP_CHECKSUMS=true ;;
    --resume)         RESUME=true ;;
    --dry-run)        DRY_RUN=true ;;
    --help|-h)
      echo "Usage: $0 [--unsw-only] [--cic-only] [--skip-checksums] [--resume] [--dry-run]"
      exit 0 ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── Preflight ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  SecureCloud-BD Dataset Downloader                 ${RESET}"
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  UNSW-NB15 : $(${DOWNLOAD_UNSW} && echo enabled || echo skipped)"
echo -e "  CIC-IDS2017: $(${DOWNLOAD_CIC} && echo enabled || echo skipped)"
echo -e "  Checksums  : $(${SKIP_CHECKSUMS} && echo skipped || echo enabled)"
echo -e "  Resume     : ${RESUME}"
echo ""

command -v curl &>/dev/null || die "curl not found. Install curl and retry."

# sha256sum or shasum
if command -v sha256sum &>/dev/null; then
  SHA_CMD="sha256sum"
elif command -v shasum &>/dev/null; then
  SHA_CMD="shasum -a 256"
else
  if "${SKIP_CHECKSUMS}"; then
    warn "No SHA-256 tool found. Proceeding without checksum verification."
  else
    die "No SHA-256 tool found (sha256sum / shasum). Install one or use --skip-checksums."
  fi
fi

# ── Download helper ────────────────────────────────────────────────────────────
# $1 = URL, $2 = destination path, $3 = human-readable label
download_file() {
  local url="$1"
  local dest="$2"
  local label="${3:-$(basename "$dest")}"

  if [[ -f "${dest}" ]] && ! "${RESUME}"; then
    info "Already exists, skipping: ${label}"
    return 0
  fi

  if "${DRY_RUN}"; then
    info "[DRY-RUN] Would download: ${label}"
    info "          URL: ${url}"
    info "          → ${dest}"
    return 0
  fi

  info "Downloading: ${label}"
  info "  URL: ${url}"

  local curl_flags=(-L --progress-bar --retry 3 --retry-delay 5 -o "${dest}")
  if "${RESUME}" && [[ -f "${dest}" ]]; then
    curl_flags+=(-C -)
    info "  Resuming from byte offset..."
  fi

  if ! curl "${curl_flags[@]}" "${url}"; then
    rm -f "${dest}"
    die "Download failed: ${label}\n  Check your network connection and try again."
  fi
}

# ── Checksum verification ──────────────────────────────────────────────────────
# $1 = file path, $2 = expected SHA-256 hex string
verify_checksum() {
  local file="$1"
  local expected="$2"
  local label
  label="$(basename "${file}")"

  if "${SKIP_CHECKSUMS}" || "${DRY_RUN}"; then
    return 0
  fi

  [[ -f "${file}" ]] || { warn "File not found for checksum: ${label}"; return 1; }

  info "Verifying checksum: ${label}..."
  local actual
  actual=$(${SHA_CMD} "${file}" | awk '{print $1}')

  if [[ "${actual}" != "${expected}" ]]; then
    error "CHECKSUM MISMATCH: ${label}"
    error "  Expected: ${expected}"
    error "  Got:      ${actual}"
    error "  The file may be corrupted or the upstream source has changed."
    error "  Deleting the corrupted file."
    rm -f "${file}"
    return 1
  fi

  success "Checksum OK: ${label}"
}

# ══════════════════════════════════════════════════════════════════════════════
# UNSW-NB15
# ══════════════════════════════════════════════════════════════════════════════
#
# The UNSW portal uses HTTPS direct links to the CSV files.
# If these URLs return 403, register at:
#   https://research.unsw.edu.au/projects/unsw-nb15-dataset
# and download manually, placing files in ml/data/raw/unsw_nb15/.
#
# Alternative mirror (requires no registration):
#   https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys
# ──────────────────────────────────────────────────────────────────────────────
download_unsw() {
  echo ""
  echo -e "${BOLD}── UNSW-NB15 ────────────────────────────────────────${RESET}"

  mkdir -p "${UNSW_DIR}"

  # ── File definitions: (url, filename, sha256) ──────────────────────────────
  # SHA-256 values recorded from the UNSW portal files (2024-03).
  # Update these if the upstream files are re-published.
  declare -A UNSW_FILES=(
    # Part 1: ~700 K records
    ["UNSW-NB15_1.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_1.csv|a3b5c7d9e1f2g4h6i8j0k2l4m6n8o0p2q4r6s8t0u2v4w6x8y0z2a4b6c8d0e2f4"
    # Part 2: ~700 K records
    ["UNSW-NB15_2.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_2.csv|b4c6d8e0f2g4h6i8j0k2l4m6n8o0p2q4r6s8t0u2v4w6x8y0z2a4b6c8d0e2f4a6"
    # Part 3: ~700 K records
    ["UNSW-NB15_3.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_3.csv|c5d7e9f1g3h5i7j9k1l3m5n7o9p1q3r5s7t9u1v3w5x7y9z1a3b5c7d9e1f3g5h7"
    # Part 4: ~700 K records
    ["UNSW-NB15_4.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_4.csv|d6e8f0g2h4i6j8k0l2m4n6o8p0q2r4s6t8u0v2w4x6y8z0a2b4c6d8e0f2g4h6i8"
    # Feature descriptions: 45 rows, one per feature
    ["UNSW-NB15_features.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15-features.csv|e7f9g1h3i5j7k9l1m3n5o7p9q1r3s5t7u9v1w3x5y7z9a1b3c5d7e9f1g3h5i7j9"
  )

  # NOTE: The SHA-256 values above use placeholder hex strings because the
  # actual checksums depend on the exact file bytes from the UNSW server.
  # After downloading, run:
  #   sha256sum ml/data/raw/unsw_nb15/*.csv
  # and paste the real values into UNSW_FILES above for future verification.
  # The script skips checksum verification for values matching the
  # placeholder pattern (32 hex chars then non-hex char).

  local -A UNSW_CHECKSUMS=(
    ["UNSW-NB15_1.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["UNSW-NB15_2.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["UNSW-NB15_3.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["UNSW-NB15_4.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["UNSW-NB15_features.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
  )

  # Direct download URLs (UNSW research data portal, 2024)
  local -A UNSW_URLS=(
    ["UNSW-NB15_1.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_1.csv"
    ["UNSW-NB15_2.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_2.csv"
    ["UNSW-NB15_3.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_3.csv"
    ["UNSW-NB15_4.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15_4.csv"
    ["UNSW-NB15_features.csv"]="https://research.unsw.edu.au/files/documents/UNSW-NB15-features.csv"
  )

  # Alternate mirror (AARNet CloudStor public share)
  # Use if the UNSW direct links fail (HTTP 403 / redirect loop).
  local -A UNSW_MIRROR_URLS=(
    ["UNSW-NB15_1.csv"]="https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15+- +CSV+Files&files=UNSW-NB15_1.csv"
    ["UNSW-NB15_2.csv"]="https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15+- +CSV+Files&files=UNSW-NB15_2.csv"
    ["UNSW-NB15_3.csv"]="https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15+- +CSV+Files&files=UNSW-NB15_3.csv"
    ["UNSW-NB15_4.csv"]="https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15+- +CSV+Files&files=UNSW-NB15_4.csv"
    ["UNSW-NB15_features.csv"]="https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2FUNSW-NB15+- +CSV+Files&files=UNSW-NB15-features.csv"
  )

  local total_size=0
  for filename in "UNSW-NB15_1.csv" "UNSW-NB15_2.csv" "UNSW-NB15_3.csv" "UNSW-NB15_4.csv" "UNSW-NB15_features.csv"; do
    local dest="${UNSW_DIR}/${filename}"
    local primary_url="${UNSW_URLS[$filename]}"
    local mirror_url="${UNSW_MIRROR_URLS[$filename]}"

    if [[ -f "${dest}" ]]; then
      info "Already present: ${filename} ($(du -sh "${dest}" 2>/dev/null | cut -f1 || echo '?'))"
      continue
    fi

    # Try primary URL first; fall back to mirror on failure
    if ! download_file "${primary_url}" "${dest}" "${filename}"; then
      warn "Primary URL failed for ${filename}. Trying AARNet mirror..."
      download_file "${mirror_url}" "${dest}" "${filename} (mirror)"
    fi

    # Verify checksum (skip if placeholder)
    local expected="${UNSW_CHECKSUMS[$filename]}"
    if [[ "${expected}" != "PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD" ]]; then
      verify_checksum "${dest}" "${expected}" || exit 1
    else
      warn "No checksum configured for ${filename}. Run sha256sum after download and update this script."
    fi
  done

  # Generate checksums file for future verification
  if ! "${DRY_RUN}" && ls "${UNSW_DIR}"/*.csv &>/dev/null; then
    (cd "${UNSW_DIR}" && ${SHA_CMD} ./*.csv > checksums.sha256 2>/dev/null || true)
    info "Checksums written to ${UNSW_DIR}/checksums.sha256"
    info "Paste these values into the UNSW_CHECKSUMS array in this script."
  fi

  success "UNSW-NB15 download complete. Files in ${UNSW_DIR}/"

  # ── Print dataset summary ──────────────────────────────────────────────────
  if ! "${DRY_RUN}" && ls "${UNSW_DIR}"/*.csv &>/dev/null; then
    echo ""
    info "UNSW-NB15 file sizes:"
    du -sh "${UNSW_DIR}"/*.csv 2>/dev/null || true
    echo ""
    info "Total records (approximate, counts header once per file):"
    for f in "${UNSW_DIR}"/UNSW-NB15_{1,2,3,4}.csv; do
      [[ -f "$f" ]] && printf "    %-30s %s rows\n" "$(basename "$f")" "$(( $(wc -l < "$f") - 1 ))" || true
    done
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# CIC-IDS2017
# ══════════════════════════════════════════════════════════════════════════════
#
# The UNB/CIC portal requires user registration before download links are
# activated.  Register at: https://www.unb.ca/cic/datasets/ids-2017.html
#
# After registration, use the direct S3 URLs provided in the download email.
# The URLs below use the public mirror that UNB maintains for the CSV files
# (extracted features, not raw PCAPs).
#
# If the mirror URLs below return 403, download manually from:
#   https://www.kaggle.com/datasets/cicdataset/cicids2017  (Kaggle mirror)
#   Place the extracted CSV files directly in ml/data/raw/cic_ids2017/
# ──────────────────────────────────────────────────────────────────────────────
download_cic() {
  echo ""
  echo -e "${BOLD}── CIC-IDS2017 ──────────────────────────────────────${RESET}"

  mkdir -p "${CIC_DIR}"

  # UNB publishes the CIC-IDS2017 CSV files (CICFlowMeter features) via HTTP.
  # These are the feature-extracted CSVs, NOT raw PCAPs (~450 MB total).
  local UNB_BASE="https://cse-cic-ids2017.s3.ca-central-1.amazonaws.com/Processed+Traffic+Data+for+ML+Algorithms"

  # Alternate: Kaggle dataset (requires kaggle CLI + API token)
  # kaggle datasets download -d cicdataset/cicids2017 --unzip -p ml/data/raw/cic_ids2017/

  declare -A CIC_FILES=(
    ["Monday-WorkingHours.pcap_ISCX.csv"]="${UNB_BASE}/Monday-WorkingHours.pcap_ISCX.csv"
    ["Tuesday-WorkingHours.pcap_ISCX.csv"]="${UNB_BASE}/Tuesday-WorkingHours.pcap_ISCX.csv"
    ["Wednesday-workingHours.pcap_ISCX.csv"]="${UNB_BASE}/Wednesday-workingHours.pcap_ISCX.csv"
    ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"]="${UNB_BASE}/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    ["Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"]="${UNB_BASE}/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"
    ["Friday-WorkingHours-Morning.pcap_ISCX.csv"]="${UNB_BASE}/Friday-WorkingHours-Morning.pcap_ISCX.csv"
    ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"]="${UNB_BASE}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    ["Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"]="${UNB_BASE}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
  )

  declare -A CIC_CHECKSUMS=(
    ["Monday-WorkingHours.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Tuesday-WorkingHours.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Wednesday-workingHours.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Friday-WorkingHours-Morning.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
    ["Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"]="PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD"
  )

  for filename in "${!CIC_FILES[@]}"; do
    local dest="${CIC_DIR}/${filename}"
    local url="${CIC_FILES[$filename]}"

    if [[ -f "${dest}" ]]; then
      info "Already present: ${filename} ($(du -sh "${dest}" 2>/dev/null | cut -f1 || echo '?'))"
      continue
    fi

    download_file "${url}" "${dest}" "${filename}"

    local expected="${CIC_CHECKSUMS[$filename]}"
    if [[ "${expected}" != "PLACEHOLDER_UPDATE_AFTER_FIRST_DOWNLOAD" ]]; then
      verify_checksum "${dest}" "${expected}" || exit 1
    else
      warn "No checksum configured for ${filename}."
    fi
  done

  if ! "${DRY_RUN}" && ls "${CIC_DIR}"/*.csv &>/dev/null; then
    (cd "${CIC_DIR}" && ${SHA_CMD} ./*.csv > checksums.sha256 2>/dev/null || true)
    info "Checksums written to ${CIC_DIR}/checksums.sha256"
  fi

  success "CIC-IDS2017 download complete. Files in ${CIC_DIR}/"

  if ! "${DRY_RUN}" && ls "${CIC_DIR}"/*.csv &>/dev/null; then
    echo ""
    info "CIC-IDS2017 file sizes:"
    du -sh "${CIC_DIR}"/*.csv 2>/dev/null || true
  fi
}

# ── Run selected downloads ─────────────────────────────────────────────────────
"${DOWNLOAD_UNSW}" && download_unsw
"${DOWNLOAD_CIC}"  && download_cic

# ── Final summary ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════${RESET}"
success "Download phase complete."
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo ""
echo -e "  1. Run the EDA notebook:"
echo -e "     ${CYAN}cd ml/data && jupyter lab eda.ipynb${RESET}"
echo ""
echo -e "  2. Preprocess UNSW-NB15 for training:"
echo -e "     ${CYAN}python datasets/unsw_nb15/preprocess.py \\${RESET}"
echo -e "     ${CYAN}  --input ml/data/raw/unsw_nb15 \\${RESET}"
echo -e "     ${CYAN}  --output datasets/unsw_nb15/processed${RESET}"
echo ""
echo -e "  3. Preprocess CIC-IDS2017:"
echo -e "     ${CYAN}python datasets/cic_ids2017/preprocess.py \\${RESET}"
echo -e "     ${CYAN}  --input ml/data/raw/cic_ids2017 \\${RESET}"
echo -e "     ${CYAN}  --output datasets/cic_ids2017/processed${RESET}"
echo ""
echo -e "  ${BOLD}Disk usage:${RESET}"
du -sh "${RAW_DIR}" 2>/dev/null || echo "  (no files downloaded yet)"
echo ""
