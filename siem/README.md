# siem/

ELK-stack SIEM pipeline and Falco runtime-security configuration.

## Stack overview

```
Pod/Node logs + Zeek conn.log
          │
          ▼ (DaemonSet on every node)
      Filebeat  ──────────────────────────────┐
                                              │ Beats protocol
                                              ▼
                                         Logstash
                                     (parse, enrich)
                                              │
                                              ▼
                                     Elasticsearch
                                   index: securecloud-*
                                              │
                                              ▼
                                          Kibana
                                   (dashboards / alerts)
```

Falco runs as a privileged DaemonSet (eBPF mode), writes JSON alert lines to
`/var/log/falco/falco.json` on every node, and Filebeat ships those too.

## Sub-directories

| Path | Contents |
|------|---------|
| `elasticsearch/` | StatefulSet (single-node), headless Service, credential Secret |
| `logstash/` | ConfigMap with pipeline (`securecloud.conf`) + Deployment + Service |
| `kibana/` | Deployment (NodePort 5601) |
| `filebeat/` | DaemonSet, ConfigMap, ServiceAccount, ClusterRole/Binding |
| `falco/` | `falco-values.yaml` — Helm values with 4 custom SecureCloud rules |

## Deploy

```bash
# Credentials — override with a real secret in production
kubectl apply -f siem/elasticsearch/secret.yaml

kubectl apply -f siem/elasticsearch/statefulset.yaml
kubectl apply -f siem/logstash/configmap.yaml
kubectl apply -f siem/logstash/deployment.yaml
kubectl apply -f siem/kibana/deployment.yaml
kubectl apply -f siem/filebeat/daemonset.yaml

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco \
  --namespace siem \
  -f siem/falco/falco-values.yaml
```

## Elasticsearch index patterns

| Index | Content |
|-------|---------|
| `securecloud-zeek-YYYY.MM.dd` | Zeek `conn.log` flows |
| `securecloud-falco-YYYY.MM.dd` | Falco JSON alerts |

## Custom Falco rules

Four rules fire on `securecloud`, `ml`, and `siem` namespaces:

1. **Unexpected outbound network from pod** — traffic to IPs outside the allow-list
2. **Sensitive file read in container** — `/etc/passwd`, `/etc/shadow`, SSH keys
3. **Shell spawned inside container** — any `sh`/`bash`/`zsh` in app pods
4. **Privilege escalation attempt** — `sudo`/`su` inside a pod

## Memory budget

| Component | RAM request | RAM limit |
|-----------|-------------|-----------|
| Elasticsearch | 1 Gi | 1.5 Gi |
| Logstash | 512 Mi | 768 Mi |
| Kibana | 512 Mi | 768 Mi |
| Filebeat (per node) | 100 Mi | 200 Mi |
| Falco (per node) | 256 Mi | 512 Mi |
