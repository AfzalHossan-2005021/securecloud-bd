# SecureCloud-BD — root Makefile
#
# Targets
#   setup          Install all Python dependencies (ml + api + datasets)
#   start-cluster  Start Minikube and bootstrap Istio + OPA Gatekeeper
#   deploy-infra   Apply namespaces, Istio policies, Gatekeeper constraints, Helm chart
#   deploy-siem    Deploy ELK stack, Filebeat, and Falco
#   train          Preprocess UNSW-NB15 and train both ML models
#   deploy-ml      Build threat-API image and deploy via Helm
#   attack-sim     Run Ansible attack playbooks against the running cluster
#   test           Run all pytest suites (ml, api, datasets)
#   teardown       Delete the Minikube cluster entirely
#
# Variables you can override on the command line:
#   MINIKUBE_CPUS     (default 4)
#   MINIKUBE_MEMORY   (default 6144)
#   UNSW_TRAIN        path to UNSW-NB15 training CSV
#   UNSW_TEST         path to UNSW-NB15 testing CSV
#   CIC_DIR           path to CIC-IDS2017 MachineLearningCVE/ directory
#   PIVOT_POD         name of the pod used as the attack pivot

MINIKUBE_CPUS   ?= 4
MINIKUBE_MEMORY ?= 6144
UNSW_TRAIN      ?= datasets/unsw_nb15/raw/UNSW_NB15_training-set.csv
UNSW_TEST       ?= datasets/unsw_nb15/raw/UNSW_NB15_testing-set.csv
CIC_DIR         ?= datasets/cic_ids2017/raw/MachineLearningCVE
PIVOT_POD       ?= $(shell kubectl get pods -n securecloud -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

.PHONY: setup start-cluster deploy-infra deploy-siem train deploy-ml attack-sim test teardown

# ──────────────────────────────────────────────────────────────────────
# setup — install Python deps for all sub-packages
# ──────────────────────────────────────────────────────────────────────
setup:
	pip install -r ml/requirements.txt
	pip install -r api/requirements.txt
	pip install -r datasets/requirements.txt

# ──────────────────────────────────────────────────────────────────────
# start-cluster — start Minikube + install Istio + OPA Gatekeeper
# ──────────────────────────────────────────────────────────────────────
start-cluster:
	MINIKUBE_CPUS=$(MINIKUBE_CPUS) MINIKUBE_MEMORY=$(MINIKUBE_MEMORY) \
	  bash infra/setup-minikube.sh

# ──────────────────────────────────────────────────────────────────────
# deploy-infra — namespaces, Istio policies, Gatekeeper, Helm app chart
# ──────────────────────────────────────────────────────────────────────
deploy-infra:
	kubectl apply -f infra/namespaces/namespaces.yaml
	kubectl apply -f infra/istio/peer-authentication.yaml
	kubectl apply -f infra/istio/destination-rules.yaml
	kubectl apply -f infra/istio/authorization-policies.yaml
	kubectl apply -f infra/gatekeeper/constraint-template-privileged.yaml
	kubectl apply -f infra/gatekeeper/constraint-template-hostpath.yaml
	@echo "Waiting 15s for Gatekeeper CRDs to register…"
	@sleep 15
	kubectl apply -f infra/gatekeeper/constraint-privileged.yaml
	kubectl apply -f infra/gatekeeper/constraint-hostpath.yaml
	helm upgrade --install securecloud infra/helm/securecloud \
	  --namespace securecloud --create-namespace

# ──────────────────────────────────────────────────────────────────────
# deploy-siem — ELK stack + Filebeat DaemonSet + Falco
# ──────────────────────────────────────────────────────────────────────
deploy-siem:
	@if ! kubectl get secret elastic-credentials -n siem >/dev/null 2>&1; then \
	  echo "Creating placeholder Elasticsearch secret (change password before prod!)"; \
	  kubectl create namespace siem --dry-run=client -o yaml | kubectl apply -f -; \
	  kubectl create secret generic elastic-credentials \
	    --from-literal=password=changeme \
	    --namespace siem; \
	fi
	kubectl apply -f siem/elasticsearch/statefulset.yaml
	kubectl apply -f siem/logstash/configmap.yaml
	kubectl apply -f siem/logstash/deployment.yaml
	kubectl apply -f siem/kibana/deployment.yaml
	kubectl apply -f siem/filebeat/daemonset.yaml
	helm repo add falcosecurity https://falcosecurity.github.io/charts || true
	helm repo update
	helm upgrade --install falco falcosecurity/falco \
	  --namespace siem \
	  --create-namespace \
	  -f siem/falco/falco-values.yaml
	@echo ""
	@echo "Kibana will be available at: $$(minikube service kibana -n siem --url 2>/dev/null || echo 'kubectl port-forward svc/kibana 5601:5601 -n siem')"

# ──────────────────────────────────────────────────────────────────────
# train — preprocess datasets and train both ML models
# ──────────────────────────────────────────────────────────────────────
train:
	@echo "==> Preprocessing UNSW-NB15"
	python datasets/unsw_nb15/preprocess.py \
	  --train $(UNSW_TRAIN) \
	  --test  $(UNSW_TEST) \
	  --out   datasets/unsw_nb15/processed/
	@echo "==> Training IsolationForest + LSTM Autoencoder"
	python ml/training/train.py \
	  --data    datasets/unsw_nb15/processed/train.parquet \
	  --output  ml/models/saved \
	  --epochs  50 \
	  --contamination 0.05 \
	  --timesteps 10

# ──────────────────────────────────────────────────────────────────────
# deploy-ml — build Docker image (into Minikube daemon) and upgrade chart
# ──────────────────────────────────────────────────────────────────────
deploy-ml:
	@echo "==> Building threat-api image into Minikube Docker daemon"
	eval $$(minikube docker-env) && \
	  docker build -f api/Dockerfile -t securecloud/threat-api:latest .
	@echo "==> Copying trained models into cluster PVC"
	$(MAKE) _copy-models
	helm upgrade --install securecloud infra/helm/securecloud \
	  --namespace securecloud --create-namespace \
	  --set threatApi.tag=latest

_copy-models:
	@echo "Hint: use 'kubectl cp ml/models/saved/. <pod>:/models' after the pod starts"

# ──────────────────────────────────────────────────────────────────────
# attack-sim — run all Ansible attack playbooks
# ──────────────────────────────────────────────────────────────────────
attack-sim:
	@if [ -z "$(PIVOT_POD)" ]; then \
	  echo "ERROR: No pod found in the securecloud namespace. Deploy the app first."; \
	  exit 1; \
	fi
	PIVOT_POD=$(PIVOT_POD) bash attack-sim/scripts/run_sim.sh

# ──────────────────────────────────────────────────────────────────────
# test — run all pytest suites
# ──────────────────────────────────────────────────────────────────────
test:
	pytest ml/tests/ api/tests/ datasets/tests/ -v --tb=short

# ──────────────────────────────────────────────────────────────────────
# teardown — destroy the Minikube cluster
# ──────────────────────────────────────────────────────────────────────
teardown:
	@echo "WARNING: This will delete the entire Minikube cluster."
	@read -p "Type 'yes' to confirm: " confirm && [ "$$confirm" = "yes" ]
	minikube delete
