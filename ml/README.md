# ml/

Python package implementing the SecureCloud-BD anomaly-detection ensemble.

## Package layout

```
ml/
├── models/
│   ├── iforest_model.py      IForestDetector  — sklearn IsolationForest wrapper
│   ├── autoencoder_model.py  LSTMAutoencoder  — seq2seq LSTM AE (Keras/TF2)
│   └── ensemble.py           ThreatEnsemble   — weighted fusion (0.4 + 0.6)
├── training/
│   └── train.py              CLI training script
├── inference/
│   └── infer.py              Batch-scoring helper used by the API
└── tests/
    └── test_models.py        pytest unit tests
```

## Install

```bash
pip install -r ml/requirements.txt
```

## Train

```bash
python ml/training/train.py \
  --data  datasets/unsw_nb15/processed/train.parquet \
  --output ml/models/saved \
  --epochs 50 \
  --contamination 0.05 \
  --timesteps 10 \
  --iforest-weight 0.4 \
  --ae-weight 0.6
```

Trained artefacts written to `ml/models/saved/`:

```
ml/models/saved/
├── iforest/
│   ├── iforest.joblib
│   └── iforest_scaler.joblib
├── autoencoder/
│   ├── autoencoder.keras
│   ├── ae_scaler.joblib
│   └── ae_meta.joblib
└── version.txt          (written manually before deployment)
```

## Scoring API

```python
from ml.models import ThreatEnsemble, EnsembleConfig
import numpy as np

ens = ThreatEnsemble.load("ml/models/saved")
X   = np.random.rand(100, 20).astype("float32")  # 100 flows × 20 features
scores = ens.score(X)   # np.ndarray shape (100,) in [0, 1]
labels = ens.predict(X) # np.ndarray shape (100,) — 1 = anomaly
```

## Ensemble design

| Model | Algorithm | Score normalisation | Weight |
|-------|-----------|---------------------|--------|
| IForestDetector | IsolationForest (n=200) | min-max of decision_function | **0.4** |
| LSTMAutoencoder | seq2seq LSTM (64→32) | MSE / p95_threshold | **0.6** |

The autoencoder carries higher weight because it captures temporal patterns
(beaconing, slow exfiltration) that the tree-based model misses.
Weights were chosen by grid search on the UNSW-NB15 validation split
maximising F1.

## Tests

```bash
pytest ml/tests/ -v
```

Covers: fit/score shape, [0,1] range, anomaly > normal score ordering,
save/load round-trip for both models, and ensemble weight validation.
