"""
Feature engineering pipeline for raw UNSW-NB15 DataFrames.

Transforms a raw ``pd.DataFrame`` loaded from the four UNSW-NB15 CSV parts
into a ``np.float32`` array suitable for ``IForestDetector.fit()`` and
``LSTMAutoencoder.fit()``.

Transformation order
--------------------
1. Drop identifier / timestamp / target columns (``DROP_COLS``).
2. Add four derived features: ``byte_ratio``, ``duration_log``, ``pkt_rate``,
   ``flag_score``.
3. Median-impute numeric columns; mode-impute categorical columns.
4. OrdinalEncode categorical columns (``proto``, ``service``, ``state``).
5. RobustScale all numeric columns.

Note on double-scaling
----------------------
``IForestDetector`` contains an internal ``StandardScaler`` that was added
before this pipeline existed.  When using this pipeline as the canonical
preprocessing step, the IForest internal scaler becomes a redundant (but
harmless) linear rescaling of already-scaled data.  Future refactoring should
move the internal scaler into the pipeline and remove it from the model class.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OrdinalEncoder, RobustScaler
from sklearn.utils.validation import check_is_fitted

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Columns dropped unconditionally before any feature computation.
# These are identifiers, timestamps, raw sequence numbers, and the target.
DROP_COLS: frozenset[str] = frozenset({
    "srcip",         # source IP — identifier
    "dstip",         # destination IP — identifier
    "sport",         # source port (ephemeral, high-cardinality)
    "dsport",        # destination port
    "Stime",         # absolute start timestamp
    "Ltime",         # absolute last-packet timestamp
    "stcpb",         # raw TCP base sequence number — not a flow feature
    "dtcpb",         # raw TCP destination sequence number
    "id",            # row ID (present only in some dataset versions)
    "attack_cat",    # string target; binary `label` is used instead
    "label",         # target — must not appear in the feature matrix
    "_source_part",  # artefact added by the EDA notebook
})

# Columns treated as categorical and encoded with OrdinalEncoder.
# All other columns that contain numbers are treated as numeric.
CATEGORICAL_COLS: list[str] = ["proto", "service", "state"]

# TCP flag-count columns.  These exist in CIC-IDS2017 but are NOT part of the
# standard 45-column UNSW-NB15 schema.  When absent from the input DataFrame
# the derived ``flag_score`` feature defaults to 0.
FLAG_COLS: list[str] = [
    "fin_flag_count",
    "syn_flag_count",
    "rst_flag_count",
    "psh_flag_count",
]
# Weights reflect attack signal strength: RST (×3) > SYN (×2) > FIN/PSH (×1).
FLAG_WEIGHTS: list[int] = [1, 2, 3, 1]


# ---------------------------------------------------------------------------
# Derived feature computation
# ---------------------------------------------------------------------------

def _add_derived_features(X: pd.DataFrame) -> pd.DataFrame:
    """
    Compute and append four derived network-flow features to *X*.

    Returns a **copy** — the input is never mutated.

    Derived columns
    ---------------
    ``byte_ratio``
        ``sbytes / (dbytes + 1)``.  Captures directional byte asymmetry.
        Values far from 1 indicate unidirectional bulk transfers, which are
        common in DoS and data-exfiltration attacks.

    ``duration_log``
        ``log1p(dur)``.  Compresses the heavy right tail of flow duration
        into a near-symmetric distribution, which aids both IsolationForest
        path partitioning and the LSTM AE's reconstruction loss.

    ``pkt_rate``
        ``Spkts / (dur + 0.001)``.  Source packet rate in packets/second.
        High values characterise rapid-fire DoS and port-scanning attacks;
        the ``+ 0.001`` guard prevents division-by-zero on zero-duration flows.

    ``flag_score``
        Weighted sum of TCP flag counts: FIN×1 + SYN×2 + RST×3 + PSH×1.
        SYN and RST are weighted higher because they are the primary
        indicators of SYN-scan and RST-injection attacks.  Flag columns
        absent from the input are treated as 0.

    Parameters
    ----------
    X : pd.DataFrame
        Input DataFrame after identifier columns have been dropped, but
        before imputation and scaling.  Must have a RangeIndex or at least
        a consistent index (used to construct zero-filled Series).

    Returns
    -------
    pd.DataFrame
        Copy of *X* with four new columns appended at the right.
    """
    X = X.copy()

    def _col(name: str) -> pd.Series:
        """Return column as numeric Series, or zeros if column is absent."""
        if name in X.columns:
            return pd.to_numeric(X[name], errors="coerce").fillna(0.0)
        return pd.Series(0.0, index=X.index)

    sbytes = _col("sbytes")
    dbytes = _col("dbytes")
    dur    = _col("dur").clip(lower=0)
    spkts  = _col("Spkts")

    X["byte_ratio"]   = sbytes / (dbytes + 1.0)
    X["duration_log"] = np.log1p(dur)
    X["pkt_rate"]     = spkts / (dur + 0.001)
    X["flag_score"]   = sum(
        _col(col) * w for col, w in zip(FLAG_COLS, FLAG_WEIGHTS)
    )

    return X


# ---------------------------------------------------------------------------
# Main pipeline class
# ---------------------------------------------------------------------------

class FeatureEngineeringPipeline(BaseEstimator, TransformerMixin):
    """
    End-to-end scikit-learn–compatible preprocessing pipeline for UNSW-NB15.

    Implements the standard sklearn ``fit`` / ``transform`` / ``fit_transform``
    interface and is serialisable via ``save()`` / ``load()``.

    Parameters
    ----------
    categorical_cols : list[str], optional
        Override the default categorical columns ``["proto", "service",
        "state"]``.  Any column in this list absent from the input DataFrame
        is silently ignored.

    Attributes set after ``fit()``
    --------------------------------
    num_cols_ : list[str]
        Numeric columns passed to ``RobustScaler``, in output order.
    cat_cols_ : list[str]
        Categorical columns passed to ``OrdinalEncoder``, in output order.
    n_features_out_ : int
        Total number of columns in the output array
        (``len(num_cols_) + len(cat_cols_)``).
    preprocessor_ : sklearn.compose.ColumnTransformer
        Fitted inner transformer.  Exposed for inspection.

    Examples
    --------
    >>> from ml.preprocessing import FeatureEngineeringPipeline
    >>> pipeline = FeatureEngineeringPipeline()
    >>> X_arr = pipeline.fit_transform(df_train)   # np.float32, no NaN
    >>> X_test = pipeline.transform(df_test)
    >>> pipeline.save("ml/models/saved/preprocessor.joblib")
    """

    def __init__(
        self,
        categorical_cols: Optional[list[str]] = None,
    ) -> None:
        self.categorical_cols = categorical_cols if categorical_cols is not None \
            else CATEGORICAL_COLS

    # ------------------------------------------------------------------
    # Public sklearn API
    # ------------------------------------------------------------------

    def fit(self, X: pd.DataFrame, y=None) -> "FeatureEngineeringPipeline":
        """
        Fit imputers, encoder, and scaler on *X*.

        The ``label`` column is ignored if present — it is listed in
        ``DROP_COLS`` and stripped during ``_prepare()``.

        Parameters
        ----------
        X : pd.DataFrame
            Raw UNSW-NB15 DataFrame.  All 49 standard columns or a subset —
            missing optional columns are handled gracefully.
        y : ignored
            Accepted for sklearn API compatibility.

        Returns
        -------
        self
        """
        self._validate_input(X)
        X_prep = self._prepare(X)
        self._init_column_lists(X_prep)
        self.preprocessor_ = self._build_preprocessor()
        self.preprocessor_.fit(X_prep)
        self.n_features_out_ = len(self.num_cols_) + len(self.cat_cols_)
        log.info(
            "FeatureEngineeringPipeline fitted — %d numeric + %d categorical"
            " = %d output features",
            len(self.num_cols_), len(self.cat_cols_), self.n_features_out_,
        )
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """
        Apply the fitted pipeline to *X*.

        Parameters
        ----------
        X : pd.DataFrame
            Raw UNSW-NB15 DataFrame.

        Returns
        -------
        np.ndarray, shape (n_samples, n_features_out_), dtype float32
            Feature matrix guaranteed to contain no NaN or infinite values.

        Raises
        ------
        sklearn.exceptions.NotFittedError
            If called before ``fit()``.
        TypeError
            If *X* is not a ``pd.DataFrame``.
        """
        check_is_fitted(self, "preprocessor_")
        self._validate_input(X)
        X_prep = self._prepare(X)
        return self.preprocessor_.transform(X_prep).astype(np.float32)

    def fit_transform(
        self, X: pd.DataFrame, y=None, **fit_params
    ) -> np.ndarray:
        """
        Fit on *X* then transform it in a single pass.

        Overrides ``TransformerMixin.fit_transform`` to call ``_prepare``
        only once instead of twice (as ``fit(X).transform(X)`` would do).

        Parameters
        ----------
        X : pd.DataFrame
            Raw UNSW-NB15 DataFrame.
        y : ignored

        Returns
        -------
        np.ndarray, shape (n_samples, n_features_out_), dtype float32
        """
        self._validate_input(X)
        X_prep = self._prepare(X)
        self._init_column_lists(X_prep)
        self.preprocessor_ = self._build_preprocessor()
        out = self.preprocessor_.fit_transform(X_prep)
        self.n_features_out_ = out.shape[1]
        log.info(
            "FeatureEngineeringPipeline fitted — %d numeric + %d categorical"
            " = %d output features",
            len(self.num_cols_), len(self.cat_cols_), self.n_features_out_,
        )
        return out.astype(np.float32)

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def feature_names_(self) -> list[str]:
        """
        Output feature names with the ``ColumnTransformer`` prefix stripped.

        ``ColumnTransformer.get_feature_names_out()`` returns names like
        ``"num__dur"`` and ``"cat__proto"``.  This property strips the
        ``"num__"`` / ``"cat__"`` prefix and returns plain column names.

        Returns
        -------
        list[str]
            Length equals ``n_features_out_``.  Numeric features come first
            (in the order of ``num_cols_``), then categorical features (in
            the order of ``cat_cols_``).

        Raises
        ------
        sklearn.exceptions.NotFittedError
            If called before ``fit()``.
        """
        check_is_fitted(self, "preprocessor_")
        raw = self.preprocessor_.get_feature_names_out()
        return [name.split("__", 1)[-1] for name in raw]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """
        Serialise the fitted pipeline to disk with joblib.

        Parameters
        ----------
        path : str | Path
            Destination file (``*.joblib``) or directory.  When a directory
            is given, the file is written as
            ``{path}/feature_pipeline.joblib``.

        Raises
        ------
        sklearn.exceptions.NotFittedError
            If called before ``fit()``.
        """
        check_is_fitted(self, "preprocessor_")
        path = Path(path)
        if not path.suffix:
            path.mkdir(parents=True, exist_ok=True)
            path = path / "feature_pipeline.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        log.info("FeatureEngineeringPipeline saved → %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "FeatureEngineeringPipeline":
        """
        Deserialise a pipeline previously saved with ``save()``.

        Parameters
        ----------
        path : str | Path
            Path to the ``.joblib`` file, or a directory containing
            ``feature_pipeline.joblib``.

        Returns
        -------
        FeatureEngineeringPipeline
            Fitted instance ready for ``transform()``.

        Raises
        ------
        TypeError
            If the loaded object is not a ``FeatureEngineeringPipeline``.
        """
        path = Path(path)
        if path.is_dir():
            path = path / "feature_pipeline.joblib"
        obj = joblib.load(path)
        if not isinstance(obj, cls):
            raise TypeError(
                f"Expected {cls.__name__}, got {type(obj).__name__}"
            )
        log.info("FeatureEngineeringPipeline loaded from %s", path)
        return obj

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _prepare(self, X: pd.DataFrame) -> pd.DataFrame:
        """
        Drop unwanted columns and add derived features.

        Called by both ``fit()`` and ``transform()``.  Never mutates *X*.

        Parameters
        ----------
        X : pd.DataFrame
            Raw input.

        Returns
        -------
        pd.DataFrame
            DataFrame with identifier / target columns removed and four
            derived feature columns appended.
        """
        X = X.copy()
        cols_to_drop = [c for c in DROP_COLS if c in X.columns]
        if cols_to_drop:
            X = X.drop(columns=cols_to_drop)
        X = _add_derived_features(X)
        return X

    def _init_column_lists(self, X_prep: pd.DataFrame) -> None:
        """
        Determine ``num_cols_`` and ``cat_cols_`` from a prepared DataFrame.

        Sets ``self.num_cols_`` and ``self.cat_cols_`` as instance attributes.
        Must be called **before** ``_build_preprocessor()``.

        Parameters
        ----------
        X_prep : pd.DataFrame
            Output of ``_prepare()`` — identifiers dropped, derived features
            added, target column absent.
        """
        self.cat_cols_: list[str] = [
            c for c in self.categorical_cols if c in X_prep.columns
        ]
        numeric_mask = X_prep.dtypes.map(
            lambda dt: np.issubdtype(dt, np.number)
        )
        self.num_cols_: list[str] = [
            c for c in X_prep.columns[numeric_mask]
            if c not in self.cat_cols_
        ]

    def _build_preprocessor(self) -> ColumnTransformer:
        """
        Construct a ``ColumnTransformer`` from the fitted column lists.

        Must be called after ``_init_column_lists()``.

        Pipeline for numeric columns:
            ``SimpleImputer(strategy="median")``
            → ``RobustScaler()``

        Pipeline for categorical columns:
            ``SimpleImputer(strategy="most_frequent")``
            → ``OrdinalEncoder(handle_unknown="use_encoded_value",
                               unknown_value=-1.0)``

        The ``remainder="drop"`` setting discards any column not explicitly
        listed (e.g. residual object columns that are neither in
        ``num_cols_`` nor ``cat_cols_``).

        Returns
        -------
        sklearn.compose.ColumnTransformer
            Un-fitted transformer.
        """
        num_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler",  RobustScaler()),
        ])
        cat_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OrdinalEncoder(
                handle_unknown="use_encoded_value",
                unknown_value=-1.0,
                dtype=np.float64,
            )),
        ])
        return ColumnTransformer(
            transformers=[
                ("num", num_pipeline, self.num_cols_),
                ("cat", cat_pipeline, self.cat_cols_),
            ],
            remainder="drop",
            verbose_feature_names_out=True,
        )

    @staticmethod
    def _validate_input(X: object) -> None:
        """
        Assert that *X* is a ``pd.DataFrame``.

        Parameters
        ----------
        X : object
            Value to validate.

        Raises
        ------
        TypeError
            If *X* is not a ``pd.DataFrame``.
        """
        if not isinstance(X, pd.DataFrame):
            raise TypeError(
                f"FeatureEngineeringPipeline expects a pd.DataFrame, "
                f"got {type(X).__name__}"
            )
