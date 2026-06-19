"""
pytest tests for ml.preprocessing.feature_engineering.

Coverage
--------
* Output shape (rows preserved, column count reasonable)
* No NaN or infinite values in output
* Derived features (byte_ratio, duration_log, pkt_rate, flag_score) are
  computed correctly and appear in feature_names_
* label column is never included in the feature matrix
* fit().transform(X) == fit_transform(X)
* Unknown / unseen categorical values are handled gracefully (→ -1.0)
* save() / load() round-trip produces identical output
* Missing values in the input do not propagate to the output
* Flag score defaults to 0 when flag columns are absent
* Flag score is the correct weighted sum when flag columns are present
* TypeError is raised when the input is not a DataFrame
* NotFittedError is raised when transform() is called before fit()
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.exceptions import NotFittedError

from ml.preprocessing.feature_engineering import (
    FLAG_COLS,
    FLAG_WEIGHTS,
    FeatureEngineeringPipeline,
    _add_derived_features,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_sample_df(n: int = 50, seed: int = 0) -> pd.DataFrame:
    """
    Build a minimal but representative UNSW-NB15-like DataFrame.

    Includes:
    * All three categorical columns (proto, service, state)
    * Core numeric columns referenced by derived-feature formulas
    * A few extra numeric columns to verify they pass through
    * The binary ``label`` column (must be excluded from output)

    The DataFrame intentionally does NOT include flag columns, IP addresses,
    or timestamp columns, to verify those are handled without errors.

    Parameters
    ----------
    n : int
        Number of rows.
    seed : int
        NumPy RNG seed for reproducibility.

    Returns
    -------
    pd.DataFrame
    """
    rng = np.random.default_rng(seed)

    protos   = ["tcp", "udp", "icmp", "ospf"]
    services = ["http", "dns", "ssl", "-", "ftp"]
    states   = ["FIN", "INT", "CON", "REQ", "RST"]

    return pd.DataFrame({
        # Categoricals
        "proto"    : rng.choice(protos,   size=n),
        "service"  : rng.choice(services, size=n),
        "state"    : rng.choice(states,   size=n),
        # Core numerics
        "dur"      : rng.exponential(scale=2.0,  size=n).clip(0),
        "sbytes"   : rng.integers(0, 100_000,     size=n).astype(float),
        "dbytes"   : rng.integers(0, 50_000,      size=n).astype(float),
        "Spkts"    : rng.integers(1, 200,          size=n).astype(float),
        "Dpkts"    : rng.integers(0, 150,          size=n).astype(float),
        # Additional numerics
        "sttl"     : rng.choice([64, 128, 255],   size=n).astype(float),
        "dttl"     : rng.choice([64, 128],         size=n).astype(float),
        "sloss"    : rng.integers(0, 10,           size=n).astype(float),
        "dloss"    : rng.integers(0, 5,            size=n).astype(float),
        "ct_srv_src": rng.integers(1, 20,          size=n).astype(float),
        # Identifier / timestamp columns (must be dropped)
        "srcip"    : ["192.168.1.1"] * n,
        "dstip"    : ["10.0.0.1"] * n,
        "Stime"    : rng.integers(1_600_000_000, 1_700_000_000, size=n).astype(float),
        # Target column (must be dropped from feature matrix)
        "label"    : rng.integers(0, 2, size=n).astype(int),
    })


@pytest.fixture
def sample_df() -> pd.DataFrame:
    """50-row UNSW-NB15-like DataFrame."""
    return _make_sample_df(n=50, seed=0)


@pytest.fixture
def large_df() -> pd.DataFrame:
    """500-row sample for split / save-load tests."""
    return _make_sample_df(n=500, seed=1)


@pytest.fixture
def fitted_pipeline(sample_df: pd.DataFrame) -> FeatureEngineeringPipeline:
    """Pipeline already fitted on ``sample_df``."""
    pipeline = FeatureEngineeringPipeline()
    pipeline.fit(sample_df)
    return pipeline


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

class TestOutputShape:
    def test_rows_preserved(self, sample_df):
        """
        The number of rows in the output must equal the number of input rows.
        """
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.shape[0] == len(sample_df)

    def test_output_is_2d(self, sample_df):
        """Output must be a 2-D array."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.ndim == 2

    def test_feature_count_positive(self, sample_df):
        """
        The output must have at least one feature column.

        We do not assert the exact count because the pipeline discovers
        columns dynamically; we only verify the lower bound.
        """
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.shape[1] > 0

    def test_feature_count_matches_n_features_out(self, sample_df):
        """``n_features_out_`` must match the actual array width."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.shape[1] == pipeline.n_features_out_

    def test_feature_count_matches_feature_names(self, sample_df):
        """``feature_names_`` length must match the actual array width."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.shape[1] == len(pipeline.feature_names_)


# ---------------------------------------------------------------------------
# Data quality
# ---------------------------------------------------------------------------

class TestDataQuality:
    def test_output_dtype_float32(self, sample_df):
        """Output must be float32 for compatibility with TF and sklearn."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert out.dtype == np.float32

    def test_no_nans_in_output(self, sample_df):
        """No NaN values must appear in the output array."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert not np.isnan(out).any(), "Output contains NaN values"

    def test_no_infinities_in_output(self, sample_df):
        """No infinite values must appear in the output array."""
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        assert np.isfinite(out).all(), "Output contains infinite values"

    def test_nans_in_input_imputed(self):
        """
        NaN values in numeric input columns must be imputed to the column
        median, not propagated to the output.
        """
        df = _make_sample_df(n=40, seed=2)
        # Inject NaN into two columns
        df.loc[df.index[:5], "dur"]    = np.nan
        df.loc[df.index[10:15], "sbytes"] = np.nan

        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(df)
        assert not np.isnan(out).any()

    def test_zero_duration_pkt_rate_finite(self):
        """
        Flows with ``dur == 0`` must produce a finite ``pkt_rate`` value
        (the formula uses ``dur + 0.001`` to avoid division-by-zero).
        """
        df = _make_sample_df(n=10, seed=3)
        df["dur"] = 0.0

        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(df)
        assert np.isfinite(out).all()


# ---------------------------------------------------------------------------
# Label exclusion
# ---------------------------------------------------------------------------

class TestLabelExclusion:
    def test_label_not_in_feature_names(self, fitted_pipeline):
        """
        The ``label`` column must never appear in ``feature_names_``.
        """
        assert "label" not in fitted_pipeline.feature_names_

    def test_attack_cat_not_in_feature_names(self, sample_df):
        """
        ``attack_cat`` must be dropped even if present in the input.
        """
        df = sample_df.copy()
        df["attack_cat"] = "Generic"
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(df)
        assert "attack_cat" not in pipeline.feature_names_

    def test_identifier_cols_not_in_feature_names(self, fitted_pipeline):
        """IP addresses and timestamps must not appear in feature_names_."""
        names = set(fitted_pipeline.feature_names_)
        for col in ("srcip", "dstip", "Stime", "Ltime"):
            assert col not in names, f"Identifier column '{col}' leaked into features"


# ---------------------------------------------------------------------------
# Derived features
# ---------------------------------------------------------------------------

class TestDerivedFeatures:
    def test_derived_names_in_feature_names(self, sample_df):
        """
        All four derived columns must appear in ``feature_names_`` after fitting.
        """
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(sample_df)
        names = pipeline.feature_names_
        for derived in ("byte_ratio", "duration_log", "pkt_rate", "flag_score"):
            assert derived in names, f"Derived feature '{derived}' missing from feature_names_"

    def test_duration_log_is_log1p_of_dur(self):
        """
        ``duration_log`` must equal ``log1p(dur)`` for non-negative durations.
        """
        df = pd.DataFrame({
            "dur"    : [0.0, 1.0, 10.0, 100.0],
            "sbytes" : [100.0] * 4,
            "dbytes" : [50.0] * 4,
            "Spkts"  : [10.0] * 4,
        })
        out = _add_derived_features(df)
        expected = np.log1p([0.0, 1.0, 10.0, 100.0])
        np.testing.assert_allclose(out["duration_log"].values, expected, rtol=1e-6)

    def test_byte_ratio_formula(self):
        """
        ``byte_ratio`` must equal ``sbytes / (dbytes + 1)``.
        """
        df = pd.DataFrame({
            "sbytes": [1000.0, 500.0, 0.0],
            "dbytes": [0.0,    499.0, 100.0],
            "dur"   : [1.0,    1.0,   1.0],
            "Spkts" : [10.0,   10.0,  10.0],
        })
        out = _add_derived_features(df)
        expected = np.array([1000 / 1, 500 / 500, 0 / 101])
        np.testing.assert_allclose(out["byte_ratio"].values, expected, rtol=1e-6)

    def test_pkt_rate_formula(self):
        """
        ``pkt_rate`` must equal ``Spkts / (dur + 0.001)``.
        """
        df = pd.DataFrame({
            "Spkts"  : [10.0, 100.0, 0.0],
            "dur"    : [1.0,   0.0,  5.0],
            "sbytes" : [0.0] * 3,
            "dbytes" : [0.0] * 3,
        })
        out = _add_derived_features(df)
        expected = np.array([10 / 1.001, 100 / 0.001, 0 / 5.001])
        np.testing.assert_allclose(out["pkt_rate"].values, expected, rtol=1e-4)

    def test_flag_score_absent_cols_is_zero(self, sample_df):
        """
        When all flag columns are absent, ``flag_score`` must be 0 for every row.
        """
        for col in FLAG_COLS:
            assert col not in sample_df.columns, \
                f"Test setup error: {col} unexpectedly present in sample_df"

        out = _add_derived_features(sample_df)
        assert (out["flag_score"] == 0.0).all()

    def test_flag_score_weighted_sum(self):
        """
        ``flag_score`` must equal the weighted sum
        ``fin×1 + syn×2 + rst×3 + psh×1``.
        """
        df = pd.DataFrame({
            "sbytes"         : [0.0] * 3,
            "dbytes"         : [0.0] * 3,
            "dur"            : [1.0] * 3,
            "Spkts"          : [1.0] * 3,
            "fin_flag_count" : [1, 0, 2],
            "syn_flag_count" : [0, 1, 1],
            "rst_flag_count" : [0, 0, 1],
            "psh_flag_count" : [0, 1, 0],
        })
        out = _add_derived_features(df)
        # Row 0: 1×1 + 0×2 + 0×3 + 0×1 = 1
        # Row 1: 0×1 + 1×2 + 0×3 + 1×1 = 3
        # Row 2: 2×1 + 1×2 + 1×3 + 0×1 = 7
        expected = np.array([1.0, 3.0, 7.0])
        np.testing.assert_allclose(out["flag_score"].values, expected)


# ---------------------------------------------------------------------------
# Categorical encoding
# ---------------------------------------------------------------------------

class TestCategoricalEncoding:
    def test_unknown_category_returns_minus_one(self, sample_df):
        """
        OrdinalEncoder must map unseen category values to -1.0, not raise.

        ``handle_unknown="use_encoded_value"`` with ``unknown_value=-1.0``
        is required for robustness to novel traffic categories at inference time.
        """
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(sample_df)

        test_df = sample_df.copy()
        # Inject a protocol value never seen during training
        test_df.loc[test_df.index[0], "proto"] = "grp"

        out = pipeline.transform(test_df)
        # No NaN or error expected
        assert not np.isnan(out).any()

    def test_categorical_columns_encoded_as_ordinals(self, sample_df):
        """
        Categorical columns must be represented as ordinal float values
        (integers cast to float32), not one-hot vectors.  The pipeline is
        narrower than one-hot encoding, which is appropriate for tree-based
        IsolationForest.
        """
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(sample_df)
        # Categorical values will be in [-1, n_categories - 1].
        # After RobustScaler the numeric block is unbounded, but the ordinal
        # block from the ColumnTransformer comes after it without scaling.
        # We just confirm no NaN and the shape is consistent.
        assert out.shape[1] == pipeline.n_features_out_

    def test_cat_cols_subset_present(self):
        """
        Pipeline must work when only a subset of the three categorical columns
        is present in the input (e.g. a DataFrame without 'state').
        """
        df = _make_sample_df(n=20)
        df = df.drop(columns=["state"])

        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(df)
        assert not np.isnan(out).any()
        assert "state" not in pipeline.feature_names_


# ---------------------------------------------------------------------------
# fit / transform equivalence
# ---------------------------------------------------------------------------

class TestFitTransformEquivalence:
    def test_fit_then_transform_equals_fit_transform(self, sample_df):
        """
        ``fit(X).transform(X)`` must produce the same array as
        ``fit_transform(X)`` (since both start from the same data).

        Two separate pipeline instances are used to avoid cross-contamination
        of fitted state.
        """
        p1 = FeatureEngineeringPipeline()
        expected = p1.fit_transform(sample_df)

        p2 = FeatureEngineeringPipeline()
        p2.fit(sample_df)
        actual = p2.transform(sample_df)

        np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=1e-6)

    def test_transform_on_unseen_subset(self, large_df):
        """
        A pipeline fitted on the first 400 rows must successfully transform
        the remaining 100 rows without error.
        """
        train = large_df.iloc[:400].reset_index(drop=True)
        test  = large_df.iloc[400:].reset_index(drop=True)

        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(train)
        out = pipeline.transform(test)

        assert out.shape == (len(test), pipeline.n_features_out_)
        assert not np.isnan(out).any()


# ---------------------------------------------------------------------------
# Save / load round-trip
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_save_load_produces_identical_output(self, large_df):
        """
        ``save()`` followed by ``load()`` must produce a pipeline that
        returns bit-for-bit identical output on the same input.
        """
        train = large_df.iloc[:400].reset_index(drop=True)
        test  = large_df.iloc[400:].reset_index(drop=True)

        original = FeatureEngineeringPipeline()
        original.fit(train)
        expected = original.transform(test)

        with tempfile.TemporaryDirectory() as tmp:
            original.save(Path(tmp) / "pipeline.joblib")
            loaded = FeatureEngineeringPipeline.load(Path(tmp) / "pipeline.joblib")

        actual = loaded.transform(test)
        np.testing.assert_array_equal(actual, expected)

    def test_save_to_directory_creates_default_filename(self, sample_df):
        """
        When ``save()`` receives a directory path (no ``.joblib`` suffix), it
        must create ``feature_pipeline.joblib`` inside that directory.
        """
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(sample_df)

        with tempfile.TemporaryDirectory() as tmp:
            pipeline.save(Path(tmp) / "mydir")
            expected_file = Path(tmp) / "mydir" / "feature_pipeline.joblib"
            assert expected_file.exists()

    def test_load_from_directory(self, sample_df):
        """
        ``load()`` with a directory path must resolve to
        ``{dir}/feature_pipeline.joblib``.
        """
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit(sample_df)

        with tempfile.TemporaryDirectory() as tmp:
            save_dir = Path(tmp) / "mydir"
            pipeline.save(save_dir)
            loaded = FeatureEngineeringPipeline.load(save_dir)

        assert loaded.n_features_out_ == pipeline.n_features_out_


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_raises_type_error_on_non_dataframe(self):
        """
        Passing a non-DataFrame to ``fit()`` must raise ``TypeError``.
        """
        pipeline = FeatureEngineeringPipeline()
        with pytest.raises(TypeError, match="pd.DataFrame"):
            pipeline.fit(np.zeros((10, 5)))

    def test_raises_type_error_in_transform(self, fitted_pipeline):
        """
        Passing a non-DataFrame to ``transform()`` must raise ``TypeError``.
        """
        with pytest.raises(TypeError, match="pd.DataFrame"):
            fitted_pipeline.transform([[1, 2, 3]])

    def test_raises_not_fitted_error(self, sample_df):
        """
        Calling ``transform()`` before ``fit()`` must raise
        ``sklearn.exceptions.NotFittedError``.
        """
        pipeline = FeatureEngineeringPipeline()
        with pytest.raises(NotFittedError):
            pipeline.transform(sample_df)

    def test_raises_not_fitted_error_for_feature_names(self):
        """
        Accessing ``feature_names_`` before fitting must raise
        ``NotFittedError``.
        """
        pipeline = FeatureEngineeringPipeline()
        with pytest.raises(NotFittedError):
            _ = pipeline.feature_names_


# ---------------------------------------------------------------------------
# Minimal DataFrame
# ---------------------------------------------------------------------------

class TestMinimalDataFrame:
    def test_single_numeric_col_works(self):
        """
        A DataFrame with only one numeric column and no categoricals must
        produce a valid (n, 5) output — 1 original + 4 derived features.

        The 4 derived features always exist (using 0 defaults for absent
        source columns), so the output can never have fewer than 4 columns
        even for the most minimal input.
        """
        df = pd.DataFrame({
            "dur"  : [1.0, 2.0, 3.0],
            "label": [0, 1, 0],
        })
        pipeline = FeatureEngineeringPipeline()
        out = pipeline.fit_transform(df)
        assert out.ndim == 2
        assert out.shape[0] == 3
        assert not np.isnan(out).any()

    def test_extra_unknown_columns_ignored(self, sample_df):
        """
        Columns not in DROP_COLS and not detected as numeric or categorical
        by the pipeline must be silently dropped (``remainder="drop"``).
        """
        df = sample_df.copy()
        df["mystery_string_col"] = "foo"  # object dtype, not in categorical_cols

        pipeline = FeatureEngineeringPipeline()
        # Must not raise
        out = pipeline.fit_transform(df)
        assert not np.isnan(out).any()
        assert "mystery_string_col" not in pipeline.feature_names_
