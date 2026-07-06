#!/usr/bin/env python3
"""Train a mechanism-family detector on the public NullRabbit bundle corpus.

A worked, self-contained example of *using Bundle v1 data for training* — the
end-to-end path a researcher takes with the public `NullRabbit/nr-bundles-public`
dataset:

    download bundles  ->  read manifest + Parquet modalities  ->  featurise
                      ->  train a classifier over the family taxonomy
                      ->  evaluate honestly (in-distribution AND cross-chain)

The point of the example is not the model (a stock gradient-boosted tree); it is
that the **shared, chain-agnostic format + taxonomy make a cross-chain question
testable**: hold out an entire chain and measure whether a detector trained on the
others recovers the *mechanism family* of that chain's attacks. That leave-one-
chain-out (LOCO) number is the honest one, and it is the metric NullRabbit uses to
decide how far a detector's autonomy is *earned* (see docs/methodology.md and the
`EARNED AUTONOMY` note printed at the end).

Dependencies (all public): huggingface_hub, pandas, pyarrow, numpy, scikit-learn.
Optionally `bundle-spec` (this repo) to Pydantic-validate each manifest.

    python examples/train_a_family_detector.py            # downloads + trains
    python examples/train_a_family_detector.py --root DIR # use a local bundle dir
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold

DATASET = "NullRabbit/nr-bundles-public"


# --------------------------------------------------------------------------- #
# 1. Featurise one bundle.
#
# A bundle is a directory: manifest.json + up to five Parquet modalities keyed on
# a monotonic `t_ns`. We read the two modalities that carry the load-bearing DoS
# signal — host telemetry and per-request response semantics — and reduce each to
# a handful of aggregates. NaNs are fine: the model below is NaN-native, so a
# bundle that simply did not capture a modality contributes NaN, not a fake zero.
# --------------------------------------------------------------------------- #
def _agg(df: pd.DataFrame, col: str) -> dict:
    if col not in df or df[col].dropna().empty:
        return {}
    s = pd.to_numeric(df[col], errors="coerce").dropna()
    out = {f"{col}.mean": s.mean(), f"{col}.max": s.max(), f"{col}.last": s.iloc[-1]}
    if len(s) > 1:  # linear trend over the capture window — memory growth, fd leak, ...
        out[f"{col}.slope"] = np.polyfit(np.arange(len(s)), s.values, 1)[0]
    return out


def featurise_bundle(bundle: Path) -> dict:
    feats: dict = {}
    host_p = bundle / "host.parquet"
    if host_p.exists():
        host = pd.read_parquet(host_p)
        for col in ("cpu_pct", "rss_bytes", "num_fds", "num_connections",
                    "num_threads", "io_read_bytes", "io_write_bytes"):
            feats.update(_agg(host, col))
    resp_p = bundle / "responses.parquet"
    if resp_p.exists():
        r = pd.read_parquet(resp_p)
        if len(r):
            req = pd.to_numeric(r.get("request_size_bytes"), errors="coerce")
            rsp = pd.to_numeric(r.get("response_size_bytes"), errors="coerce")
            dur = pd.to_numeric(r.get("duration_ns"), errors="coerce")
            feats["resp.count"] = float(len(r))
            feats["resp.resp_bytes.mean"] = rsp.mean()
            feats["resp.resp_bytes.max"] = rsp.max()
            feats["resp.req_bytes.mean"] = req.mean()
            # amplification: the defining signal of the response_amp family
            amp = (rsp / req.replace(0, np.nan))
            feats["resp.amp.mean"] = amp.mean()
            feats["resp.amp.max"] = amp.max()
            feats["resp.duration_ns.mean"] = dur.mean()
            feats["resp.distinct_endpoints"] = float(r.get("endpoint").nunique())
    return feats


# --------------------------------------------------------------------------- #
# 2. Load the whole corpus into a feature table keyed by (family, chain).
# --------------------------------------------------------------------------- #
def load_corpus(root: Path) -> pd.DataFrame:
    rows = []
    for man in sorted(root.glob("crp_*/manifest.json")):
        m = json.loads(man.read_text())
        row = featurise_bundle(man.parent)
        row["family"] = m.get("family_id")
        row["chain"] = "solana" if m.get("chain") == "solana-agave" else m.get("chain")
        row["label"] = m.get("ground_truth_label") or m.get("label")
        rows.append(row)
    df = pd.DataFrame(rows)
    print(f"loaded {len(df)} bundles | {df['chain'].nunique()} chains | "
          f"{df['family'].nunique()} families")
    return df


# --------------------------------------------------------------------------- #
# 3. Train + evaluate. Two numbers, named separately so neither is oversold.
# --------------------------------------------------------------------------- #
def _fit(Xtr, ytr):
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.06,
                                         min_samples_leaf=5, random_state=42)
    clf.fit(Xtr, ytr)
    return clf


def train_and_eval(df: pd.DataFrame) -> None:
    feat_cols = [c for c in df.columns if c not in ("family", "chain", "label")]
    X = df[feat_cols].to_numpy(dtype=float)
    y = df["family"].to_numpy()
    chains = df["chain"].to_numpy()

    # (a) IN-DISTRIBUTION: 5-fold stratified CV over families. Leakage-adjacent
    #     (near-duplicate bundles of one primitive can straddle the split) — the
    #     easy number, reported for continuity, NOT the headline.
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    f1s = []
    for tr, te in skf.split(X, y):
        clf = _fit(X[tr], y[tr])
        f1s.append(f1_score(y[te], clf.predict(X[te]), average="macro"))
    print(f"\n[in-distribution] 5-fold CV family macro-F1: {np.mean(f1s):.3f}")

    # (b) CROSS-CHAIN (the honest one): leave one chain out, train on the rest,
    #     recover the held-out chain's families zero-shot. This is the question
    #     the shared format lets you *pose* — and on this corpus it does NOT yet
    #     transfer for protocol-distinct chains. That gap is the point.
    print("[cross-chain] leave-one-chain-out family macro-F1 (shared families only):")
    loco = {}
    for ch in sorted(set(chains)):
        tr, te = chains != ch, chains == ch
        shared = set(y[tr]) & set(y[te])
        mask_te = te & np.isin(y, list(shared))
        if te.sum() < 3 or len(shared) < 2 or mask_te.sum() < 3:
            print(f"  {ch:<14} n/a (too few shared families to pose the question)")
            continue
        clf = _fit(X[tr], y[tr])
        f1 = f1_score(y[mask_te], clf.predict(X[mask_te]), average="macro")
        loco[ch] = f1
        print(f"  {ch:<14} {f1:.3f}   (n={int(mask_te.sum())}, {len(shared)} shared families)")

    print(
        "\nEARNED AUTONOMY — how to read these two numbers:\n"
        "  The in-distribution number says the detector separates families it has\n"
        "  seen on a chain. The cross-chain number says whether that generalises to\n"
        "  a chain it has NEVER trained on. Autonomy is 'earned' only where the\n"
        "  cross-chain number holds up: high LOCO = the mechanism signal transfers\n"
        "  (deploy with confidence on a new chain); near-floor LOCO = it does not,\n"
        "  and the honest move is to gate the detector to chains you have data for.\n"
        "  The corpus exists to let you measure that line rather than assume it."
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=None,
                    help="local dir of crp_*/ bundles; if omitted, download from HF")
    ap.add_argument("--limit", type=int, default=None, help="cap #bundles (quick runs)")
    args = ap.parse_args()

    root = args.root
    if root is None:
        from huggingface_hub import snapshot_download
        root = Path(snapshot_download(
            DATASET, repo_type="dataset",
            allow_patterns=["*/*.parquet", "*/manifest.json"]))
    df = load_corpus(root)
    if args.limit:
        df = df.groupby("family", group_keys=False).head(max(1, args.limit // df["family"].nunique()))
    train_and_eval(df)


if __name__ == "__main__":
    main()
