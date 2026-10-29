"""Metric helpers shared by train.py and evaluate.py (numpy + scikit-learn only)."""

from __future__ import annotations

import numpy as np
from common import LABELS
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score

SAFE_ID = LABELS.index("SAFE")


def classification_report_dict(labels, preds, probs: np.ndarray | None = None) -> dict:
    labels = np.asarray(labels)
    preds = np.asarray(preds)
    ids = list(range(len(LABELS)))
    p, r, f, s = precision_recall_fscore_support(labels, preds, labels=ids, zero_division=0)
    present = [i for i in ids if s[i] > 0]
    per_class = {
        LABELS[i]: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4), "f1": round(float(f[i]), 4),
                    "support": int(s[i])}
        for i in ids
    }
    gold_vuln = labels != SAFE_ID
    pred_vuln = preds != SAFE_ID
    tp = int(np.sum(gold_vuln & pred_vuln))
    fp = int(np.sum(~gold_vuln & pred_vuln))
    fn = int(np.sum(gold_vuln & ~pred_vuln))
    bp = tp / (tp + fp) if tp + fp else 0.0
    br = tp / (tp + fn) if tp + fn else 0.0
    binary = {
        "precision": round(bp, 4),
        "recall": round(br, 4),
        "f1": round(2 * bp * br / (bp + br), 4) if bp + br else 0.0,
        "false_positives": fp,
        "false_negatives": fn,
    }
    if probs is not None and len(set(gold_vuln.tolist())) == 2:
        binary["roc_auc"] = round(float(roc_auc_score(gold_vuln, 1 - probs[:, SAFE_ID])), 4)
    return {
        "n": int(len(labels)),
        "accuracy": round(float(np.mean(labels == preds)), 4) if len(labels) else 0.0,
        "macro_f1": round(float(np.mean([f[i] for i in present])), 4) if present else 0.0,
        "per_class": per_class,
        "binary": binary,
        "confusion_matrix": confusion_matrix(labels, preds, labels=ids).tolist(),
    }


def expected_calibration_error(probs: np.ndarray, labels, n_bins: int = 15) -> float:
    labels = np.asarray(labels)
    conf = probs.max(axis=1)
    correct = probs.argmax(axis=1) == labels
    bins = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    for lo, hi in zip(bins[:-1], bins[1:], strict=True):
        mask = (conf > lo) & (conf <= hi)
        if mask.any():
            ece += mask.mean() * abs(correct[mask].mean() - conf[mask].mean())
    return round(float(ece), 4)
