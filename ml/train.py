"""Fine-tune CodeBERT (microsoft/codebert-base) as a 7-class SQLi function classifier.

Typical runs
  # Apple Silicon (8 GB): shorter sequences + gradient accumulation
  python ml/train.py --max-length 256 --batch-size 8 --grad-accum 4 --epochs 4

  # CUDA GPU (Colab T4)
  python ml/train.py --max-length 512 --batch-size 16 --epochs 4 --fp16

  # Pipeline smoke test with a tiny random model (minutes, no real learning)
  python ml/train.py --model-name hf-internal-testing/tiny-random-RobertaForSequenceClassification \
      --max-train-samples 200 --epochs 1 --output-dir ml/runs/smoke-model

Generalization / overfitting controls (see PLAN.md §Phase 4):
  --augment-prob     identifier-rename augmentation, re-sampled every epoch
  --dropout          hidden + attention dropout
  --label-smoothing  softens targets (synthetic data is very clean)
  --freeze-layers N  freeze embeddings + lower N encoder layers for the first epoch
  early stopping on validation macro-F1, template-grouped splits (ml/data/build_dataset.py)

After training the best checkpoint is calibrated with temperature scaling on the
validation set and exported to --output-dir with sidecar files the backend reads.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import time
from pathlib import Path

import numpy as np
import torch
from augment import rename_identifiers
from common import DEFAULT_MODEL_DIR, ID2LABEL, LABEL2ID, LABELS, ML_DIR, PROCESSED_DIR, read_jsonl
from metrics import classification_report_dict, expected_calibration_error
from torch import nn
from torch.utils.data import Dataset
from transformers import (
    AutoConfig,
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    EarlyStoppingCallback,
    Trainer,
    TrainerCallback,
    TrainingArguments,
    set_seed,
)


class CodeDataset(Dataset):
    def __init__(self, rows: list[dict], tokenizer, max_length: int, augment_prob: float = 0.0, seed: int = 0):
        self.rows = rows
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.augment_prob = augment_prob
        self.rng = random.Random(seed)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict:
        row = self.rows[idx]
        code = row["code"]
        if self.augment_prob and self.rng.random() < self.augment_prob:
            try:
                code = rename_identifiers(code, self.rng, wrap_class=row.get("unit_kind") == "method")
            except Exception:  # noqa: BLE001 - augmentation must never break training
                pass
        enc = self.tokenizer(code, truncation=True, max_length=self.max_length)
        enc["labels"] = LABEL2ID[row["label"]]
        return enc


class WeightedTrainer(Trainer):
    def __init__(self, *args, class_weights: torch.Tensor | None = None, label_smoothing: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.class_weights = class_weights
        self.label_smoothing = label_smoothing

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        weight = self.class_weights.to(outputs.logits.device) if self.class_weights is not None else None
        loss = nn.functional.cross_entropy(
            outputs.logits, labels, weight=weight, label_smoothing=self.label_smoothing
        )
        return (loss, outputs) if return_outputs else loss


class UnfreezeCallback(TrainerCallback):
    """Freeze lower layers for the first epoch, then train everything."""

    def __init__(self, model, n_layers: int):
        self.model = model
        self.frozen = self._lower_params(model, n_layers)
        for p in self.frozen:
            p.requires_grad = False

    @staticmethod
    def _lower_params(model, n_layers):
        base = getattr(model, model.base_model_prefix, model)
        params = list(base.embeddings.parameters())
        for layer in base.encoder.layer[:n_layers]:
            params.extend(layer.parameters())
        return params

    def on_epoch_end(self, args, state, control, **kwargs):
        if self.frozen:
            for p in self.frozen:
                p.requires_grad = True
            self.frozen = []
            print("[unfreeze] all encoder layers trainable from now on")


def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    report = classification_report_dict(labels, preds)
    return {"accuracy": report["accuracy"], "macro_f1": report["macro_f1"], "binary_f1": report["binary"]["f1"]}


def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
    """Temperature scaling (Guo et al., 2017) on held-out validation logits."""
    logits_t = torch.tensor(logits, dtype=torch.float32)
    labels_t = torch.tensor(labels, dtype=torch.long)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.05, max_iter=200)

    def closure():
        opt.zero_grad()
        loss = nn.functional.cross_entropy(logits_t / log_t.exp(), labels_t)
        loss.backward()
        return loss

    opt.step(closure)
    return float(log_t.detach().exp().clamp(0.05, 20.0))


def softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max(axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)


def evaluate_split(trainer: Trainer, rows: list[dict], tokenizer, max_length: int, temperature: float) -> dict:
    ds = CodeDataset(rows, tokenizer, max_length)
    out = trainer.predict(ds)
    probs = softmax(out.predictions / temperature)
    labels = out.label_ids
    report = classification_report_dict(labels, probs.argmax(-1), probs=probs)
    report["ece"] = expected_calibration_error(probs, labels)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=Path, default=PROCESSED_DIR)
    parser.add_argument("--model-name", default="microsoft/codebert-base")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--run-dir", type=Path, default=ML_DIR / "runs" / time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--stride", type=int, default=128, help="sliding-window stride used at inference")
    parser.add_argument("--epochs", type=float, default=4)
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--grad-accum", type=int, default=1)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--warmup-ratio", type=float, default=0.1)
    parser.add_argument("--dropout", type=float, default=0.1)
    parser.add_argument("--label-smoothing", type=float, default=0.0)
    parser.add_argument("--augment-prob", type=float, default=0.5)
    parser.add_argument("--freeze-layers", type=int, default=0)
    parser.add_argument("--class-weights", action="store_true", help="inverse-frequency class weights")
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--max-train-samples", type=int, default=None)
    parser.add_argument("--max-eval-samples", type=int, default=None)
    parser.add_argument("--fp16", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    set_seed(args.seed)
    train_rows = read_jsonl(args.data_dir / "train.jsonl")
    val_rows = read_jsonl(args.data_dir / "val.jsonl")
    test_rows = read_jsonl(args.data_dir / "test.jsonl")
    heldout_path = args.data_dir / "heldout.jsonl"
    heldout_rows = read_jsonl(heldout_path) if heldout_path.exists() else []
    rng = random.Random(args.seed)
    if args.max_train_samples:
        train_rows = rng.sample(train_rows, min(args.max_train_samples, len(train_rows)))
    if args.max_eval_samples:
        val_rows, test_rows, heldout_rows = (
            rng.sample(r, min(args.max_eval_samples, len(r))) for r in (val_rows, test_rows, heldout_rows)
        )
    print(f"train={len(train_rows)} val={len(val_rows)} test={len(test_rows)} heldout={len(heldout_rows)}")

    tokenizer = AutoTokenizer.from_pretrained(args.model_name)
    config = AutoConfig.from_pretrained(
        args.model_name,
        num_labels=len(LABELS),
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        hidden_dropout_prob=args.dropout,
        attention_probs_dropout_prob=args.dropout,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, config=config, ignore_mismatched_sizes=True
    )

    class_weights = None
    if args.class_weights:
        counts = np.bincount([LABEL2ID[r["label"]] for r in train_rows], minlength=len(LABELS)).astype(float)
        weights = counts.sum() / (len(LABELS) * np.maximum(counts, 1))
        class_weights = torch.tensor(weights, dtype=torch.float32)
        print("class weights:", dict(zip(LABELS, np.round(weights, 3), strict=True)))

    train_ds = CodeDataset(train_rows, tokenizer, args.max_length, args.augment_prob, args.seed)
    val_ds = CodeDataset(val_rows, tokenizer, args.max_length)

    steps_per_epoch = math.ceil(len(train_rows) / (args.batch_size * args.grad_accum))
    warmup_steps = int(steps_per_epoch * args.epochs * args.warmup_ratio)
    training_args = TrainingArguments(
        output_dir=str(args.run_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size * 2,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.lr,
        weight_decay=args.weight_decay,
        warmup_steps=warmup_steps,
        eval_strategy="epoch",
        save_strategy="epoch",
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_steps=25,
        fp16=args.fp16 and torch.cuda.is_available(),
        dataloader_num_workers=0,
        dataloader_pin_memory=False,
        report_to="none",
        seed=args.seed,
    )
    callbacks = [EarlyStoppingCallback(early_stopping_patience=args.patience)]
    if args.freeze_layers:
        callbacks.append(UnfreezeCallback(model, args.freeze_layers))

    trainer = WeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
        callbacks=callbacks,
        class_weights=class_weights,
        label_smoothing=args.label_smoothing,
    )
    started = time.time()
    trainer.train()
    train_minutes = (time.time() - started) / 60

    # ---- calibration on validation set
    val_out = trainer.predict(val_ds)
    temperature = fit_temperature(val_out.predictions, val_out.label_ids)
    print(f"temperature = {temperature:.3f}")

    metrics = {
        "model_name": args.model_name,
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "train_minutes": round(train_minutes, 1),
        "train_samples": len(train_rows),
        "hyperparameters": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
        "temperature": temperature,
        "val": evaluate_split(trainer, val_rows, tokenizer, args.max_length, temperature),
        "test": evaluate_split(trainer, test_rows, tokenizer, args.max_length, temperature),
    }
    if heldout_rows:
        metrics["heldout"] = evaluate_split(trainer, heldout_rows, tokenizer, args.max_length, temperature)

    # ---- export
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))
    (out / "temperature.json").write_text(json.dumps({"temperature": temperature}, indent=2))
    (out / "inference_config.json").write_text(
        json.dumps({"max_length": args.max_length, "stride": args.stride}, indent=2)
    )
    (out / "label_map.json").write_text(json.dumps({"id2label": ID2LABEL, "label2id": LABEL2ID}, indent=2))
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))

    print("\n=== summary ===")
    for split in ("val", "test", "heldout"):
        if split in metrics:
            m = metrics[split]
            print(f"{split:<8} acc={m['accuracy']:.4f} macro_f1={m['macro_f1']:.4f} "
                  f"binary_f1={m['binary']['f1']:.4f} ece={m['ece']:.4f}")
    gap = metrics["test"]["macro_f1"] - metrics.get("heldout", metrics["test"])["macro_f1"]
    print(f"generalization gap (test - heldout macro F1): {gap:.4f}")
    print(f"model exported to {out}")


if __name__ == "__main__":
    main()
