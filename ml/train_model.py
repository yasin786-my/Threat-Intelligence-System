"""Train a CIC-IDS2017 Random Forest model from one or more flow CSV files.

Example: python ml/train_model.py dataset --max-rows-per-file 50000
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def csv_files(inputs: list[str]) -> list[Path]:
    """Resolve CSV paths, directories, and glob patterns without duplicates."""
    files: set[Path] = set()
    for value in inputs:
        path = Path(value)
        if path.is_dir():
            files.update(path.rglob("*.csv"))
        elif path.is_file() and path.suffix.lower() == ".csv":
            files.add(path)
        else:
            files.update(Path().glob(value))
    return sorted(files)


def read_flows(path: Path, max_rows: int | None) -> pd.DataFrame:
    """Load and normalize a CIC CSV; optional sampling avoids memory exhaustion."""
    frame = pd.read_csv(path, low_memory=False)
    frame.columns = [column.strip() for column in frame.columns]
    label_column = next((column for column in frame.columns if column.lower() == "label"), None)
    if label_column is None:
        raise ValueError(f"{path.name} has no Label column")
    if max_rows and len(frame) > max_rows:
        frame = frame.sample(n=max_rows, random_state=42)
    frame = frame.rename(columns={label_column: "Label"})
    frame["Label"] = frame["Label"].astype(str).str.strip()
    return frame


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a CIC-IDS2017 classifier from CSV files.")
    parser.add_argument("inputs", nargs="+", help="CSV files, glob patterns, or folders containing CSV files")
    parser.add_argument("--out", default="backend/models/cic_ids_rf.joblib", help="Output model path")
    parser.add_argument("--max-rows-per-file", type=int, default=50000, help="Rows sampled from each CSV (0 uses all rows)")
    parser.add_argument("--trees", type=int, default=150, help="Number of Random Forest trees")
    args = parser.parse_args()

    files = csv_files(args.inputs)
    if not files:
        raise SystemExit("No CSV files found. Check the dataset path.")
    print(f"Loading {len(files)} CSV file(s)…")
    frames: list[pd.DataFrame] = []
    for path in files:
        try:
            frame = read_flows(path, args.max_rows_per_file or None)
            frames.append(frame)
            print(f"  ✓ {path.name}: {len(frame):,} rows")
        except (ValueError, pd.errors.ParserError, UnicodeDecodeError) as error:
            print(f"  ! Skipped {path.name}: {error}")
    if not frames:
        raise SystemExit("No valid CIC CSV files were loaded.")

    dataset = pd.concat(frames, ignore_index=True, sort=False)
    # CIC export files occasionally differ slightly; use the complete numeric union and zero-fill gaps.
    features = dataset.drop(columns=["Label"]).select_dtypes(include="number").replace([float("inf"), float("-inf")], 0).fillna(0)
    if features.empty:
        raise SystemExit("No numeric flow features found in the CSV files.")
    labels = dataset["Label"].replace({"BENIGN": "Normal", "Benign": "Normal"})
    encoder = LabelEncoder()
    target = encoder.fit_transform(labels)
    x_train, x_test, y_train, y_test = train_test_split(features, target, test_size=0.2, random_state=42, stratify=target)
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, class_weight="balanced", random_state=42)
    print(f"Training on {len(x_train):,} flows and validating on {len(x_test):,} flows…")
    model.fit(x_train, y_train)
    predicted = model.predict(x_test)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, predicted, average="weighted", zero_division=0)
    metrics = {"accuracy": round(accuracy_score(y_test, predicted), 4), "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4), "samples": len(dataset), "files": [str(path) for path in files]}
    print(json.dumps(metrics, indent=2))
    # Include every known label even when a rare class is absent from this sampled test split.
    print(classification_report(
        y_test,
        predicted,
        labels=list(range(len(encoder.classes_))),
        target_names=encoder.classes_,
        zero_division=0,
    ))
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": list(features.columns), "classes": list(encoder.classes_), "metrics": metrics}, output)
    output.with_suffix(".metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Model saved to {output}")


if __name__ == "__main__":
    main()
