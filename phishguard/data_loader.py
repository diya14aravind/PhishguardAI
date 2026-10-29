"""Loads the training CSV files from data/ and maps every row to ham, spam or phishing.

Put your datasets in the data/ folder (any .csv). The loader guesses the text and
label columns. File names decide how a numeric label of 1 is read:
  name contains 'phish'                 -> 1 means phishing
  name contains 'enron', 'sms', 'spam'  -> 1 means spam
"""

import pandas as pd

from phishguard.config import DATA_DIR

TEXT_COLUMNS = ["email text", "text", "body", "message", "content", "email", "v2", "text_combined"]
LABEL_COLUMNS = ["email type", "label", "class", "category", "spam", "v1", "target", "type"]


def _find_column(columns, candidates):
    lowered = {str(c).strip().lower(): c for c in columns}
    for candidate in candidates:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _map_label(value, file_name):
    text = str(value).strip().lower()
    if "phish" in text:
        return "phishing"
    if "spam" in text:
        return "spam"
    if text in ("ham", "safe email", "safe", "legitimate", "legit", "not spam", "normal"):
        return "ham"
    if text in ("1", "1.0", "true"):
        if "phish" in file_name:
            return "phishing"
        return "spam"
    if text in ("0", "0.0", "false"):
        return "ham"
    return None


def load_file(path):
    file_name = path.name.lower()
    frame = pd.read_csv(path, encoding="utf-8", encoding_errors="replace", on_bad_lines="skip")
    text_column = _find_column(frame.columns, TEXT_COLUMNS)
    label_column = _find_column(frame.columns, LABEL_COLUMNS)
    if text_column is None or label_column is None:
        print("  skipped " + path.name + ": could not find text and label columns in " + str(list(frame.columns)))
        return None

    rows = pd.DataFrame({
        "text": frame[text_column].astype(str),
        "label": [_map_label(v, file_name) for v in frame[label_column]],
        "source": path.stem,
    })
    rows = rows.dropna(subset=["label"])
    rows = rows[rows["text"].str.strip().str.len() > 5]
    print("  " + path.name + ": " + str(len(rows)) + " rows " + str(rows["label"].value_counts().to_dict()))
    return rows


def load_all():
    files = sorted(DATA_DIR.glob("*.csv"))
    if not files:
        raise SystemExit("No CSV files found in " + str(DATA_DIR) + ". Copy your datasets there first.")
    frames = []
    print("Loading datasets from " + str(DATA_DIR))
    for path in files:
        loaded = load_file(path)
        if loaded is not None:
            frames.append(loaded)
    if not frames:
        raise SystemExit("No usable dataset files found.")
    data = pd.concat(frames, ignore_index=True)
    data = data.drop_duplicates(subset=["text"])
    print("Total after removing duplicates: " + str(len(data)) + " " + str(data["label"].value_counts().to_dict()))
    return data
