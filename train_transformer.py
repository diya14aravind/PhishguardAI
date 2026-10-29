"""Optional upgrade: fine-tune DistilBERT on the same datasets.

Install first:  pip install torch transformers datasets accelerate
Run:            /opt/homebrew/bin/python3.11 train_transformer.py
After training, models/transformer/ is used automatically by the Content Agent.
Use --model roberta-base to try RoBERTa instead (slower).
"""

import argparse

import numpy as np
from datasets import Dataset
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split
from transformers import (AutoModelForSequenceClassification, AutoTokenizer, Trainer,
                          TrainingArguments)

from phishguard.config import TRANSFORMER_DIR
from phishguard.data_loader import load_all
from phishguard.text_utils import clean_text

LABELS = ["ham", "phishing", "spam"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="distilbert-base-uncased")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--max-rows", type=int, default=12000, help="cap rows to keep training time reasonable")
    args = parser.parse_args()

    data = load_all()
    if len(data) > args.max_rows:
        data = data.sample(args.max_rows, random_state=42)

    label_to_id = {label: index for index, label in enumerate(LABELS)}
    texts = [clean_text(t) for t in data["text"]]
    ids = [label_to_id[label] for label in data["label"]]
    x_train, x_test, y_train, y_test = train_test_split(texts, ids, test_size=0.2, random_state=42, stratify=ids)

    tokenizer = AutoTokenizer.from_pretrained(args.model)

    def tokenize(batch):
        return tokenizer(batch["text"], truncation=True, max_length=256)

    train_set = Dataset.from_dict({"text": x_train, "label": y_train}).map(tokenize, batched=True)
    test_set = Dataset.from_dict({"text": x_test, "label": y_test}).map(tokenize, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model, num_labels=len(LABELS),
        id2label={i: label for label, i in label_to_id.items()}, label2id=label_to_id)

    def metrics(prediction):
        predicted = np.argmax(prediction.predictions, axis=1)
        return {"macro_f1": f1_score(prediction.label_ids, predicted, average="macro")}

    arguments = TrainingArguments(
        output_dir=str(TRANSFORMER_DIR) + "_runs", num_train_epochs=args.epochs,
        per_device_train_batch_size=16, per_device_eval_batch_size=32, learning_rate=3e-5,
        eval_strategy="epoch", save_strategy="no", logging_steps=50, report_to="none")
    trainer = Trainer(model=model, args=arguments, train_dataset=train_set, eval_dataset=test_set,
                      processing_class=tokenizer, compute_metrics=metrics)
    trainer.train()

    predicted = np.argmax(trainer.predict(test_set).predictions, axis=1)
    print(classification_report(y_test, predicted, target_names=LABELS, digits=4))

    TRANSFORMER_DIR.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(TRANSFORMER_DIR))
    tokenizer.save_pretrained(str(TRANSFORMER_DIR))
    print("Saved to " + str(TRANSFORMER_DIR))


if __name__ == "__main__":
    main()
