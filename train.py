"""Train the Content Agent (TF-IDF + Logistic Regression, balanced with ADASYN).

Run from the project folder:
    /opt/homebrew/bin/python3.11 train.py
"""

import joblib
from imblearn.over_sampling import ADASYN, SMOTE
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split

from phishguard.config import LR_MODEL_PATH, MODEL_DIR
from phishguard.data_loader import load_all
from phishguard.text_utils import clean_text


def main():
    data = load_all()
    texts = [clean_text(t) for t in data["text"]]
    labels = list(data["label"])
    sources = list(data["source"])

    x_train_text, x_test_text, y_train, y_test, _, source_test = train_test_split(
        texts, labels, sources, test_size=0.2, random_state=42, stratify=labels)

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=0.9, max_features=60000,
                                 sublinear_tf=True)
    x_train = vectorizer.fit_transform(x_train_text)
    x_test = vectorizer.transform(x_test_text)

    print("Balancing the training split with ADASYN (test split is left untouched)")
    try:
        x_train, y_train = ADASYN(random_state=42).fit_resample(x_train, y_train)
    except (ValueError, RuntimeError) as error:
        print("ADASYN could not run (" + str(error)[:80] + "). Trying SMOTE instead.")
        try:
            x_train, y_train = SMOTE(random_state=42).fit_resample(x_train, y_train)
        except (ValueError, RuntimeError) as smote_error:
            print("SMOTE could not run (" + str(smote_error)[:80] + "). Training without resampling.")

    classifier = LogisticRegression(max_iter=2000, C=4.0, solver="lbfgs")
    classifier.fit(x_train, y_train)

    predictions = classifier.predict(x_test)
    print("\nTest results")
    print(classification_report(y_test, predictions, digits=4))
    print("Confusion matrix (rows = true, columns = predicted), order " + str([str(c) for c in classifier.classes_]))
    print(confusion_matrix(y_test, predictions, labels=classifier.classes_))
    print("Macro F1: " + str(round(f1_score(y_test, predictions, average="macro"), 4)))

    # Accuracy per data source. Report the real datasets, not the generated modern_synthetic one.
    print("\nAccuracy by source (test split)")
    for source in sorted(set(source_test)):
        indexes = [i for i, name in enumerate(source_test) if name == source]
        correct = len([i for i in indexes if predictions[i] == y_test[i]])
        print("  " + source.ljust(26) + str(round(correct / len(indexes), 4)) + "  (" + str(len(indexes)) + " emails)")

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "classifier": classifier}, LR_MODEL_PATH)
    print("\nSaved model to " + str(LR_MODEL_PATH))


if __name__ == "__main__":
    main()
