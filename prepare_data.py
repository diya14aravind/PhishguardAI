"""Download public datasets and convert them into CSV files for training.

Sources (all on GitHub):
  Enron-Spam (ham and spam)  github.com/MWiechmann/enron_spam_data
  SMS Spam Collection        github.com/justmarkham/pycon-2016-tutorial
  phishing_pot (real phishing .eml files)  github.com/rf-peixoto/phishing_pot  (about 1 GB download)

Run:
    python prepare_data.py              # everything
    python prepare_data.py --skip-pot   # skip the 1 GB phishing_pot download
Files are written to data/ and picked up by train.py.
"""

import argparse
import csv
import io
import urllib.request
import zipfile

import pandas as pd

from phishguard.config import DATA_DIR
from phishguard.parser import parse_email

ENRON_URL = "https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip"
SMS_URL = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
POT_URL = "https://codeload.github.com/rf-peixoto/phishing_pot/zip/refs/heads/main"

RAW_DIR = DATA_DIR / "raw"
MAX_CHARS = 5000


def download(url, target):
    if target.exists():
        print("  already downloaded: " + target.name)
        return
    print("  downloading " + url)
    urllib.request.urlretrieve(url, target)


def prepare_enron():
    target = RAW_DIR / "enron_spam_data.zip"
    download(ENRON_URL, target)
    with zipfile.ZipFile(target) as archive:
        with archive.open("enron_spam_data.csv") as handle:
            frame = pd.read_csv(handle)
    subject = frame["Subject"].fillna("").astype(str)
    message = frame["Message"].fillna("").astype(str)
    text = (subject + " . " + message).str.slice(0, MAX_CHARS)
    label = frame["Spam/Ham"].str.lower().str.strip()
    out = pd.DataFrame({"text": text, "label": label})
    out = out[out["label"].isin(["ham", "spam"])]
    out.to_csv(DATA_DIR / "enron_spam.csv", index=False)
    print("  enron_spam.csv " + str(out["label"].value_counts().to_dict()))


def prepare_sms():
    target = RAW_DIR / "sms.tsv"
    download(SMS_URL, target)
    frame = pd.read_csv(target, sep="\t", header=None, names=["label", "text"], quoting=csv.QUOTE_NONE)
    frame.to_csv(DATA_DIR / "sms_spam_collection.csv", index=False)
    print("  sms_spam_collection.csv " + str(frame["label"].value_counts().to_dict()))


def prepare_phishing_pot():
    target = RAW_DIR / "phishing_pot.zip"
    download(POT_URL, target)
    partial_path = RAW_DIR / "phishing_pot_partial.csv"

    # Progress is saved as we go, so an interrupted run can be started again and will continue.
    done_names = set()
    if partial_path.exists():
        done_names = set(pd.read_csv(partial_path)["name"])
        print("  resuming, " + str(len(done_names)) + " emails already parsed")
    else:
        with open(partial_path, "w", newline="", encoding="utf-8") as handle:
            csv.writer(handle).writerow(["name", "text", "label"])

    with zipfile.ZipFile(target) as archive:
        infos = [i for i in archive.infolist() if i.filename.endswith(".eml")]
        print("  parsing " + str(len(infos)) + " phishing emails (this takes a few minutes)")
        with open(partial_path, "a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            for index, info in enumerate(infos):
                if info.filename in done_names:
                    continue
                text = ""
                if info.file_size < 15 * 1024 * 1024:
                    try:
                        email = parse_email(archive.read(info.filename))
                        text = ((email.subject or "") + " . " + (email.body_text or "")).strip()
                    except Exception:
                        text = ""
                if len(text) < 30:
                    writer.writerow([info.filename, "", "skip"])
                else:
                    writer.writerow([info.filename, text[:MAX_CHARS], "phishing"])
                if (index + 1) % 500 == 0:
                    handle.flush()
                    print("    " + str(index + 1) + " done", flush=True)

    frame = pd.read_csv(partial_path)
    out = frame[frame["label"] == "phishing"][["text", "label"]]
    out.to_csv(DATA_DIR / "phishing_pot.csv", index=False)
    print("  phishing_pot.csv " + str(len(out)) + " rows, " + str(len(frame) - len(out)) + " skipped")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-pot", action="store_true", help="skip the 1 GB phishing_pot download")
    args = parser.parse_args()
    DATA_DIR.mkdir(exist_ok=True)
    RAW_DIR.mkdir(exist_ok=True)
    print("Enron-Spam")
    prepare_enron()
    print("SMS Spam Collection")
    prepare_sms()
    if not args.skip_pot:
        print("phishing_pot")
        prepare_phishing_pot()


if __name__ == "__main__":
    main()
