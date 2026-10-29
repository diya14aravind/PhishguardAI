# PhishGuard AI

Multi-agent, explainable email threat detection. It extends a single-classifier approach into five specialist
agents, a weighted decision fusion step with BEC escalation, and a MITRE ATT&CK tagged threat intelligence report.

## Setup (Mac, VS Code terminal)

```bash
cd PhishGuardAI
/opt/homebrew/bin/python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 1. Get data and train the Content Agent

The project trains on public datasets, all hosted on GitHub:

| Dataset | What it gives | Rows used |
|---|---|---|
| Enron-Spam (MWiechmann/enron_spam_data) | ham and spam | about 33,000 |
| SMS Spam Collection | ham and spam | about 5,500 |
| phishing_pot (rf-peixoto/phishing_pot) | real phishing emails (.eml) | about 12,000 |
| modern_synthetic (generated here) | modern ham and promotional spam | about 5,000 |

phishing_pot is licensed CC BY-NC 4.0 (non-commercial use with attribution), which fits an academic project.
Cite it and the Enron-Spam source in your report.

Option A: use the ready CSVs. Unzip `PhishGuardAI_data.zip` into the `data/` folder.

Option B: build them yourself (the phishing_pot download is about 1 GB):

```bash
python prepare_data.py              # use --skip-pot to skip the 1 GB phishing_pot download
python generate_modern_samples.py
```

Then train (about 2 minutes):

```bash
python train.py
```

It prints per-class precision, recall and F1, a confusion matrix and accuracy per data source, then saves
`models/content_lr.joblib`. Report the numbers for enron_spam and phishing_pot. The modern_synthetic score is
meaningless because those rows are generated from templates.

Why the modern_synthetic file exists: Enron ham is from 2001 and rarely has links, while the phishing samples are
recent and nearly all have links. Trained without it, the model scored a normal Amazon shipping email as 99% phishing.

## 2. Check an email

```bash
python analyze.py samples/phish_paypal.eml
python analyze.py --text "Dear user, verify your password at http://paypa1.com/login"
python analyze.py --json samples/bec_wire.eml
```

## 3. Use the web app

```bash
python run_server.py
```

Open http://127.0.0.1:8000. You can upload an .eml, paste the full raw source, or paste just subject and body.

## Testing your own mail

Best accuracy needs headers, because SPF, DKIM, DMARC and Reply-To checks use them.

* Gmail, upload route: open the email, three dots, Download message, then upload the .eml.
* Gmail, paste route: open the email, three dots, Show original, Copy to clipboard, paste into "Paste full source".
* Body only works too, but sender checks are skipped and the report says so.

## How it decides

| Agent | Method | Weight |
|---|---|---|
| Content | TF-IDF + Logistic Regression (or DistilBERT if trained), 3 classes | 0.30 |
| URL Intelligence | rules: lookalike domains, text vs href mismatch, IP hosts, punycode, shorteners, TLDs | 0.25 |
| Sender Verification | rules: SPF, DKIM, DMARC, display name spoofing, Reply-To mismatch | 0.20 |
| Attachment Analysis | rules: double extensions, executables, macros, PDF active content, archives, magic bytes | 0.15 |
| Social Engineering | rules: urgency, fear, authority, reward, credential and payment asks, secrecy | 0.10 |

Fusion steps (see `phishguard/fusion.py` and `phishguard/config.py`):

1. Weighted sum of the five scores.
2. Strong evidence from the URL, sender or attachment agent raises the floor to 0.60.
3. Text rules: a credential or payment ask plus a suspicious link, a strong text model plus an ask, or a reward plus an ask each raise the floor to 0.55.
4. Two or more agents above 0.40 add a corroboration bonus.
5. BEC tier 1 (money or availability request with pressure) floors at 0.45. Tier 2 (the same plus a spoofed or mismatched sender) floors at 0.80.
6. Mail that passes DMARC from a known brand domain with clean links is capped at 0.20.
7. Verdict: PHISHING at 0.55 or more, SPAM when the spam probability is 0.50 or more and risk is under 0.45, SUSPICIOUS at 0.30 or more, otherwise SAFE.

Spam is its own class, so promotional mail is no longer pushed into phishing. This replaces the old single threshold.

## Optional: transformer upgrade (DistilBERT or RoBERTa)

You need: the CSVs in `data/`, the extra packages, internet on the first run (the base model is about 270 MB
from Hugging Face), and ideally a GPU.

```bash
pip install torch "transformers>=4.46" datasets accelerate
python train_transformer.py                      # DistilBERT, 2 epochs, up to 12000 rows
python train_transformer.py --model roberta-base # slower, usually a little better
python train_transformer.py --epochs 3 --max-rows 20000
```

Rough time: Mac with Apple Silicon about 30 to 60 minutes for the default run. A free Google Colab GPU
(Runtime, Change runtime type, T4) takes about 10 minutes: upload the project folder and the data, run the same command,
then download the `models/transformer/` folder back into this project.

When `models/transformer/` exists the Content Agent uses it automatically. Delete that folder to go back to
Logistic Regression. After switching, run the tests and the samples again, because transformer probabilities are
sharper than Logistic Regression and the fusion thresholds were tuned on the latter.

## Tests

```bash
pip install pytest
python -m pytest -q tests
```

## Limits to know about

* URL checks are offline (structure and lookalike rules). There is no live reputation, WHOIS or DNS lookup.
* The brand list in `phishguard/domain_utils.py` is finite. Add brands you care about.
* The text model only knows the style of its training data, so retrain with your own labelled mail for best results.
* Rules and weights are hand set, not learned. Tune them in `config.py` if you see mistakes.
