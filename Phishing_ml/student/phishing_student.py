"""
    LAB 3.0 -- PHISHING DETECTION WITH MACHINE LEARNING

BEFORE YOU START -- One-time Kaggle setup (5 minutes)

1. Go to   : https://www.kaggle.com  -> sign up free
2. Go to   : https://www.kaggle.com/settings -> API Tokens
3. Click   : Create Legacy API Key  -> downloads kaggle.json
4. Place it:
     Windows : C:/Users/YourName/.kaggle/kaggle.json
     Mac/Linux: ~/.kaggle/kaggle.json

THIS IS THE ONLY FILE YOU EDIT.
Implement every function/block marked with TODO.
Everything else in this file is provided and should not be modified.
"""

import os, re, math, time, json, shutil, subprocess, warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from pathlib import Path
from email import message_from_string
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_curve, auc
)
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore")

# -- Paths (do not modify) ----------------------------------------
DATA_DIR      = Path("data")
TREC_TEXT_CSV = DATA_DIR / "email_text.csv"
TREC_ORIG_CSV = DATA_DIR / "email_origin.csv"
NAZARIO_DIR   = DATA_DIR / "nazario"
MODERN_CSV    = DATA_DIR / "modern" / "phishing_email.csv"
OUTPUT_DIR    = Path("outputs")
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# -- Kaggle IDs (do not modify) ------------------------------------
TREC_KAGGLE    = "bayes2003/emails-for-spam-or-ham-classification-trec-2007"
NAZARIO_KAGGLE = "bayes2003/emails-for-spam-or-ham-classification-spamassassin"
MODERN_KAGGLE  = "naserabdullahalam/phishing-email-dataset"

# -- Constants (do not modify) -------------------------------------
URGENCY_KEYWORDS = [
    "urgent", "verify", "suspended", "compromised", "immediately",
    "act now", "click here", "confirm", "unusual", "locked",
    "limited time", "expire",
]
RISKY_TLDS = {".ru", ".tk", ".xyz", ".top", ".club", ".pw", ".gq"}

# Order matters -- this must match the order you append manual signals
# to each row in extract_features() below.
MANUAL_FEATURE_NAMES = [
    "urgency_count", "urgency_density", "avg_url_entropy", "risky_tld_count",
    "reply_to_mismatch", "suspicious_mailer", "spf_fail",
]

MODELS = {
    "Naive Bayes":          MultinomialNB(),
    "Logistic Regression":  LogisticRegression(max_iter=1000, random_state=42,
                                               class_weight="balanced"),
    "Random Forest":        RandomForestClassifier(n_estimators=50, max_depth=20,
                                                   random_state=42,
                                                   class_weight="balanced"),
    # SVM is wrapped in CalibratedClassifierCV because a raw LinearSVC has no
    # predict_proba() method (only decision_function()) -- Task 3 needs
    # predict_proba() for every model to compute the ROC curve and AUC.
    "SVM (Linear)":         CalibratedClassifierCV(
                                LinearSVC(max_iter=2000, random_state=42,
                                          class_weight="balanced")),
}

SEP = "=" * 68
sep = "-" * 68


# Auto-download (do not modify)

def _check_kaggle_credentials():
    kaggle_path = Path.home() / ".kaggle" / "kaggle.json"
    if not kaggle_path.exists():
        print(f"\n  X  kaggle.json not found at {kaggle_path}")
        print("     Follow setup instructions at the top of this file.")
        raise FileNotFoundError("kaggle.json missing")
    os.environ["KAGGLE_CONFIG_DIR"] = str(Path.home() / ".kaggle")
    print(f"  OK  Kaggle credentials found")

def _find_kaggle() -> str:
    import shutil as sh, sys
    found = sh.which("kaggle")
    if found:
        return found
    candidates = [
        Path(sys.executable).parent / "Scripts" / "kaggle.exe",
        Path(sys.executable).parent / "kaggle.exe",
        Path(sys.executable).parent.parent / "Scripts" / "kaggle.exe",
    ]
    appdata = Path.home() / "AppData" / "Roaming" / "Python"
    if appdata.exists():
        for s in appdata.glob("*/Scripts/kaggle.exe"):
            candidates.append(s)
    for c in candidates:
        if Path(c).exists():
            return str(c)
    raise FileNotFoundError("kaggle not found. Run: pip install kaggle")

def _kaggle_download(dataset: str, dest: Path, unzip: bool = True):
    dest.mkdir(parents=True, exist_ok=True)
    kaggle_exe = _find_kaggle()
    print(f"  Downloading {dataset} ...")
    cmd = [kaggle_exe, "datasets", "download", "-d", dataset, "-p", str(dest)]
    if unzip:
        cmd.append("--unzip")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  X  Download failed:\n{result.stderr}")
        raise RuntimeError(f"Kaggle download failed for {dataset}")
    print(f"  OK  Downloaded to {dest}")

def ensure_datasets():
    print(f"\n{SEP}\n  CHECKING DATASETS\n{sep}")
    _check_kaggle_credentials()
    if TREC_TEXT_CSV.exists() and TREC_ORIG_CSV.exists():
        print(f"  OK  TREC 2007 already present")
    else:
        _kaggle_download(TREC_KAGGLE, DATA_DIR, unzip=True)
    if NAZARIO_DIR.exists() and any(NAZARIO_DIR.glob("**/*")):
        print(f"  OK  SpamAssassin already present")
    else:
        _kaggle_download(NAZARIO_KAGGLE, NAZARIO_DIR, unzip=True)
    modern_dir = DATA_DIR / "modern"
    if MODERN_CSV.exists():
        print(f"  OK  Modern 2024 already present")
    else:
        _kaggle_download(MODERN_KAGGLE, modern_dir, unzip=True)
        if not MODERN_CSV.exists():
            csvs = list(modern_dir.glob("*.csv"))
            if csvs:
                shutil.copy(csvs[0], MODERN_CSV)


# TASK 1a -- Load Dataset

# Load emails from three sources into ONE list of row-dicts, then a DataFrame.
# Each row needs exactly two keys: "raw_email" (str) and "label" (int, 1=phishing/spam, 0=clean).
#
# Source 1 -- TREC 2007 (has full headers): read TREC_ORIG_CSV.
#   Columns are "origin" (the raw email text) and "label" (string, e.g. "spam"/"ham").
#   Map label to 1 if it is NOT in ("ham","0","false","legit"), else 0.
#
# Source 2 -- SpamAssassin (real .eml files with headers): walk NAZARIO_DIR
#   recursively with .rglob("*"). Skip anything that is not a file. Read each
#   file as bytes and decode as utf-8 (errors="ignore"). The email's label is
#   NOT in the file itself -- it comes from the containing folder name: if
#   "ham" appears in the parent folder name (lowercased), label = 0, else 1.
#
# Source 3 -- Modern 2024 (body text only, if MODERN_CSV exists): read MODERN_CSV.
#   Columns are "text_combined" and "label" (string). Map label to 0 if it is
#   in ("ham","0","false","legit","safe"), else 1.

def load_dataset() -> pd.DataFrame:
    print(f"\n{SEP}\n  TASK 1a -- LOADING DATASET\n{sep}")
    rows = []

    print("  Loading TREC 2007 (full headers)...")
    # TODO: read TREC_ORIG_CSV with pd.read_csv(..., on_bad_lines="skip"),
    # loop over rows, build the label using the rule above, and append
    # {"raw_email": ..., "label": ...} dicts to `rows`.


    print("  Loading SpamAssassin...")
    # TODO: walk NAZARIO_DIR with .rglob("*"), read each file, determine the
    # label from the parent folder name, and append to `rows`.


    if MODERN_CSV.exists():
        print("  Loading Modern 2024...")
        # TODO: read MODERN_CSV and append to `rows`, using the label rule above.


    df = pd.DataFrame(rows)
    print(f"\n  Total emails  : {len(df):,}")
    print(f"  Phishing/spam : {df['label'].sum():,}  ({df['label'].mean()*100:.1f}%)")
    print(f"  Clean         : {(df['label']==0).sum():,}  ({(1-df['label'].mean())*100:.1f}%)")
    return df


# -- Provided helpers -- use these inside extract_features() (do not modify) --

def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c/n)*math.log2(c/n) for c in freq.values())

def _extract_urls(text: str) -> list:
    return re.findall(r"https?://[^\s\"'<>]+", text)

def _url_domain(url: str) -> str:
    url = re.sub(r"^https?://", "", url)
    return url.split("/")[0].split("?")[0]

def _strip_attachments(text: str, max_len: int = 20000) -> str:
    text = re.sub(r"[A-Za-z0-9+/=]{80,}", " ", text)
    return text[:max_len]


# ======================================================================
# TASK 1b, PART A -- Header Signal Extraction
# ======================================================================
# This mirrors parse_email_headers() from Lab 3, applied here to build 3 of
# the 7 manual signals used later. Parse raw_email with message_from_string(),
# then compute:
#
#   reply_to_mismatch  1 if Reply-To domain exists AND differs from From domain, else 0
#   suspicious_mailer  1 if X-Mailer header contains any of:
#                       "bulk", "blast", "campaign", "mass mail"   (case-insensitive)
#   spf_fail            1 if Authentication-Results + Received-SPF headers,
#                       combined and lowercased, contain "fail" or "softfail"
#                       as a whole word (use \b in your regex)
#
# If the email has no headers at all (from_addr, mailer, and auth_res all
# empty), return all three signals as 0 rather than raising an error.
# Hint: extract a domain from an address string with:
#   re.search(r"@([\w\.-]+)", addr)

def _parse_header_signals(raw_email: str) -> dict:
    try:
        msg = message_from_string(raw_email)
    except Exception:
        return {"reply_to_mismatch": 0, "suspicious_mailer": 0, "spf_fail": 0}

    # TODO: extract from_addr, reply_to, mailer, auth_res from msg.get(...)
    # TODO: compute reply_to_mismatch, suspicious_mailer, spf_fail per the rules above

    reply_to_mismatch = 0  # TODO
    suspicious_mailer = 0  # TODO
    spf_fail           = 0  # TODO

    return {
        "reply_to_mismatch": reply_to_mismatch,
        "suspicious_mailer": suspicious_mailer,
        "spf_fail": spf_fail,
    }


# TASK 1b, PART B -- TF-IDF and Manual Feature Assembly


"""
Returns:
    X_tfidf   : sparse TF-IDF matrix  (N x 3000)
    X_manual  : dense manual features (N x 7), scaled to 0-1
    y         : labels array
    tfidf     : the fitted TfidfVectorizer (needed later for Task 4)
Manual feature order MUST match MANUAL_FEATURE_NAMES exactly:
    urgency_count, urgency_density, avg_url_entropy, risky_tld_count,
    reply_to_mismatch, suspicious_mailer, spf_fail
"""

def extract_features(df: pd.DataFrame):
    print(f"\n{sep}\n  TASK 1b -- EXTRACTING FEATURES\n{sep}")

    print("  Cleaning attachment blobs before vectorising...")
    clean_text = df["raw_email"].fillna("").apply(_strip_attachments)

    print("  Building TF-IDF matrix (3000 features)...")
    # TODO: create a TfidfVectorizer with:
    #   max_features=3000, stop_words="english", ngram_range=(1, 2),
    #   min_df=5, sublinear_tf=True
    # then fit_transform() it on clean_text to get X_tfidf.
    tfidf   = None   # TODO
    X_tfidf = None   # TODO
    print(f"  TF-IDF shape  : {X_tfidf.shape}")

    print("  Extracting manual signals...")
    manual_rows = []
    total_rows = len(df)
    for i, (_, row) in enumerate(df.iterrows()):
        if i % 20000 == 0:
            print(f"    ... {i:,} / {total_rows:,}")
        text  = str(row["raw_email"])
        lower = text.lower()

        # TODO: urgency_count = total occurrences of every URGENCY_KEYWORDS
        # phrase in `lower` (sum of lower.count(kw) for each keyword)
        urgency_count = 0     # TODO

        # TODO: urgency_density = urgency_count / number of words in `lower`
        # (0.0 if the email has no words). Round to 4 decimal places.
        urgency_density = 0.0  # TODO

        # TODO: for every URL found by _extract_urls(text):
        #   - get its domain with _url_domain(url)
        #   - take the label before the first dot (e.g. "paypal" from
        #     "paypal.secure0.malicious.ru")
        #   - compute its Shannon entropy with _shannon_entropy(label)
        #   - check if its TLD (the part after the last dot, with a
        #     leading dot, e.g. ".ru") is in RISKY_TLDS
        # avg_entropy = mean entropy across all URLs (0.0 if none)
        # risky_tld   = COUNT of URLs whose TLD is risky (not a boolean)
        avg_entropy = 0.0   # TODO
        risky_tld   = 0     # TODO

        # Header signals -- provided function, just call it:
        hdr = _parse_header_signals(text)

        manual_rows.append([
            urgency_count,
            urgency_density,
            avg_entropy,
            risky_tld,
            hdr["reply_to_mismatch"],
            hdr["suspicious_mailer"],
            hdr["spf_fail"],
        ])

    X_manual = np.array(manual_rows, dtype=float)

    # TODO: scale X_manual to the 0-1 range with MinMaxScaler so these 7
    # columns do not dominate the much smaller TF-IDF weights.
    X_manual = None   # TODO

    y = df["label"].values
    print(f"  Manual shape  : {X_manual.shape}")
    print(f"  Features total: {X_tfidf.shape[1] + X_manual.shape[1]}")
    return X_tfidf, X_manual, y, tfidf


# TASK 2 -- Train/Test Split and Model Training

def train_models(X_tfidf, X_manual, y):
    print(f"\n{SEP}\n  TASK 2 -- TRAINING MODELS\n{sep}")

    # TODO: combine X_tfidf (sparse) and X_manual (dense) into one sparse
    # matrix using hstack([X_tfidf, csr_matrix(X_manual)])
    X_combined = None   # TODO

    # TODO: split X_combined and y with train_test_split, using:
    #   test_size=0.2, random_state=42, stratify=y
    X_train, X_test, y_train, y_test = None, None, None, None   # TODO

    print(f"  Train set : {X_train.shape[0]:,} emails")
    print(f"  Test set  : {X_test.shape[0]:,}  emails\n")

    for name, model in MODELS.items():
        print(f"  Training {name}...", end="", flush=True)
        t0 = time.time()
        # TODO: model.fit(X_train, y_train)
        print(f"  done  ({time.time()-t0:.1f}s)")

    return X_train, X_test, y_train, y_test


# TASK 3 -- Evaluate All Models

# For each model, compute all six values below using sklearn functions
# already imported at the top of this file:
#   y_pred    = model.predict(X_test)
#   y_prob    = model.predict_proba(X_test)[:, 1]   -- works for every model
#               here, since SVM is wrapped in CalibratedClassifierCV (see MODELS)
#   accuracy  = accuracy_score(y_test, y_pred)
#   precision = precision_score(y_test, y_pred, zero_division=0)
#   recall    = recall_score(y_test, y_pred, zero_division=0)
#   f1        = f1_score(y_test, y_pred, zero_division=0)
#   cm        = confusion_matrix(y_test, y_pred)
#   fpr, tpr, _ = roc_curve(y_test, y_prob)
#   auc_score   = auc(fpr, tpr)

def evaluate_models(X_test, y_test) -> dict:
    print(f"\n{SEP}\n  TASK 3 -- EVALUATION RESULTS\n{sep}")
    print(f"  {'Model':<22} {'Accuracy':>9} {'Precision':>10} "
          f"{'Recall':>8} {'F1':>8} {'AUC':>8}")
    print(f"  {sep}")

    results = {}
    for name, model in MODELS.items():
        # TODO: compute all six values listed above
        y_pred    = None  # TODO
        y_prob    = None  # TODO
        accuracy  = None  # TODO
        precision = None  # TODO
        recall    = None  # TODO
        f1        = None  # TODO
        cm        = None  # TODO
        fpr       = None  # TODO
        tpr       = None  # TODO
        auc_score = None  # TODO

        results[name] = {
            "accuracy": accuracy, "precision": precision,
            "recall":   recall,   "f1":        f1,
            "cm":       cm,       "fpr":       fpr,
            "tpr":      tpr,      "auc":       auc_score,
            "y_pred":   y_pred,
        }
        print(f"  {name:<22} {accuracy:>9.4f} {precision:>10.4f} "
              f"{recall:>8.4f} {f1:>8.4f} {auc_score:>8.4f}")
    return results


# TASK 4 -- Compare Models and Analyse Errors

# Part A: find the model name with the highest F1 score.
#   Hint: best_name = max(results, key=lambda n: results[n]["f1"])
#
# Part B: NOT Random Forest feature importance -- use the Logistic
#   Regression model's coefficients directly (already retrieved below as
#   `coef`) combined with `vocab` (already built for you) to find the most
#   predictive words/signals.
#   Hint: np.argsort(coef) gives indices from smallest to largest value.
#
# Part C: false negatives = phishing emails (y_test==1) predicted as clean
#   (best_pred==0). False positives = clean emails (y_test==0) predicted as
#   phishing (best_pred==1). Use np.where() with boolean conditions on
#   np.array(y_test) and best_pred to get their indices.

def compare_models(results: dict, tfidf: TfidfVectorizer, X_test, y_test) -> tuple:
    print(f"\n{SEP}\n  TASK 4 -- MODEL COMPARISON AND ERROR ANALYSIS\n{sep}")

    # Part A
    best_name = None   # TODO
    print(f"\n  Best model : {best_name}  (F1 = {results[best_name]['f1']:.4f})\n")

    # Part B -- top words (provided setup, you fill in the TODOs below)
    print("  Top 20 most predictive words (Logistic Regression coefficients):")
    lr_model  = MODELS["Logistic Regression"]
    coef      = lr_model.coef_[0]
    vocab     = list(tfidf.get_feature_names_out()) + MANUAL_FEATURE_NAMES

    top_phish = None   # TODO: indices of the 20 LARGEST coef values (phishing-leaning)
    top_clean = None   # TODO: indices of the 20 SMALLEST coef values (clean-leaning)

    print("\n  Strongest PHISHING words:")
    for idx in top_phish:
        bar = "#" * int(abs(coef[idx]) * 20)
        print(f"    {vocab[idx]:<20} {bar}  {coef[idx]:.4f}")

    print("\n  Strongest CLEAN words:")
    for idx in top_clean:
        bar = "#" * int(abs(coef[idx]) * 20)
        print(f"    {vocab[idx]:<20} {bar}  {coef[idx]:.4f}")

    # Manual signal category comparison -- provided, no TODO here
    print(f"\n{sep}\n  MANUAL SIGNAL COMPARISON -- vs Lab 3 assumed weights\n{sep}")
    manual_start = len(vocab) - len(MANUAL_FEATURE_NAMES)
    manual_coefs = {name: coef[manual_start + i]
                     for i, name in enumerate(MANUAL_FEATURE_NAMES)}
    header_feats = ["reply_to_mismatch", "suspicious_mailer", "spf_fail"]
    url_feats    = ["avg_url_entropy", "risky_tld_count"]
    body_feats   = ["urgency_count", "urgency_density"]
    header_score = sum(abs(manual_coefs[f]) for f in header_feats)
    url_score    = sum(abs(manual_coefs[f]) for f in url_feats)
    body_score   = sum(abs(manual_coefs[f]) for f in body_feats)
    total_score  = header_score + url_score + body_score
    if total_score > 0:
        print(f"  Header : 35% assumed vs {header_score/total_score*100:.1f}% learned")
        print(f"  URL    : 40% assumed vs {url_score/total_score*100:.1f}% learned")
        print(f"  Body   : 25% assumed vs {body_score/total_score*100:.1f}% learned")

    # Part C
    best_pred  = results[best_name]["y_pred"]
    y_test_arr = np.array(y_test)
    fn_idx = None   # TODO: indices where y_test_arr==1 AND best_pred==0
    fp_idx = None   # TODO: indices where y_test_arr==0 AND best_pred==1

    print(f"\n  False Negatives (phishing missed) : {len(fn_idx):,}")
    print(f"  False Positives (clean flagged)   : {len(fp_idx):,}")

    return best_name


# Visualisations (do not modify)

def plot_dataset_distribution(df: pd.DataFrame):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("Dataset Distribution", fontsize=13, fontweight="bold")

    counts = df["label"].value_counts()
    axes[0].bar(["Clean (0)", "Phishing (1)"],
                [counts.get(0,0), counts.get(1,0)],
                color=["#2ecc71","#e74c3c"], edgecolor="black", linewidth=0.8)
    axes[0].set_title("Class Balance")
    axes[0].set_ylabel("Number of Emails")
    for bar in axes[0].patches:
        axes[0].text(bar.get_x()+bar.get_width()/2,
                     bar.get_height()+300,
                     f"{int(bar.get_height()):,}",
                     ha="center", fontsize=10)

    axes[1].bar(["Phishing","Clean"],
                [df[df["label"]==1]["raw_email"].str.len().mean(),
                 df[df["label"]==0]["raw_email"].str.len().mean()],
                color=["#e74c3c","#2ecc71"], edgecolor="black", linewidth=0.8)
    axes[1].set_title("Mean Email Length by Class")
    axes[1].set_ylabel("Characters")

    plt.tight_layout()
    path = OUTPUT_DIR / "1_dataset_distribution.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"\n  -> saved: {path}")


def plot_confusion_matrices(results: dict):
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    fig.suptitle("Confusion Matrices", fontsize=13, fontweight="bold")
    axes = axes.flatten()
    for ax, (name, res) in zip(axes, results.items()):
        sns.heatmap(res["cm"], annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Clean","Phishing"],
                    yticklabels=["Clean","Phishing"],
                    ax=ax, linewidths=0.5, linecolor="gray")
        ax.set_title(f"{name}  (F1={res['f1']:.3f})", fontsize=11)
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    plt.tight_layout()
    path = OUTPUT_DIR / "2_confusion_matrices.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  -> saved: {path}")


def plot_model_comparison(results: dict):
    metrics = ["accuracy","precision","recall","f1","auc"]
    names   = list(results.keys())
    x, w    = np.arange(len(metrics)), 0.18
    colors  = ["#3498db","#e74c3c","#2ecc71","#f39c12"]
    fig, ax = plt.subplots(figsize=(13, 6))
    for i, (name, color) in enumerate(zip(names, colors)):
        vals = [results[name][m] for m in metrics]
        bars = ax.bar(x+i*w, vals, w, label=name,
                      color=color, edgecolor="black", linewidth=0.6)
        for bar in bars:
            ax.text(bar.get_x()+bar.get_width()/2,
                    bar.get_height()+0.003,
                    f"{bar.get_height():.2f}",
                    ha="center", va="bottom", fontsize=7, rotation=90)
    ax.set_xticks(x+w*1.5)
    ax.set_xticklabels([m.capitalize() for m in metrics], fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("Score")
    ax.set_title("Model Comparison -- All Metrics", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = OUTPUT_DIR / "3_model_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  -> saved: {path}")


def plot_top_words(tfidf: TfidfVectorizer):
    lr_model = MODELS["Logistic Regression"]
    coef     = lr_model.coef_[0]
    vocab    = list(tfidf.get_feature_names_out()) + MANUAL_FEATURE_NAMES
    n        = 20

    top_phish_idx = np.argsort(coef)[-n:][::-1]
    top_clean_idx = np.argsort(coef)[:n]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 7))
    fig.suptitle("Top 20 Most Predictive Words (Logistic Regression)",
                 fontsize=13, fontweight="bold")

    ax1.barh([vocab[i] for i in top_phish_idx[::-1]],
             [coef[i]  for i in top_phish_idx[::-1]],
             color="#e74c3c", edgecolor="black", linewidth=0.5)
    ax1.set_title("Strongest PHISHING words")
    ax1.set_xlabel("Coefficient")

    ax2.barh([vocab[i] for i in top_clean_idx],
             [abs(coef[i]) for i in top_clean_idx],
             color="#2ecc71", edgecolor="black", linewidth=0.5)
    ax2.set_title("Strongest CLEAN words")
    ax2.set_xlabel("Coefficient (absolute)")

    plt.tight_layout()
    path = OUTPUT_DIR / "4_top_words.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  -> saved: {path}")


def plot_roc_curves(results: dict):
    colors = ["#3498db","#e74c3c","#2ecc71","#f39c12"]
    fig, ax = plt.subplots(figsize=(8, 7))
    for (name, res), color in zip(results.items(), colors):
        ax.plot(res["fpr"], res["tpr"], color=color, linewidth=2,
                label=f"{name}  (AUC={res['auc']:.3f})")
    ax.plot([0,1],[0,1],"k--", linewidth=1, label="Random baseline")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate",  fontsize=11)
    ax.set_title("ROC Curves -- All Models", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    path = OUTPUT_DIR / "5_roc_curves.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  -> saved: {path}")


# ENTRY POINT (do not modify)

if __name__ == "__main__":
    print(f"\n{SEP}")
    print("  LAB 3.0 -- PHISHING DETECTION WITH MACHINE LEARNING")
    print(SEP)

    ensure_datasets()
    raw_df = load_dataset()
    plot_dataset_distribution(raw_df)

    X_tfidf, X_manual, y, tfidf = extract_features(raw_df)
    X_train, X_test, y_train, y_test = train_models(X_tfidf, X_manual, y)
    results = evaluate_models(X_test, y_test)

    print(f"\n{sep}\n  VISUALISATIONS")
    plot_confusion_matrices(results)
    plot_roc_curves(results)

    best_name = compare_models(results, tfidf, X_test, y_test)

    plot_model_comparison(results)
    plot_top_words(tfidf)

    print(f"\n{SEP}")
    print(f"  Lab complete.  All outputs saved to: {OUTPUT_DIR}/")
    print(SEP)