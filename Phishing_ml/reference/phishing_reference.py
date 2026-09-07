"""
      LAB 3.0 — PHISHING DETECTION WITH MACHINE LEARNING      
"""

import os, re, math, time, json, shutil, zipfile, subprocess, warnings
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

# ── Paths ─────────────────────────────────────────────────────────
DATA_DIR      = Path("data")
TREC_TEXT_CSV = DATA_DIR / "email_text.csv"
TREC_ORIG_CSV = DATA_DIR / "email_origin.csv"
NAZARIO_DIR   = DATA_DIR / "nazario"
MODERN_CSV    = DATA_DIR / "modern" / "phishing_email.csv"
OUTPUT_DIR    = Path("outputs")
DATA_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ── Kaggle IDs ────────────────────────────────────────────────────
TREC_KAGGLE    = "bayes2003/emails-for-spam-or-ham-classification-trec-2007"
NAZARIO_KAGGLE = "bayes2003/emails-for-spam-or-ham-classification-spamassassin"
MODERN_KAGGLE  = "naserabdullahalam/phishing-email-dataset"

# ── Constants ─────────────────────────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "verify", "suspended", "compromised", "immediately",
    "act now", "click here", "confirm", "unusual", "locked",
    "limited time", "expire",
]
RISKY_TLDS = {".ru", ".tk", ".xyz", ".top", ".club", ".pw", ".gq"}

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
    "SVM (Linear)":         CalibratedClassifierCV(
                                LinearSVC(max_iter=2000, random_state=42,
                                          class_weight="balanced")),
}

SEP = "═" * 68
sep = "─" * 68

def _check_kaggle_credentials():
    kaggle_path = Path.home() / ".kaggle" / "kaggle.json"
    if not kaggle_path.exists():
        print(f"\n  ✗  kaggle.json not found at {kaggle_path}")
        print("     Follow setup instructions at the top of this file.")
        raise FileNotFoundError("kaggle.json missing")
    os.environ["KAGGLE_CONFIG_DIR"] = str(Path.home() / ".kaggle")
    print(f"  ✓  Kaggle credentials found")


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
    cmd = [kaggle_exe, "datasets", "download",
           "-d", dataset, "-p", str(dest)]
    if unzip:
        cmd.append("--unzip")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ✗  Download failed:\n{result.stderr}")
        raise RuntimeError(f"Kaggle download failed for {dataset}")
    print(f"  ✓  Downloaded to {dest}")


def ensure_datasets():
    print(f"\n{SEP}\n  CHECKING DATASETS\n{sep}")
    _check_kaggle_credentials()

    # TREC 2007
    if TREC_TEXT_CSV.exists() and TREC_ORIG_CSV.exists():
        rows = sum(1 for _ in open(TREC_TEXT_CSV, encoding="utf-8",
                                   errors="ignore")) - 1
        print(f"  ✓  TREC 2007 already present  ({rows:,} emails)")
    else:
        print("  TREC 2007 not found — downloading...")
        _kaggle_download(TREC_KAGGLE, DATA_DIR, unzip=True)
        if not TREC_TEXT_CSV.exists():
            for f in DATA_DIR.rglob("email_text.csv"):
                shutil.copy(f, TREC_TEXT_CSV); break
        if not TREC_ORIG_CSV.exists():
            for f in DATA_DIR.rglob("email_origin.csv"):
                shutil.copy(f, TREC_ORIG_CSV); break
        print(f"  ✓  TREC 2007 ready")

    # SpamAssassin
    if NAZARIO_DIR.exists() and any(NAZARIO_DIR.glob("**/*")):
        n = len(list(NAZARIO_DIR.glob("**/*")))
        print(f"  ✓  SpamAssassin already present  ({n:,} files)")
    else:
        print("  SpamAssassin not found — downloading...")
        _kaggle_download(NAZARIO_KAGGLE, NAZARIO_DIR, unzip=True)
        print(f"  ✓  SpamAssassin ready")

    # Modern 2024
    modern_dir = DATA_DIR / "modern"
    if MODERN_CSV.exists():
        rows = sum(1 for _ in open(MODERN_CSV, encoding="utf-8",
                                   errors="ignore")) - 1
        print(f"  ✓  Modern 2024 already present  ({rows:,} emails)")
    else:
        print("  Modern 2024 not found — downloading...")
        _kaggle_download(MODERN_KAGGLE, modern_dir, unzip=True)
        if not MODERN_CSV.exists():
            csvs = list(modern_dir.glob("*.csv"))
            if csvs:
                shutil.copy(csvs[0], MODERN_CSV)
        print(f"  ✓  Modern 2024 ready")


#   TASK 1a — Load Dataset 

def load_dataset() -> pd.DataFrame:
    print(f"\n{SEP}\n  TASK 1a — LOADING DATASET\n{sep}")
    rows = []
    print("  Loading TREC 2007 (full headers)...")
    df_text = pd.read_csv(TREC_ORIG_CSV, encoding="utf-8", on_bad_lines="skip")
    print(f"  [DEBUG] email_origin.csv columns: {list(df_text.columns)}")
    text_col  = "origin"
    label_col = "label"
    for _, row in df_text.iterrows():
        raw  = str(row[text_col])
        lval = str(row[label_col]).lower().strip()
        label = 0 if lval in ("ham","0","false","legit") else 1
        rows.append({"raw_email": raw, "label": label})
    print(f"  TREC loaded   : {len(rows):,} emails")

    # SpamAssassin — these are real .eml files with headers
    print("  Loading SpamAssassin...")
    naz_count = 0
    for eml_file in NAZARIO_DIR.rglob("*"):
        if not eml_file.is_file():
            continue
        try:
            raw = eml_file.read_bytes().decode("utf-8", errors="ignore")
        except Exception:
            continue
        folder = eml_file.parent.name.lower()
        label  = 0 if "ham" in folder else 1
        rows.append({"raw_email": raw, "label": label})
        naz_count += 1
    print(f"  SpamAssassin  : {naz_count:,} emails")

    # Modern 2024
    if MODERN_CSV.exists():
        print("  Loading Modern 2024...")
        df_m = pd.read_csv(MODERN_CSV, encoding="utf-8", on_bad_lines="skip")
        text_col_m  = "text_combined"
        label_col_m = "label"
        mc = 0
        for _, row in df_m.iterrows():
            raw  = str(row[text_col_m])
            lval = str(row[label_col_m]).lower().strip()
            label = 0 if lval in ("ham","0","false","legit","safe") else 1
            rows.append({"raw_email": raw, "label": label})
            mc += 1
        print(f"  Modern loaded : {mc:,} emails")

    df = pd.DataFrame(rows)
    print(f"\n  Total emails  : {len(df):,}")
    print(f"  Phishing/spam : {df['label'].sum():,}  "
          f"({df['label'].mean()*100:.1f}%)")
    print(f"  Clean         : {(df['label']==0).sum():,}  "
          f"({(1-df['label'].mean())*100:.1f}%)")
    return df

#  TASK 1b — Extract Features 

def _parse_header_signals(raw_email: str) -> dict:
    try:
        msg = message_from_string(raw_email)
    except Exception:
        return {"has_headers": 0, "reply_to_mismatch": 0,
                "suspicious_mailer": 0, "spf_fail": 0}

    from_addr = msg.get("From", "") or ""
    reply_to  = msg.get("Reply-To", "") or ""
    mailer    = (msg.get("X-Mailer", "") or "")
    auth_res  = (msg.get("Authentication-Results", "") or "") + \
                (msg.get("Received-SPF", "") or "")

    has_headers = 1 if (from_addr or mailer or auth_res) else 0

    def _domain(addr):
        m = re.search(r"@([\w\.-]+)", addr)
        return m.group(1).lower() if m else ""

    from_domain  = _domain(from_addr)
    reply_domain = _domain(reply_to)
    reply_to_mismatch = 1 if (reply_to and reply_domain and from_domain
                               and reply_domain != from_domain) else 0

    suspicious_keywords = ["bulk", "blast", "campaign", "mass mail"]
    suspicious_mailer = 1 if any(k in mailer.lower() for k in suspicious_keywords) else 0

    spf_fail = 1 if re.search(r"\b(fail|softfail)\b", auth_res.lower()) else 0

    return {
        "has_headers": has_headers,
        "reply_to_mismatch": reply_to_mismatch,
        "suspicious_mailer": suspicious_mailer,
        "spf_fail": spf_fail,
    }


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
    # Collapse long runs of base64-looking characters (no spaces, 40+ chars)
    text = re.sub(r"[A-Za-z0-9+/=]{80,}", " ", text)
    return text[:max_len]


def extract_features(df: pd.DataFrame):
    """
    Returns:
        X_tfidf   : sparse TF-IDF matrix  (142204 x 3000)
        X_manual  : dense manual features  (142204 x 7)
        y         : labels array
    Feature names: tfidf features + [urgency_count, urgency_density,
                                      avg_url_entropy, risky_tld_count,
                                      reply_to_mismatch, suspicious_mailer,
                                      spf_fail]
    """
    print(f"\n{sep}\n  TASK 1b — EXTRACTING FEATURES\n{sep}")

    # ── TF-IDF on raw text ────────────────────────────────────────
    print("  Cleaning attachment blobs before vectorising...")
    clean_text = df["raw_email"].fillna("").apply(_strip_attachments)

    print("  Building TF-IDF matrix (3000 features)...")
    tfidf = TfidfVectorizer(
        max_features=3000,
        stop_words="english",
        ngram_range=(1, 2),     # unigrams + bigrams
        min_df=5,               # ignore very rare words
        sublinear_tf=True       # dampens very high term frequencies
    )
    X_tfidf = tfidf.fit_transform(clean_text)
    print(f"  TF-IDF shape  : {X_tfidf.shape}")

    # ── Manual body/URL signals ───────────────────────────────────
    print("  Extracting manual signals...")
    manual_rows = []
    total_rows = len(df)
    for i, (_, row) in enumerate(df.iterrows()):
        if i % 20000 == 0:
            print(f"    ... {i:,} / {total_rows:,}")
        text  = str(row["raw_email"])
        lower = text.lower()

        # Urgency signals
        urgency_count = sum(lower.count(kw) for kw in URGENCY_KEYWORDS)
        words = lower.split()
        urgency_density = round(urgency_count / len(words), 4) if words else 0.0

        # URL signals
        urls      = _extract_urls(text)
        entropies = []
        risky_tld = 0
        for url in urls:
            domain = _url_domain(url)
            label  = domain.split(".")[0] if domain else ""
            entropies.append(_shannon_entropy(label))
            tld = "." + domain.split(".")[-1].lower() if "." in domain else ""
            if tld in RISKY_TLDS:
                risky_tld += 1

        avg_entropy = round(sum(entropies)/len(entropies), 4) if entropies else 0.0

        # Header signals — 0 if this row has no parseable headers
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

    # Scale manual features to 0-1 so they don't dominate TF-IDF weights
    scaler   = MinMaxScaler()
    X_manual = scaler.fit_transform(X_manual)

    y = df["label"].values
    print(f"  Manual shape  : {X_manual.shape}")
    print(f"  Features total: {X_tfidf.shape[1] + X_manual.shape[1]}")
    return X_tfidf, X_manual, y, tfidf

#   TASK 2 — Train/Test Split and Model Training 

def train_models(X_tfidf, X_manual, y):
    print(f"\n{SEP}\n  TASK 2 — TRAINING MODELS\n{sep}")

    # Combine TF-IDF (sparse) + manual (dense) into one sparse matrix
    X_combined = hstack([X_tfidf, csr_matrix(X_manual)])

    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(f"  Train set : {X_train.shape[0]:,} emails")
    print(f"  Test set  : {X_test.shape[0]:,}  emails\n")

    for name, model in MODELS.items():
        print(f"  Training {name}...", end="", flush=True)
        t0 = time.time()
        model.fit(X_train, y_train)
        print(f"  done  ({time.time()-t0:.1f}s)")

    return X_train, X_test, y_train, y_test


#  TASK 3 — Evaluate All Models
def evaluate_models(X_test, y_test) -> dict:
    print(f"\n{SEP}\n  TASK 3 — EVALUATION RESULTS\n{sep}")
    print(f"  {'Model':<22} {'Accuracy':>9} {'Precision':>10} "
          f"{'Recall':>8} {'F1':>8} {'AUC':>8}")
    print(f"  {sep}")

    results = {}
    for name, model in MODELS.items():
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        accuracy  = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred,  zero_division=0)
        recall    = recall_score(y_test,    y_pred,  zero_division=0)
        f1        = f1_score(y_test,        y_pred,  zero_division=0)
        cm        = confusion_matrix(y_test, y_pred)
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        auc_score   = auc(fpr, tpr)

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

#  TASK 4 — Compare Models and Analyse Errors

def compare_models(results: dict, tfidf: TfidfVectorizer,
                   X_test, y_test) -> tuple:
    print(f"\n{SEP}\n  TASK 4 — MODEL COMPARISON AND ERROR ANALYSIS\n{sep}")

    # Part A — best model by F1
    best_name = max(results, key=lambda n: results[n]["f1"])
    print(f"\n  Best model : {best_name}  "
          f"(F1 = {results[best_name]['f1']:.4f})\n")

    # Part B — top TF-IDF words from Logistic Regression
    print("  Top 20 most predictive words (Logistic Regression coefficients):")
    lr_model   = MODELS["Logistic Regression"]
    coef       = lr_model.coef_[0]
    # Full feature name list: 3000 TF-IDF words + 7 manual feature names,
    vocab      = list(tfidf.get_feature_names_out()) + MANUAL_FEATURE_NAMES
    top_phish  = np.argsort(coef)[-20:][::-1]
    top_clean  = np.argsort(coef)[:20]

    print("\n  Strongest PHISHING words:")
    for idx in top_phish:
        bar = "█" * int(abs(coef[idx]) * 20)
        print(f"    {vocab[idx]:<20} {bar}  {coef[idx]:.4f}")

    print("\n  Strongest CLEAN words:")
    for idx in top_clean:
        bar = "█" * int(abs(coef[idx]) * 20)
        print(f"    {vocab[idx]:<20} {bar}  {coef[idx]:.4f}")

    # ── Direct comparison to Lab 3 categories ───────────────────────
    print(f"\n{sep}")
    print("  MANUAL SIGNAL COMPARISON — vs Lab 3 assumed weights")
    print(f"{sep}")

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

    print(f"\n  {'Category':<12} {'Lab 3 assumed':>15} {'Learned weight':>16}")
    print(f"  {'-'*45}")
    if total_score > 0:
        print(f"  {'Header':<12} {'35%':>15} {header_score/total_score*100:>15.1f}%")
        print(f"  {'URL':<12} {'40%':>15} {url_score/total_score*100:>15.1f}%")
        print(f"  {'Body':<12} {'25%':>15} {body_score/total_score*100:>15.1f}%")
    else:
        print("  All manual signal coefficients are zero — check training data.")

    print(f"\n  Individual signal coefficients:")
    for name, val in sorted(manual_coefs.items(), key=lambda x: -abs(x[1])):
        direction = "→ phishing" if val > 0 else "→ clean"
        print(f"    {name:<20} {val:>8.4f}  {direction}")

    # Part C — error analysis
    best_pred  = results[best_name]["y_pred"]
    y_test_arr = np.array(y_test)
    fn_idx = np.where((y_test_arr == 1) & (best_pred == 0))[0]
    fp_idx = np.where((y_test_arr == 0) & (best_pred == 1))[0]

    print(f"\n  False Negatives (phishing missed) : {len(fn_idx):,}")
    print(f"  False Positives (clean flagged)   : {len(fp_idx):,}")

    return best_name

#   VISUALISATIONS                                                 

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
    print(f"\n  → saved: {path}")


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
    print(f"  → saved: {path}")


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
    ax.set_title("Model Comparison — All Metrics", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right")
    ax.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    path = OUTPUT_DIR / "3_model_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  → saved: {path}")


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
    print(f"  → saved: {path}")


def plot_roc_curves(results: dict):
    colors = ["#3498db","#e74c3c","#2ecc71","#f39c12"]
    fig, ax = plt.subplots(figsize=(8, 7))
    for (name, res), color in zip(results.items(), colors):
        ax.plot(res["fpr"], res["tpr"], color=color, linewidth=2,
                label=f"{name}  (AUC={res['auc']:.3f})")
    ax.plot([0,1],[0,1],"k--", linewidth=1, label="Random baseline")
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate",  fontsize=11)
    ax.set_title("ROC Curves — All Models", fontsize=13, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    path = OUTPUT_DIR / "5_roc_curves.png"
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  → saved: {path}")

#   ENTRY POINT                                                     

if __name__ == "__main__":
    print(f"\n{SEP}")
    print("  LAB 3.0 — PHISHING DETECTION WITH MACHINE LEARNING")
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