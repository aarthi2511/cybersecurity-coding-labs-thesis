import re
import math
import json
import base64
from email import message_from_string
from email.header import decode_header


def load_email(path: str = "sample_email.eml") -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_url_cache(path: str = "url_cache.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_raw_email(raw: str):
    return message_from_string(raw)


# TASK 1

def parse_email_headers(raw_email: str) -> dict:
    msg = parse_raw_email(raw_email)

    def extract_domain(addr: str) -> str:
        addr = re.sub(r".*<(.+)>.*", r"\1", addr).strip()
        match = re.search(r"@([\w.\-]+)", addr)
        return match.group(1).lower() if match else ""

    from_domain     = extract_domain(msg.get("From", ""))
    reply_to_domain = extract_domain(msg.get("Reply-To", ""))
    mismatch        = from_domain != reply_to_domain

    spf_raw    = (msg.get("Received-SPF") or "unknown").lower()
    spf_result = "unknown"
    for status in ("pass", "fail", "softfail", "neutral"):
        if status in spf_raw:
            spf_result = status
            break

    spam_raw      = (msg.get("X-Spam-Status") or "").lower()
    spam_flagged  = "yes" in spam_raw

    mailer_raw        = (msg.get("X-Mailer") or "").lower()
    suspicious_mailer = any(k in mailer_raw
                            for k in ("bulk", "phpmailer", "mass", "sendgrid"))

    has_originating_ip = msg.get("X-Originating-IP") is not None

    header_risk_score = sum([
        mismatch,
        spf_result in ("fail", "softfail"),
        spam_flagged,
        suspicious_mailer,
        has_originating_ip,
        spf_result == "neutral",
    ])

    return {
        "from_domain":         from_domain,
        "reply_to_domain":     reply_to_domain,
        "mismatch":            mismatch,
        "spf_result":          spf_result,
        "spam_flagged":        spam_flagged,
        "suspicious_mailer":   suspicious_mailer,
        "has_originating_ip":  has_originating_ip,
        "header_risk_score":   header_risk_score,
    }


# TASK 2

def analyze_url_features(url_cache: dict) -> list[dict]:

    def extract_domain(url: str) -> str:
        url = re.sub(r"^https?://", "", url)
        return url.split("/")[0].split("?")[0]

    def subdomain_depth(domain: str) -> int:
        parts = domain.split(".")
        return max(0, len(parts) - 2)

    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        n = len(text)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def is_ip_literal(host: str) -> bool:
        return bool(re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host))

    RISKY_TLDS = {".ru", ".tk", ".xyz", ".top", ".club", ".pw", ".gq"}

    results = []
    for entry in url_cache.get("urls", []):
        url       = entry["original_url"]
        hop_count = entry["hop_count"]

        domain    = extract_domain(url)
        depth     = subdomain_depth(domain)
        label     = domain.split(".")[0]
        entropy   = shannon_entropy(label)
        ip_lit    = is_ip_literal(domain)

        risky_tld = any(url.lower().endswith(tld) or
                        ("." + url.lower().split(".")[-1].split("/")[0]) == tld
                        for tld in RISKY_TLDS)
        # More robust TLD check
        tld_part = "." + domain.split(".")[-1].lower()
        risky_tld = tld_part in RISKY_TLDS

        try:
            domain.encode("ascii")
            has_homoglyph = any(ord(c) > 127 for c in domain)
        except UnicodeEncodeError:
            has_homoglyph = True

        is_punycode = "xn--" in domain.lower()

        url_risk_score = sum([
            depth >= 2,
            entropy > 3.5,
            ip_lit,
            risky_tld,
            has_homoglyph,
            is_punycode,
            hop_count >= 2,
        ])

        results.append({
            "url":             url,
            "domain":          domain,
            "subdomain_depth": depth,
            "domain_entropy":  round(entropy, 4),
            "has_ip_literal":  ip_lit,
            "risky_tld":       risky_tld,
            "has_homoglyph":   has_homoglyph,
            "is_punycode":     is_punycode,
            "hop_count":       hop_count,
            "url_risk_score":  url_risk_score,
        })

    return results


# TASK 3

def score_email_body(raw_email: str) -> dict:
    msg        = parse_raw_email(raw_email)
    plain_text = ""
    html_text  = ""

    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/plain":
            plain_text = part.get_payload(decode=True).decode("utf-8", errors="ignore")
        elif ct == "text/html":
            html_text  = part.get_payload(decode=True).decode("utf-8", errors="ignore")

    URGENCY_KEYWORDS = [
        "urgent", "verify", "suspended", "compromised", "immediately",
        "act now", "click here", "confirm", "unusual", "locked",
        "limited time", "expire",
    ]
    BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "google"]

    lower_plain = plain_text.lower()
    urgency_keyword_count = sum(
        lower_plain.count(kw) for kw in URGENCY_KEYWORDS
    )
    words = lower_plain.split()
    urgency_density = round(
        urgency_keyword_count / len(words) if words else 0.0, 4
    )

    anchor_pattern = re.compile(
        r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )
    anchor_href_mismatches = 0
    for href, text in anchor_pattern.findall(html_text):
        text_clean = re.sub(r"<[^>]+>", "", text).strip()
        if ("http" in text_clean or "." in text_clean) and text_clean != href:
            anchor_href_mismatches += 1

    has_base64_payload = bool(
        re.search(r"data:[^;]+;base64,", html_text, re.IGNORECASE)
    )

    from_domain = extract_from_domain(raw_email)
    combined    = (plain_text + " " + html_text).lower()
    lookalike_brands = [
        brand for brand in BRANDS
        if brand in combined and brand not in from_domain
    ]

    body_risk_score = sum([
        urgency_keyword_count >= 3,
        urgency_density > 0.02,
        anchor_href_mismatches >= 1,
        has_base64_payload,
        len(lookalike_brands) >= 1,
    ])

    return {
        "urgency_keyword_count":  urgency_keyword_count,
        "urgency_density":        urgency_density,
        "anchor_href_mismatches": anchor_href_mismatches,
        "has_base64_payload":     has_base64_payload,
        "lookalike_brands":       lookalike_brands,
        "body_risk_score":        body_risk_score,
    }


def extract_from_domain(raw_email: str) -> str:
    msg   = parse_raw_email(raw_email)
    addr  = msg.get("From", "")
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else ""

# TASK 4

def classify_phishing(
    header_results: dict,
    url_features:   list[dict],
    body_results:   dict,
    weights: dict | None = None,
) -> dict:
    if weights is None:
        weights = {"header": 0.35, "url": 0.40, "body": 0.25}

    header_score = header_results["header_risk_score"] / 6

    if url_features:
        avg_url = sum(f["url_risk_score"] for f in url_features) / len(url_features)
    else:
        avg_url = 0.0
    url_score = avg_url / 7

    body_score = body_results["body_risk_score"] / 5

    composite_score = round(
        weights["header"] * header_score
        + weights["url"]    * url_score
        + weights["body"]   * body_score,
        4
    )

    if composite_score >= 0.55:
        verdict = "PHISHING"
    elif composite_score >= 0.30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    reasoning = []
    if header_results["mismatch"]:
        reasoning.append(
            "From domain and Reply-To domain do not match — classic spoofing indicator."
        )
    if header_results["spf_result"] in ("fail", "softfail"):
        reasoning.append(
            f"SPF check returned '{header_results['spf_result']}' — sender not authorised."
        )
    if header_results["spam_flagged"]:
        reasoning.append("Email was flagged as spam by the receiving server.")
    if any(f["url_risk_score"] >= 3 for f in url_features):
        reasoning.append("One or more URLs carry multiple high-risk features.")
    if any(f["has_ip_literal"] for f in url_features):
        reasoning.append("At least one link uses a raw IP address instead of a domain name.")
    if body_results["anchor_href_mismatches"] >= 1:
        reasoning.append(
            f"{body_results['anchor_href_mismatches']} link(s) display a different URL "
            f"than their actual destination — anchor/href mismatch."
        )
    if body_results["has_base64_payload"]:
        reasoning.append("HTML body contains a base64-encoded data payload.")
    if body_results["urgency_keyword_count"] >= 3:
        reasoning.append(
            f"Body contains {body_results['urgency_keyword_count']} urgency keywords."
        )
    if not reasoning:
        reasoning.append("No significant risk factors detected.")

    return {
        "header_score":    round(header_score, 4),
        "url_score":       round(url_score, 4),
        "body_score":      round(body_score, 4),
        "composite_score": composite_score,
        "verdict":         verdict,
        "reasoning":       reasoning,
    }


# REPORT

def print_report(header_results, url_features, body_results, classification):
    SEP = "=" * 65
    sep = "-" * 65
    
    print("  LAB 3 — PHISHING DETECTION ENGINE")

    print("\n[ SECTION 1 — HEADER FORENSICS ]\n")
    print(f"  From domain   : {header_results['from_domain']}")
    print(f"  Reply-To      : {header_results['reply_to_domain']}")
    print(f"  Domain mismatch: {'YES ⚠' if header_results['mismatch'] else 'No'}")
    print(f"  SPF result    : {header_results['spf_result']}")
    print(f"  Spam-flagged  : {'YES ⚠' if header_results['spam_flagged'] else 'No'}")
    print(f"  Suspicious mailer: {'YES ⚠' if header_results['suspicious_mailer'] else 'No'}")
    print(f"  Originating IP present: {'YES ⚠' if header_results['has_originating_ip'] else 'No'}")
    print(f"\n  Header risk score : {header_results['header_risk_score']} / 6")

    print(f"\n{sep}")
    print("[ SECTION 2 — URL & BODY ANALYSIS ]\n")
    print("  URLs analysed:")
    for i, f in enumerate(url_features, 1):
        print(f"\n  [{i}] {f['url'][:70]}")
        print(f"      Domain entropy : {f['domain_entropy']:.4f}")
        print(f"      Subdomain depth: {f['subdomain_depth']}")
        print(f"      IP literal     : {'YES ⚠' if f['has_ip_literal'] else 'No'}")
        print(f"      Risky TLD      : {'YES ⚠' if f['risky_tld'] else 'No'}")
        print(f"      Homoglyph chars: {'YES ⚠' if f['has_homoglyph'] else 'No'}")
        print(f"      Punycode       : {'YES ⚠' if f['is_punycode'] else 'No'}")
        print(f"      Redirect hops  : {f['hop_count']}")
        print(f"      URL risk score : {f['url_risk_score']} / 7")

    print(f"\n  Body indicators:")
    print(f"    Urgency keywords    : {body_results['urgency_keyword_count']}")
    print(f"    Urgency density     : {body_results['urgency_density']:.4f}")
    print(f"    Anchor/href mismatches: {body_results['anchor_href_mismatches']}")
    print(f"    Base64 payload      : {'YES ⚠' if body_results['has_base64_payload'] else 'No'}")
    print(f"    Lookalike brands    : {body_results['lookalike_brands']}")
    print(f"\n    Body risk score : {body_results['body_risk_score']} / 5")

    print(f"\n{sep}")
    print("[ SECTION 3 — FINAL CLASSIFICATION ]\n")
    print(f"  Header score  : {classification['header_score']:.4f}")
    print(f"  URL score     : {classification['url_score']:.4f}")
    print(f"  Body score    : {classification['body_score']:.4f}")
    print(f"  Composite     : {classification['composite_score']:.4f}")
    print(f"\n  ▶  VERDICT: {classification['verdict']}")
    print("\n  Reasoning:")
    for line in classification["reasoning"]:
        print(f"    • {line}")


if __name__ == "__main__":
    import email_generator
    eml_path, cache_path = email_generator.generate()
    print(f"Generated email : {eml_path}")
    print(f"URL cache       : {cache_path}\n")
    raw       = load_email(eml_path)
    url_cache = load_url_cache(cache_path)
    headers        = parse_email_headers(raw)
    url_features   = analyze_url_features(url_cache)
    body           = score_email_body(raw)
    classification = classify_phishing(headers, url_features, body)
    print_report(headers, url_features, body, classification)