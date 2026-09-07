"""
Lab 3 — Phishing Detection Engine
"""

import re
import math
import json
import base64
from email import message_from_string


# ── Helpers (do not modify) 

def load_email(path="sample_email.eml"):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def load_url_cache(path="url_cache.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def parse_raw_email(raw):
    return message_from_string(raw)


# ── Task 1 — Header Analysis 
# Read the email headers and return this dict:
#
#   from_domain        str   domain after @ in From
#   reply_to_domain    str   domain after @ in Reply-To
#   mismatch           bool  True if the two domains differ
#   spf_result         str   "pass" | "fail" | "softfail" | "neutral" | "unknown"
#   spam_flagged       bool  True if X-Spam-Status contains "yes"
#   suspicious_mailer  bool  True if X-Mailer contains "bulk","phpmailer","mass","sendgrid"
#   has_originating_ip bool  True if X-Originating-IP header exists
#   header_risk_score  int   0-6  (one point each for the 6 risk conditions)
#                             mismatch, spf in (fail/softfail), spf==neutral,
#                             spam_flagged, suspicious_mailer, has_originating_ip

def parse_email_headers(raw_email):
    msg = parse_raw_email(raw_email)

    def extract_domain(addr):
        # TODO
        pass

    from_domain        = None  # TODO
    reply_to_domain    = None  # TODO
    mismatch           = None  # TODO
    spf_result         = None  # TODO
    spam_flagged       = None  # TODO
    suspicious_mailer  = None  # TODO
    has_originating_ip = None  # TODO
    header_risk_score  = None  # TODO

    return {
        "from_domain": from_domain, "reply_to_domain": reply_to_domain,
        "mismatch": mismatch, "spf_result": spf_result,
        "spam_flagged": spam_flagged, "suspicious_mailer": suspicious_mailer,
        "has_originating_ip": has_originating_ip,
        "header_risk_score": header_risk_score,
    }


# ── Task 2 — URL Feature Analysis ────────────────────────────────────────────
# For each URL in the cache return a list of dicts with these keys:
#
#   url             str   original URL
#   domain          str   host extracted from URL
#   subdomain_depth int   labels above the registered domain
#                         e.g. secure.login.paypal.com → 2
#   domain_entropy  float Shannon entropy of the label before the first dot
#                         formula: -sum(p * log2(p)) per unique character
#   has_ip_literal  bool  True if host is a raw IPv4  e.g. 192.168.1.1
#   risky_tld       bool  True if TLD in {.ru .tk .xyz .top .club .pw .gq}
#   has_homoglyph   bool  True if domain has non-ASCII characters
#   is_punycode     bool  True if domain contains "xn--"
#   hop_count       int   from cache
#   url_risk_score  int   0-7  (one point each for the 7 risk conditions)
#                          subdomain_depth >= 2, domain_entropy > 3.5,
#                          has_ip_literal, risky_tld, has_homoglyph,
#                          is_punycode, hop_count >= 2

def analyze_url_features(url_cache):

    def extract_domain(url):
        pass  # TODO

    def subdomain_depth(domain):
        pass  # TODO

    def shannon_entropy(text):
        pass  # TODO

    def is_ip_literal(host):
        pass  # TODO

    RISKY_TLDS = {".ru", ".tk", ".xyz", ".top", ".club", ".pw", ".gq"}

    results = []
    for entry in url_cache.get("urls", []):
        url       = entry["original_url"]
        hop_count = entry["hop_count"]

        domain         = None  # TODO
        depth          = None  # TODO
        entropy        = None  # TODO
        ip_lit         = None  # TODO
        risky_tld      = None  # TODO
        has_homoglyph  = None  # TODO
        is_punycode    = None  # TODO
        url_risk_score = None  # TODO

        results.append({
            "url": url, "domain": domain,
            "subdomain_depth": depth, "domain_entropy": entropy,
            "has_ip_literal": ip_lit, "risky_tld": risky_tld,
            "has_homoglyph": has_homoglyph, "is_punycode": is_punycode,
            "hop_count": hop_count, "url_risk_score": url_risk_score,
        })

    return results


# ── Task 3 — Body Scoring ─────────────────────────────────────────────────────
# Analyse the email body and return this dict:
#
#   urgency_keyword_count  int   count of urgency words in plain text
#                                words: urgent verify suspended compromised
#                                immediately act now click here confirm
#                                unusual locked limited time expire
#   urgency_density        float count / total words  (4 decimal places)
#   anchor_href_mismatches int   <a> tags where visible text looks like a URL
#                                but differs from href
#   has_base64_payload     bool  True if HTML contains  data:...;base64,
#   lookalike_brands       list  brands in body not found in From domain
#                                brands: paypal amazon microsoft apple netflix google
#   body_risk_score        int   0-5  (one point each for the 5 risk conditions)
#                                1. urgency_keyword_count >= 3
#                                2. urgency_density > 0.02
#                                3. anchor_href_mismatches >= 1
#                                4. has_base64_payload is True
#                                5. len(lookalike_brands) >= 1
def score_email_body(raw_email):
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

    urgency_keyword_count  = None  # TODO
    urgency_density        = None  # TODO
    anchor_href_mismatches = None  # TODO
    has_base64_payload     = None  # TODO
    lookalike_brands       = None  # TODO
    body_risk_score        = None  # TODO

    return {
        "urgency_keyword_count": urgency_keyword_count,
        "urgency_density": urgency_density,
        "anchor_href_mismatches": anchor_href_mismatches,
        "has_base64_payload": has_base64_payload,
        "lookalike_brands": lookalike_brands,
        "body_risk_score": body_risk_score,
    }


def extract_from_domain(raw_email):
    msg   = parse_raw_email(raw_email)
    addr  = msg.get("From", "")
    match = re.search(r"@([\w.\-]+)", addr)
    return match.group(1).lower() if match else ""


# ── Task 4 — Final Classification ────────────────────────────────────────────
# Combine the three scores into a verdict.
#
# Normalize:
#   header_score = header_risk_score / 6
#   url_score    = average(url_risk_scores) / 7   (0 if empty)
#   body_score   = body_risk_score / 5
#
# Composite:
#   composite = (0.35 * header_score) + (0.40 * url_score) + (0.25 * body_score)
#   custom weights accepted via the weights parameter
#
# Verdict:
#   >= 0.55 → "PHISHING"
#   >= 0.30 → "SUSPICIOUS"
#   else    → "CLEAN"
#
# Return dict keys:
#   header_score  url_score  body_score  composite_score  verdict  reasoning
#   reasoning = list of strings, one per active risk factor
#               if none fired: ["No significant risk factors detected."]

def classify_phishing(header_results, url_features, body_results, weights=None):
    if weights is None:
        weights = {"header": 0.35, "url": 0.40, "body": 0.25}

    header_score    = None  # TODO
    url_score       = None  # TODO
    body_score      = None  # TODO
    composite_score = None  # TODO
    verdict         = None  # TODO
    reasoning       = []    # TODO

    return {
        "header_score": header_score, "url_score": url_score,
        "body_score": body_score, "composite_score": composite_score,
        "verdict": verdict, "reasoning": reasoning,
    }


# ── Report (do not modify) ────────────────────────────────────────────────────

def print_report(header_results, url_features, body_results, classification):
    SEP = "=" * 65
    sep = "-" * 65
    print(f"\n{SEP}\n  LAB 3 — PHISHING DETECTION ENGINE\n{SEP}")

    print("\n[ SECTION 1 — HEADER FORENSICS ]\n")
    print(f"  From domain      : {header_results['from_domain']}")
    print(f"  Reply-To         : {header_results['reply_to_domain']}")
    print(f"  Domain mismatch  : {'YES ⚠' if header_results['mismatch'] else 'No'}")
    print(f"  SPF result       : {header_results['spf_result']}")
    print(f"  Spam-flagged     : {'YES ⚠' if header_results['spam_flagged'] else 'No'}")
    print(f"  Suspicious mailer: {'YES ⚠' if header_results['suspicious_mailer'] else 'No'}")
    print(f"  Originating IP   : {'YES ⚠' if header_results['has_originating_ip'] else 'No'}")
    print(f"\n  Header risk score : {header_results['header_risk_score']} / 6")

    print(f"\n{sep}\n[ SECTION 2 — URL & BODY ANALYSIS ]\n\n  URLs analysed:")
    for i, f in enumerate(url_features, 1):
        print(f"\n  [{i}] {f['url'][:70]}")
        print(f"      Entropy        : {f['domain_entropy']:.4f}")
        print(f"      Subdomain depth: {f['subdomain_depth']}")
        print(f"      IP literal     : {'YES ⚠' if f['has_ip_literal'] else 'No'}")
        print(f"      Risky TLD      : {'YES ⚠' if f['risky_tld'] else 'No'}")
        print(f"      Homoglyph      : {'YES ⚠' if f['has_homoglyph'] else 'No'}")
        print(f"      Punycode       : {'YES ⚠' if f['is_punycode'] else 'No'}")
        print(f"      Redirect hops  : {f['hop_count']}")
        print(f"      URL risk score : {f['url_risk_score']} / 7")

    print(f"\n  Body indicators:")
    print(f"    Urgency keywords      : {body_results['urgency_keyword_count']}")
    print(f"    Urgency density       : {body_results['urgency_density']:.4f}")
    print(f"    Anchor/href mismatches: {body_results['anchor_href_mismatches']}")
    print(f"    Base64 payload        : {'YES ⚠' if body_results['has_base64_payload'] else 'No'}")
    print(f"    Lookalike brands      : {body_results['lookalike_brands']}")
    print(f"\n    Body risk score : {body_results['body_risk_score']} / 5")

    print(f"\n{sep}\n[ SECTION 3 — FINAL CLASSIFICATION ]\n")
    print(f"  Header score : {classification['header_score']:.4f}")
    print(f"  URL score    : {classification['url_score']:.4f}")
    print(f"  Body score   : {classification['body_score']:.4f}")
    print(f"  Composite    : {classification['composite_score']:.4f}")
    print(f"\n  ▶  VERDICT: {classification['verdict']}\n\n  Reasoning:")
    for line in classification["reasoning"]:
        print(f"    • {line}")
    print(f"\n{SEP}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import email_generator
    eml_path, cache_path = email_generator.generate()
    print(f"Generated email : {eml_path}")
    print(f"URL cache       : {cache_path}\n")

    raw            = load_email(eml_path)
    url_cache      = load_url_cache(cache_path)
    headers        = parse_email_headers(raw)
    url_features   = analyze_url_features(url_cache)
    body           = score_email_body(raw)
    classification = classify_phishing(headers, url_features, body)
    print_report(headers, url_features, body, classification)