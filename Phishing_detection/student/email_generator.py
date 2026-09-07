
import random
import json
import hashlib
import time
import os
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

RUN_SEED = int(hashlib.md5(str(time.time()).encode()).hexdigest(), 16) % (2**32)
random.seed(RUN_SEED)

# Data pools

LEGIT_BRANDS = ["paypal", "amazon", "microsoft", "apple", "netflix", "google"]

LEGIT_DOMAINS = {
    "paypal":    "paypal.com",
    "amazon":    "amazon.com",
    "microsoft": "microsoft.com",
    "apple":     "apple.com",
    "netflix":   "netflix.com",
    "google":    "google.com",
}

# Homoglyph / typosquatting substitutions used in phishing domains
HOMOGLYPHS = {
    "a": ["а", "ɑ", "4"],   # cyrillic а, latin script ɑ, digit 4
    "e": ["е", "3"],          # cyrillic е
    "o": ["о", "0"],          # cyrillic о
    "i": ["і", "1", "l"],     # cyrillic і
    "l": ["1", "I"],
    "p": ["р"],               # cyrillic р
    "n": ["и"],               # cyrillic и
}

PHISHING_TLDS = [".ru", ".tk", ".xyz", ".top", ".club", ".pw", ".gq"]
LEGIT_TLDS    = [".com", ".org", ".net", ".co.uk", ".io"]

URGENCY_PHRASES = [
    "Your account has been compromised.",
    "Immediate action required.",
    "Verify your identity within 24 hours or your account will be suspended.",
    "Unusual sign-in activity detected.",
    "URGENT: Your payment failed.",
    "Act now to avoid account termination.",
    "Security alert: unauthorized access attempt.",
]

CLEAN_PHRASES = [
    "Thank you for your recent purchase.",
    "Your monthly statement is now available.",
    "Here is your order confirmation.",
    "We wanted to share some updates with you.",
    "Your subscription has been renewed successfully.",
]


# URL builders

def _make_legit_url(brand: str) -> str:
    domain = LEGIT_DOMAINS[brand]
    paths = ["/account/verify", "/security/login", "/orders/recent",
             "/help/billing", "/profile/update"]
    return f"https://www.{domain}{random.choice(paths)}"


def _make_phishing_url(brand: str, technique: str) -> str:

    if technique == "homoglyph":
        name = brand
        for char, replacements in HOMOGLYPHS.items():
            if char in name:
                name = name.replace(char, random.choice(replacements), 1)
                break
        tld = random.choice(PHISHING_TLDS)
        return f"https://www.{name}{tld}/secure/verify"

    elif technique == "subdomain":
        tld = random.choice(PHISHING_TLDS)
        subdepth = random.randint(2, 4)
        subs = ".".join([brand] + [f"secure{i}" for i in range(subdepth - 1)])
        return f"https://{subs}.malicious{tld}/login"

    elif technique == "path-spoof":
        tld = random.choice(PHISHING_TLDS)
        rand_domain = "".join(random.choices("abcdefghijklmnop", k=8))
        return f"https://{rand_domain}{tld}/{brand}/account/verify"

    elif technique == "ip-literal":
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"http://{ip}/{brand}/login.php"

    elif technique == "punycode":
        # Simulate a punycode domain (pre-encoded for display)
        name = brand
        for char, replacements in HOMOGLYPHS.items():
            if char in name:
                encoded = base64.b64encode(name.encode()).decode()[:8].lower()
                return f"https://xn--{encoded}.com/secure/{brand}"
        return f"https://xn--{brand}0.com/login"

    # fallback
    return _make_phishing_url(brand, "subdomain")


def _build_redirect_chain(final_url: str, is_phishing: bool) -> list[dict]:
    chain = []
    if not is_phishing or random.random() < 0.3:
        chain.append({"url": final_url, "status_code": 200,
                       "is_redirect": False})
        return chain

    hops = random.randint(1, 3)
    for i in range(hops):
        rand = "".join(random.choices("abcdefghijklmnop0123456789", k=10))
        hop_tld = random.choice(PHISHING_TLDS)
        hop_url = f"https://redir-{rand}{hop_tld}/go?u={i}"
        chain.append({"url": hop_url, "status_code": 302,
                       "is_redirect": True})
    chain.append({"url": final_url, "status_code": 200,
                   "is_redirect": False})
    return chain

# Header builders

def _make_headers(brand: str, is_phishing: bool) -> dict:
    legit_domain = LEGIT_DOMAINS[brand]

    if is_phishing:
        technique = random.choice(["reply-to-mismatch", "display-name-spoof",
                                    "x-mailer-spoof", "received-chain-fake"])
        sender_domain = "".join(random.choices("abcdefghi", k=7)) \
                        + random.choice(PHISHING_TLDS)

        headers = {
            "From":     f'"{brand.title()} Support" <noreply@{legit_domain}>',
            "Reply-To": f"support@{sender_domain}",
            "X-Mailer": random.choice(["BulkMailer 3.0", "PHPMailer 5.2",
                                        "SendGrid-spoof/1.0"]),
        }
        if technique == "received-chain-fake":
            headers["X-Originating-IP"] = ".".join(
                str(random.randint(1, 254)) for _ in range(4))
            headers["Received-SPF"] = "fail"
        else:
            headers["Received-SPF"] = random.choice(["softfail", "neutral"])

        headers["X-Spam-Status"] = random.choice(["Yes", "unknown"])
        headers["_sender_domain"] = sender_domain   # metadata for analysis
        headers["_is_phishing"]   = True

    else:
        headers = {
            "From":       f'"no-reply" <noreply@{legit_domain}>',
            "Reply-To":   f"support@{legit_domain}",
            "X-Mailer":   "Postfix MTA",
            "Received-SPF": "pass",
            "X-Spam-Status": "No",
            "_sender_domain": legit_domain,
            "_is_phishing":   False,
        }

    return headers


# Body builder

def _make_body(brand: str, urls: list[str], is_phishing: bool) -> tuple[str, str]:
    if is_phishing:
        opener = random.choice(URGENCY_PHRASES)
        cta    = "Verify My Account Now"
    else:
        opener = random.choice(CLEAN_PHRASES)
        cta    = "View Details"

    url1 = urls[0] if urls else "#"
    url2 = urls[1] if len(urls) > 1 else url1

    if is_phishing and random.random() < 0.7:
        display_url = f"https://www.{LEGIT_DOMAINS[brand]}/secure/verify"
        real_url    = url1
    else:
        display_url = url1
        real_url    = url1

    plain = (
        f"Dear Customer,\n\n"
        f"{opener}\n\n"
        f"Please {cta.lower()} at the following link:\n{display_url}\n\n"
        f"Regards,\n{brand.title()} Support Team"
    )

    hidden_block = ""
    if is_phishing and random.random() < 0.5:
        payload = f"tracking_id={RUN_SEED}&brand={brand}&harvest=email,password"
        encoded = base64.b64encode(payload.encode()).decode()
        hidden_block = (
            f'\n<div style="display:none">'
            f'<img src="data:text/plain;base64,{encoded}" /></div>'
        )

    html = (
        f"<html><body>"
        f"<p>Dear Customer,</p>"
        f"<p>{opener}</p>"
        f'<p><a href="{real_url}">{cta}</a></p>'
        f'<p>Or copy this link: <a href="{display_url}">{display_url}</a></p>'
        f"{hidden_block}"
        f"<p>Regards,<br>{brand.title()} Support Team</p>"
        f"</body></html>"
    )

    return plain, html

# Main generator

def generate(output_dir: str = ".") -> tuple[str, str]:
    is_phishing = random.random() < 0.6
    brand = random.choice(LEGIT_BRANDS)
    technique = random.choice(["homoglyph", "subdomain", "path-spoof",
                                "ip-literal", "punycode"])

    # Build 3-5 URLs: mix of legit and phishing
    num_urls = random.randint(3, 5)
    urls = []
    url_meta = []

    for i in range(num_urls):
        use_phishing_url = is_phishing and (i < num_urls - 1 or random.random() < 0.8)
        if use_phishing_url:
            url = _make_phishing_url(brand, technique)
            chain = _build_redirect_chain(url, is_phishing=True)
        else:
            url = _make_legit_url(brand)
            chain = _build_redirect_chain(url, is_phishing=False)

        urls.append(url)
        url_meta.append({
            "original_url":    url,
            "redirect_chain":  chain,
            "final_url":       chain[-1]["url"],
            "hop_count":       len(chain) - 1,
            "crosses_tld":     any(
                any(tld in hop["url"] for tld in PHISHING_TLDS)
                for hop in chain
            ),
        })

    # Build headers and body
    raw_headers = _make_headers(brand, is_phishing)
    plain, html  = _make_body(brand, urls, is_phishing)

    # Assemble MIME message
    msg = MIMEMultipart("alternative")
    msg["Subject"]    = (
        f"[{'URGENT' if is_phishing else 'INFO'}] "
        f"{'Action required' if is_phishing else 'Account update'} — {brand.title()}"
    )
    msg["From"]       = raw_headers["From"]
    msg["To"]         = "student@university.edu"
    msg["Reply-To"]   = raw_headers["Reply-To"]
    msg["Date"]       = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=raw_headers["_sender_domain"])
    msg["X-Mailer"]   = raw_headers["X-Mailer"]
    msg["Received-SPF"]   = raw_headers["Received-SPF"]
    msg["X-Spam-Status"]  = raw_headers["X-Spam-Status"]

    if "X-Originating-IP" in raw_headers:
        msg["X-Originating-IP"] = raw_headers["X-Originating-IP"]

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    eml_path   = os.path.join(output_dir, "sample_email.eml")
    cache_path = os.path.join(output_dir, "url_cache.json")

    with open(eml_path, "w", encoding="utf-8") as f:
        f.write(msg.as_string())

    cache = {
        "run_seed":    RUN_SEED,
        "brand":       brand,
        "is_phishing": is_phishing,   # ground truth — used by test suite only
        "technique":   technique if is_phishing else "none",
        "urls":        url_meta,
    }
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)

    return eml_path, cache_path


if __name__ == "__main__":
    eml, cache = generate()
    print(f"Generated: {eml}")
    print(f"URL cache: {cache}")