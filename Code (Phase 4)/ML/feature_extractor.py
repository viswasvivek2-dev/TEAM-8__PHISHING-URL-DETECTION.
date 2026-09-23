import re
import urllib.parse
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup

def extract_features(url: str, fetch_html: bool = False, timeout: float = 2.0) -> pd.DataFrame:
    """
    Extracts all URL-level and HTML-level features expected by the
    PhiUSIIL Phishing URL machine learning model.
    """
    original_url = url.strip()
    if not re.match(r"^https?://", original_url, re.IGNORECASE):
        target_url = "http://" + original_url
    else:
        target_url = original_url

    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc.lower()
    if ":" in domain:
        domain = domain.split(":")[0]

    domain_parts = domain.split(".")
    tld = domain_parts[-1] if len(domain_parts) > 1 else "unknown"

    clean_url = re.sub(r"^https?://(www\.)?", "", original_url)
    url_len = len(original_url)
    domain_len = len(domain)
    tld_len = len(tld)
    num_subdomains = max(0, len(domain_parts) - 2)

    letters = max(0, len(re.findall(r"[a-zA-Z]", clean_url)) - 1)
    digits = len(re.findall(r"[0-9]", clean_url))
    equals = original_url.count("=")
    qmarks = original_url.count("?")
    ampersands = original_url.count("&")
    other_special = len(re.findall(r"[^a-zA-Z0-9=?&]", clean_url))

    letter_ratio = letters / url_len if url_len > 0 else 0.0
    digit_ratio = digits / url_len if url_len > 0 else 0.0
    special_ratio = other_special / url_len if url_len > 0 else 0.0

    is_domain_ip = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    has_obfuscation = 1 if "%" in original_url else 0
    num_obfuscated = original_url.count("%")
    obfuscation_ratio = num_obfuscated / url_len if url_len > 0 else 0.0
    is_https = 1 if original_url.lower().startswith("https://") else 0

    title = ""
    line_of_code = np.nan
    largest_line_len = np.nan
    has_title = np.nan
    has_favicon = np.nan
    has_description = np.nan
    num_iframe = np.nan
    has_password = np.nan
    has_submit = np.nan
    has_hidden = np.nan
    has_external_form = np.nan
    has_social = np.nan
    bank = np.nan
    pay = np.nan
    crypto = np.nan
    has_copyright = np.nan
    num_image = np.nan
    num_css = np.nan
    num_js = np.nan

    if fetch_html:
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            resp = requests.get(target_url, timeout=timeout, headers=headers)
            html = resp.text
            lines = html.splitlines()
            line_of_code = len(lines)
            largest_line_len = max([len(l) for l in lines]) if lines else 0

            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
                has_title = 1
            else:
                has_title = 0

            has_favicon = 1 if soup.find("link", rel=lambda x: x and "icon" in x.lower()) else 0
            has_description = 1 if soup.find("meta", attrs={"name": re.compile(r"description", re.I)}) else 0
            num_iframe = len(soup.find_all("iframe"))
            has_password = 1 if soup.find("input", attrs={"type": "password"}) else 0
            has_submit = 1 if soup.find(["input", "button"], attrs={"type": "submit"}) else 0
            has_hidden = 1 if soup.find("input", attrs={"type": "hidden"}) else 0

            has_external_form = 0
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action.startswith("http") and domain not in action:
                    has_external_form = 1
                    break

            text_lower = html.lower()
            bank = 1 if "bank" in text_lower else 0
            pay = 1 if ("pay" in text_lower or "paypal" in text_lower) else 0
            crypto = 1 if ("crypto" in text_lower or "bitcoin" in text_lower) else 0
            has_copyright = 1 if ("copyright" in text_lower or "©" in html) else 0

            has_social = 1 if any(s in text_lower for s in ["facebook.com", "twitter.com", "linkedin.com", "instagram.com"]) else 0
            num_image = len(soup.find_all("img"))
            num_css = len(soup.find_all("link", rel="stylesheet")) + len(soup.find_all("style"))
            num_js = len(soup.find_all("script"))
        except Exception:
            pass

    domain_title_match = 100.0 if not is_domain_ip else 0.0
    url_title_match = 100.0 if not is_domain_ip else 0.0

    feat_num_dots = original_url.count(".")
    feat_num_hyphen = original_url.count("-")
    feat_num_underscore = original_url.count("_")
    feat_path_depth = original_url.count("/")
    feat_has_at = 1 if "@" in original_url else 0
    feat_has_shortener = 1 if re.search(r"(?:bit\.ly|goo\.gl|tinyurl|t\.co)", original_url, re.I) else 0

    record = {
        "url": original_url,
        "title": title,
        "tld": tld,
        "urllength": url_len,
        "domainlength": domain_len,
        "isdomainip": is_domain_ip,
        "urlsimilarityindex": 100.0 if not is_domain_ip else 0.0,
        "charcontinuationrate": 1.0 if not is_domain_ip else 0.5,
        "tldlegitimateprob": 0.52 if tld in ["com", "org", "net", "edu", "gov", "in", "uk", "de"] else 0.038,
        "urlcharprob": 0.06 if not is_domain_ip else 0.02,
        "tldlength": tld_len,
        "noofsubdomain": num_subdomains,
        "hasobfuscation": has_obfuscation,
        "noofobfuscatedchar": num_obfuscated,
        "obfuscationratio": obfuscation_ratio,
        "nooflettersinurl": letters,
        "letterratioinurl": letter_ratio,
        "noofdegitsinurl": digits,
        "degitratioinurl": digit_ratio,
        "noofequalsinurl": equals,
        "noofqmarkinurl": qmarks,
        "noofampersandinurl": ampersands,
        "noofotherspecialcharsinurl": other_special,
        "spacialcharratioinurl": special_ratio,
        "ishttps": is_https,
        "lineofcode": line_of_code,
        "largestlinelength": largest_line_len,
        "hastitle": has_title,
        "domaintitlematchscore": domain_title_match,
        "urltitlematchscore": url_title_match,
        "hasfavicon": has_favicon,
        "robots": np.nan,
        "isresponsive": np.nan,
        "noofurlredirect": 0,
        "noofselfredirect": 0,
        "hasdescription": has_description,
        "noofpopup": np.nan,
        "noofiframe": num_iframe,
        "hasexternalformsubmit": has_external_form,
        "hassocialnet": has_social,
        "hassubmitbutton": has_submit,
        "hashiddenfields": has_hidden,
        "haspasswordfield": has_password,
        "bank": bank,
        "pay": pay,
        "crypto": crypto,
        "hascopyrightinfo": has_copyright,
        "noofimage": num_image,
        "noofcss": num_css,
        "noofjs": num_js,
        "noofselfref": np.nan,
        "noofemptyref": np.nan,
        "noofexternalref": np.nan,
        "feat_num_dots": feat_num_dots,
        "feat_num_hyphen": feat_num_hyphen,
        "feat_num_underscore": feat_num_underscore,
        "feat_path_depth": feat_path_depth,
        "feat_has_at": feat_has_at,
        "feat_has_shortener": feat_has_shortener,
    }

    return pd.DataFrame([record])
