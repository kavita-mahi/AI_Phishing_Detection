import re
import string
import ipaddress
import math
from urllib.parse import urlparse


FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsHTTPS",
    "IsDomainIP",
    "NoOfSubDomain",
    "TLDLength",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "LetterRatioInURL",
    "DegitRatioInURL",
    "SpacialCharRatioInURL"
]


def extract_url_features(url):

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please enter a valid URL.")

    original_url = url.strip()

    if not re.match(r"^https?://", original_url, re.IGNORECASE):
        original_url = "https://" + original_url

    parsed = urlparse(original_url)

    hostname = parsed.hostname or ""

    if not hostname:
        raise ValueError("Invalid URL: domain not found.")

    # Remove scheme and optional www for lexical counting
    url_body = re.sub(
        r"^https?://",
        "",
        original_url,
        flags=re.IGNORECASE
    )

    url_body = re.sub(
        r"^www\.",
        "",
        url_body,
        flags=re.IGNORECASE
    )

    features = {}

    # 1. URL length
    features["URLLength"] = len(original_url)

    # 2. Domain length
    features["DomainLength"] = len(hostname)

    # 3. HTTPS
    features["IsHTTPS"] = int(
        parsed.scheme.lower() == "https"
    )

    # 4. IP address
    try:
        ipaddress.ip_address(hostname)
        features["IsDomainIP"] = 1
    except ValueError:
        features["IsDomainIP"] = 0

    # 5. Subdomains
    domain_parts = hostname.split(".")

    features["NoOfSubDomain"] = max(
        0, len(domain_parts) - 2
    )

    # 6. TLD length
    features["TLDLength"] = (
        len(domain_parts[-1]) if domain_parts else 0
    )

    # 7. Obfuscation
    encoded_chars = re.findall(
        r"%[0-9a-fA-F]{2}",
        original_url
    )

    obfuscated_count = (
        len(encoded_chars) + original_url.count("@")
    )

    features["HasObfuscation"] = int(
        obfuscated_count > 0
    )

    features["NoOfObfuscatedChar"] = obfuscated_count

    # 8. Obfuscation ratio
    denominator = max(len(original_url), 1)

    features["ObfuscationRatio"] = (
        obfuscated_count / denominator
    )

    # 9. Character counts
    letter_count = sum(
        char.isalpha() for char in url_body
    )

    digit_count = sum(
        char.isdigit() for char in url_body
    )

    features["NoOfLettersInURL"] = letter_count

    features["NoOfDegitsInURL"] = digit_count

    features["NoOfEqualsInURL"] = original_url.count("=")

    features["NoOfQMarkInURL"] = original_url.count("?")

    features["NoOfAmpersandInURL"] = original_url.count("&")

    features["NoOfOtherSpecialCharsInURL"] = sum(
        char in string.punctuation
        for char in url_body
        if char not in "=?&"
    )

    # 10. Ratios
    features["LetterRatioInURL"] = (
        letter_count / denominator
    )

    features["DegitRatioInURL"] = (
        digit_count / denominator
    )

    features["SpacialCharRatioInURL"] = (
        features["NoOfOtherSpecialCharsInURL"]
        / denominator
    )

    # 11. Ensure correct feature order and valid numbers
    features = {
        name: features[name]
        for name in FEATURE_COLUMNS
    }

    if not all(math.isfinite(value) for value in features.values()):
        raise ValueError("Invalid numerical feature generated.")

    return features


if __name__ == "__main__":

    test_url = "https://www.southbankmosaics.com"

    result = extract_url_features(test_url)

    print("\nExtracted URL Features:\n")

    for name, value in result.items():
        print(f"{name}: {value}")

    print("\nTotal Features:", len(result))