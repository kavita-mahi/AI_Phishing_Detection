import streamlit as st
import joblib
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import difflib

model = joblib.load("phishing_model_simple.pkl")
feature_cols = joblib.load("feature_columns_simple.pkl")

PHISHING_ROW = 2   # keep your verified working row numbers
LEGIT_ROW = 0

st.set_page_config(page_title="AI-Powered Phishing Website Detection", layout="centered")

# ---- Custom CSS for a more polished look ----
st.markdown("""
<style>

.stApp{
    background: linear-gradient(135deg,#F9A8D4 0%,#FCD34D 50%,#F9A8D4 100%);
}

/* Main white container */
.main-card{
    background:white;
    padding:35px;
    border-radius:20px;
    box-shadow:0 8px 25px rgba(0,0,0,0.15);
    max-width:900px;
    margin:auto;
}

/* Title */
.main-title{
    text-align:center;
    color:#1E3A8A;
    font-size:2.6rem;
    font-weight:800;
    margin-bottom:8px;
}

/* Subtitle */
.subtitle{
    text-align:center;
    color:#64748B;
    font-size:1.1rem;
    margin-bottom:30px;
}

/* Section headings */
.section-title{
    font-size:22px;
    color:#1E3A8A;
    font-weight:700;
    margin-top:25px;
    margin-bottom:15px;
}

/* Buttons */
div.stButton > button{
    border-radius:10px;
    height:48px;
    font-size:17px;
    font-weight:600;
}

/* Footer */
.footer{
    text-align:center;
    color:#666;
    margin-top:40px;
    font-size:14px;
}

.result-box{
    padding:20px;
    border-radius:12px;
    text-align:center;
    font-size:22px;
    font-weight:bold;
}

</style>
""", unsafe_allow_html=True)

# ---- Header ----
st.markdown("<div class='main-title'> AI-Powered Phishing Website Detection</div>", unsafe_allow_html=True)
st.markdown("<div class='subtitle'>Real-Time AI Detection Using Machine Learning and URL Feature Analysis</div>", unsafe_allow_html=True)

BINARY_FEATURES = {"IsHTTPS", "HasPasswordField", "HasFavicon"}

for col in feature_cols:
    if col not in st.session_state:
        st.session_state[col] = False if col in BINARY_FEATURES else 0.0


# =========================================================
# LIVE FEATURE EXTRACTION FUNCTION
# =========================================================
def extract_features_from_url(url):
    """
    Fetches a live URL and extracts the 7 features used by the model.
    Returns a dict of feature_name -> value, or raises an Exception on failure.
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url  # let IsHTTPS reflect what the site actually redirects to

    headers = {"User-Agent": "Mozilla/5.0 (compatible; PhishingDetectorBot/1.0)"}
    response = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
    final_url = response.url
    parsed = urlparse(final_url)
    html = response.text[:100000]
    soup = BeautifulSoup(html, "lxml")

    features = {}

    # 1. URLLength
    features["URLLength"] = len(final_url)

    # 2. NoOfSubDomain
    domain_parts = parsed.netloc.split(".")
    # e.g. "www.mail.example.com" -> 4 parts -> subdomains = parts - 2 (domain + tld)
    features["NoOfSubDomain"] = max(len(domain_parts) - 2, 0)

    # 3. IsHTTPS
    features["IsHTTPS"] = 1 if parsed.scheme == "https" else 0

    # 4. NoOfURLRedirect
    features["NoOfURLRedirect"] = len(response.history)

    # 5. DomainTitleMatchScore (fuzzy match domain name vs <title> tag)
    title_tag = soup.title
    title_text = title_tag.get_text().strip().lower() if title_tag else ""
    domain_main = domain_parts[-2] if len(domain_parts) >= 2 else parsed.netloc
    domain_main = domain_main.lower()
    if title_text:
        match_score = difflib.SequenceMatcher(None, domain_main, title_text).ratio()
    else:
        match_score = 0.0
    features["DomainTitleMatchScore"] = round(match_score * 100, 2)

    # 6. HasPasswordField
    password_input = soup.find("input", {"type": "password"})
    features["HasPasswordField"] = 1 if password_input else 0

    # 7. HasFavicon
    favicon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
    features["HasFavicon"] = 1 if favicon_link else 0

    return features


# =========================================================
# LIVE URL SCAN SECTION
# =========================================================
st.markdown(
    '<div class="section-title"> Scan a Live Website</div>',
    unsafe_allow_html=True
)
live_url = st.text_input("Enter a website URL to scan", placeholder="e.g. https://example.com")

scan_col1, scan_col2 = st.columns([1, 1])
with scan_col1:
    scan_clicked = st.button(" Scan URL",
        type="primary",
        use_container_width=True
        )

if scan_clicked:
    if not live_url.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Fetching page and extracting features..."):
            try:
                extracted = extract_features_from_url(live_url.strip())
                for col in feature_cols:
                    if col in extracted:
                        st.session_state[col] = bool(extracted[col]) if col in BINARY_FEATURES else float(extracted[col])
                st.success("Features extracted successfully — scroll down to see values and click Analyze.")
                with st.expander("🔍 Extracted feature values"):
                    st.json(extracted)
            except requests.exceptions.ConnectionError:
                st.error(
                    "🚫 This website couldn't be found. The domain doesn't seem to exist or isn't "
                    "currently registered — when we tried to look it up, there was no record of it at all.\n\n"
                    "This is actually a common phishing pattern: attackers register a lookalike domain, "
                    "use it briefly, and it disappears or was never fully live. If you found this URL in a "
                    "message or email, treat it as suspicious even though it can't be scanned directly."
                )
            except requests.exceptions.Timeout:
                st.error(
                    "⏱️ This website took too long to respond and the scan timed out. "
                    "It may be overloaded, offline, or deliberately slow to block scanners like this one."
                )
            except requests.exceptions.RequestException:
                st.error(
                    "🚫 This website couldn't be reached. It may be down, blocking automated visitors, "
                    "or the URL might be incorrect."
                )
            except Exception as e:
                st.error(f"Actual Error: {e}")

st.divider()

# ---- Demo buttons ----
st.markdown("####  Try a Demo")
col1, col2 = st.columns(2)

demo = pd.read_csv("demo_features.csv")

col1, col2 = st.columns(2)

with col1:
    if st.button("Load Phishing Example", use_container_width=True):
        sample = demo[demo["label"] == 0].iloc[0]

        for col in feature_cols:
            value = sample[col]
            st.session_state[col] = bool(value) if col in BINARY_FEATURES else float(value)

        st.rerun()

with col2:
    if st.button("Load Legitimate Example", use_container_width=True):
        sample = demo[demo["label"] == 1].iloc[0]

        for col in feature_cols:
            value = sample[col]
            st.session_state[col] = bool(value) if col in BINARY_FEATURES else float(value)

        st.rerun()

st.divider()


# ---- Inputs in 2 columns instead of one long list ----
st.markdown ("####  Website Features")

input_data = {}
cols = st.columns(2)
for i, col in enumerate(feature_cols):
    with cols[i % 2]:
        if col in BINARY_FEATURES:
            # IMPORTANT: key=col (not a separate "chk_" key) so that values loaded by the
            # demo buttons or the live URL scan actually reach this widget on rerun.
            if not isinstance(st.session_state[col], bool):
                st.session_state[col] = bool(st.session_state[col])
            checked = st.checkbox(col, key=col)
            input_data[col] = 1.0 if checked else 0.0
        else:
            input_data[col] = st.number_input(col, key=col)

st.markdown("<br>", unsafe_allow_html=True)
st.divider()
st.markdown("<br>", unsafe_allow_html=True)

# ---- Predict button ----
if st.button(" Analyze Website", type="primary", use_container_width=True):
    df_input = pd.DataFrame([input_data])[feature_cols]
    prediction = model.predict(df_input)[0]
    proba = model.predict_proba(df_input)[0]

    prediction = model.predict(df_input)[0]
    proba = model.predict_proba(df_input)[0]

    st.write("Prediction =", prediction)
    st.write("Probability =", proba)
    st.write(df_input)
    

    if prediction == 0:
        st.markdown(
            f"<div class='result-box' style='background-color:#FEE2E2; color:#B91C1C;'>⚠️ PHISHING DETECTED<br><span style='font-size:1rem;'>Confidence: {proba[0]*100:.1f}%</span></div>",
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            f"<div class='result-box' style='background-color:#DCFCE7; color:#15803D;'>✅ LEGITIMATE WEBSITE<br><span style='font-size:1rem;'>Confidence: {proba[1]*100:.1f}%</span></div>",
            unsafe_allow_html=True
        )

with st.expander(" Debug: raw values"):
    st.json(input_data)

st.markdown("""
<div class="footer">
<b>Developed by:</b> Kavita <br>
AI-Based Phishing Website Detection
</div>

</div>
""", unsafe_allow_html=True)