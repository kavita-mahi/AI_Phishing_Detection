import os
import joblib
import pandas as pd
import streamlit as st

from feature_extraction import (
    extract_url_features,
    FEATURE_COLUMNS
)


# --------------------------------
# PAGE CONFIGURATION
# --------------------------------

st.set_page_config(
    page_title="SecureScan | URL Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)


# --------------------------------
# PROFESSIONAL CUSTOM CSS
# --------------------------------

st.markdown("""
<style>

.stApp {
    background-color: #0B1120;
    color: #E5E7EB;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1100px;
}

header[data-testid="stHeader"] {
    background: transparent;
}

.main-title {
    font-size: 38px;
    font-weight: 750;
    color: #F8FAFC;
    letter-spacing: -1px;
    margin-bottom: 5px;
}

.subtitle {
    color: #94A3B8;
    font-size: 16px;
    margin-bottom: 28px;
}

.section-label {
    color: #2DD4BF;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.info-card {
    background: #151F32;
    border: 1px solid #263449;
    padding: 22px;
    border-radius: 14px;
    margin-top: 15px;
}

.result-card {
    background: #151F32;
    border: 1px solid #263449;
    border-radius: 16px;
    padding: 28px;
    margin-top: 22px;
    text-align: center;
}

.safe-result {
    border: 1px solid #0F766E;
    background: #102A2B;
}

.danger-result {
    border: 1px solid #B45353;
    background: #301C29;
}

.result-heading {
    font-size: 25px;
    font-weight: 750;
    margin-bottom: 8px;
}

.result-description {
    color: #CBD5E1;
    font-size: 14px;
}

.stTextInput input {
    background-color: #151F32 !important;
    color: #F8FAFC !important;
    border: 1px solid #334155 !important;
    border-radius: 10px !important;
    padding: 13px !important;
}

.stTextInput label {
    color: #CBD5E1 !important;
    font-weight: 600;
}

.stButton > button {
    background: #0D9488;
    color: white;
    border: none;
    border-radius: 10px;
    height: 48px;
    font-weight: 700;
    width: 100%;
    transition: 0.2s;
}

.stButton > button:hover {
    background: #0F766E;
    color: white;
    border: none;
}

[data-testid="stMetric"] {
    background: #151F32;
    border: 1px solid #263449;
    border-radius: 12px;
    padding: 18px;
}

[data-testid="stMetricLabel"] {
    color: #94A3B8;
}

[data-testid="stMetricValue"] {
    color: #F8FAFC;
}

hr {
    border-color: #263449;
}

.footer {
    color: #64748B;
    text-align: center;
    font-size: 12px;
    padding-top: 35px;
}

</style>
""", unsafe_allow_html=True)


# --------------------------------
# MODEL LOADING
# --------------------------------

MODEL_PATH = "models/xgboost_url_only_model.pkl"
FEATURE_PATH = "models/url_only_feature_columns.pkl"


@st.cache_resource
def load_model():

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model file not found.")

    if not os.path.exists(FEATURE_PATH):
        raise FileNotFoundError("Feature columns file not found.")

    model = joblib.load(MODEL_PATH)
    feature_columns = joblib.load(FEATURE_PATH)

    if feature_columns != FEATURE_COLUMNS:
        raise ValueError("Feature columns mismatch.")

    return model, feature_columns


# --------------------------------
# HEADER
# --------------------------------

st.markdown(
    '<div class="section-label">CYBERSECURITY INTELLIGENCE PLATFORM</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="main-title">🛡️ SecureScan</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">AI-Powered Phishing Website Detection System</div>',
    unsafe_allow_html=True
)

st.divider()


# --------------------------------
# INTRODUCTION
# --------------------------------

st.markdown("""
<div class="info-card">
    <div class="section-label">SYSTEM OVERVIEW</div>
    <h3 style="color:#F8FAFC; margin-bottom:8px;">
        Analyze suspicious URLs
    </h3>
    <p style="color:#94A3B8; margin-bottom:0;">
        SecureScan uses an XGBoost machine learning model to analyze
        URL-based characteristics and classify a website URL as
        potentially phishing or legitimate.
    </p>
</div>
""", unsafe_allow_html=True)


# --------------------------------
# URL ANALYSIS
# --------------------------------

st.write("")
st.markdown(
    '<div class="section-label">URL ANALYSIS</div>',
    unsafe_allow_html=True
)

url = st.text_input(
    "Website URL",
    placeholder="https://example.com",
    label_visibility="visible"
)

analyze = st.button("🔍  Analyze Website")


# --------------------------------
# PREDICTION
# --------------------------------

if analyze:

    if not url.strip():

        st.warning("Please enter a website URL.")

    else:

        try:

            with st.spinner("Analyzing URL characteristics..."):

                model, feature_columns = load_model()

                features = extract_url_features(url)

                input_data = pd.DataFrame(
                    [features],
                    columns=feature_columns
                )

                prediction = int(model.predict(input_data)[0])

                probabilities = model.predict_proba(input_data)[0]

                class_probabilities = dict(
                    zip(model.classes_, probabilities)
                )

                phishing_probability = (
                    class_probabilities[0] * 100
                )

                legitimate_probability = (
                    class_probabilities[1] * 100
                )

            st.divider()

            st.markdown(
                '<div class="section-label">ANALYSIS REPORT</div>',
                unsafe_allow_html=True
            )

            if prediction == 0:

                st.markdown(f"""
                <div class="result-card danger-result">
                    <div style="font-size:38px;">⚠️</div>
                    <div class="result-heading" style="color:#FCA5A5;">
                        Phishing Website Detected
                    </div>
                    <div class="result-description">
                        The model classified this URL as potentially
                        malicious. Avoid entering personal information.
                    </div>
                </div>
                """, unsafe_allow_html=True)

            else:

                st.markdown(f"""
                <div class="result-card safe-result">
                    <div style="font-size:38px;">✓</div>
                    <div class="result-heading" style="color:#5EEAD4;">
                        Legitimate Website Prediction
                    </div>
                    <div class="result-description">
                        The model classified this URL as legitimate.
                        This does not guarantee that the website is safe.
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.write("")

            col1, col2 = st.columns(2)

            with col1:

                st.metric(
                    "Phishing Probability",
                    f"{phishing_probability:.2f}%"
                )

                st.progress(
                    float(phishing_probability / 100)
                )

            with col2:

                st.metric(
                    "Legitimate Probability",
                    f"{legitimate_probability:.2f}%"
                )

                st.progress(
                    float(legitimate_probability / 100)
                )

            # Feature details
            st.write("")

            with st.expander("View Extracted URL Features"):

                feature_table = pd.DataFrame(
                    features.items(),
                    columns=["Feature Name", "Extracted Value"]
                )

                st.dataframe(
                    feature_table,
                    use_container_width=True,
                    hide_index=True
                )

        except Exception as error:

            st.error(f"Analysis failed: {error}")


# --------------------------------
# FOOTER
# --------------------------------

st.divider()

st.markdown("""
<div class="footer">
    <p>SECURESCAN | AI-POWERED CYBERSECURITY</p>
    <p>Machine Learning Engine: XGBoost | URL Feature Analysis: 18 Features</p>
    <p>For educational and research purposes. Predictions are not a security guarantee.</p>
</div>
""", unsafe_allow_html=True)