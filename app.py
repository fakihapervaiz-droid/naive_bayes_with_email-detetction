import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
import math
from urllib.parse import urlparse

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="PhishGuard | URL Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

    /* Main background */
    .stApp {
        background: #f7f9fc;
    }

    /* Main container */
    .block-container {
        max-width: 1100px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    /* Header */
    .hero {
        text-align: center;
        padding: 25px 10px 10px 10px;
    }

    .hero-title {
        font-size: 42px;
        font-weight: 750;
        color: #172033;
        margin-bottom: 8px;
        letter-spacing: -1px;
    }

    .hero-subtitle {
        font-size: 17px;
        color: #64748b;
        max-width: 720px;
        margin: auto;
        line-height: 1.6;
    }

    /* URL input section */
    .input-card {
        background: white;
        padding: 28px;
        border-radius: 18px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 8px 25px rgba(15, 23, 42, 0.06);
        margin-top: 25px;
        margin-bottom: 25px;
    }

    /* Result cards */
    .result-card {
        background: white;
        border-radius: 18px;
        padding: 30px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 8px 25px rgba(15, 23, 42, 0.06);
        margin-top: 20px;
    }

    .result-title {
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .safe {
        color: #15803d;
    }

    .danger {
        color: #dc2626;
    }

    .warning {
        color: #d97706;
    }

    /* Metric cards */
    .metric-card {
        background: white;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 18px;
        text-align: center;
        box-shadow: 0 5px 15px rgba(15, 23, 42, 0.04);
    }

    .metric-value {
        font-size: 25px;
        font-weight: 700;
        color: #172033;
    }

    .metric-label {
        font-size: 13px;
        color: #64748b;
        margin-top: 5px;
    }

    /* Information boxes */
    .info-box {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        padding: 20px;
        margin-top: 15px;
    }

    .info-title {
        font-size: 17px;
        font-weight: 650;
        color: #172033;
        margin-bottom: 8px;
    }

    .info-text {
        color: #64748b;
        line-height: 1.6;
        font-size: 14px;
    }

    /* Footer */
    .footer {
        text-align: center;
        color: #94a3b8;
        font-size: 13px;
        margin-top: 45px;
        padding-top: 20px;
        border-top: 1px solid #e2e8f0;
    }

    /* Buttons */
    .stButton > button {
        width: 100%;
        border-radius: 10px;
        height: 48px;
        font-weight: 650;
        border: none;
    }

</style>
""", unsafe_allow_html=True)


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():

    with open(
        "phishing_url_naive_bayes.pkl",
        "rb"
    ) as file:

        package = pickle.load(file)

    return package


try:

    package = load_model()

    model = package["model"]
    scaler = package["scaler"]
    feature_columns = package["feature_columns"]

except Exception as e:

    st.error(
        "Unable to load the model. "
        "Make sure phishing_url_naive_bayes.pkl "
        "is in the same folder as app.py."
    )

    st.stop()


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):

    url = str(url).strip()

    parsed_url = urlparse(
        url
        if re.match(r"^[a-zA-Z]+://", url)
        else "http://" + url
    )

    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    domain_without_port = domain.split(":")[0]

    features = {}

    # Basic features
    features["URLLength"] = len(url)

    features["DomainLength"] = len(
        domain_without_port
    )

    features["PathLength"] = len(path)

    features["QueryLength"] = len(query)

    features["NumDots"] = url.count(".")

    features["NumHyphens"] = url.count("-")

    features["NumUnderscores"] = url.count("_")

    features["NumSlashes"] = url.count("/")

    features["NumQuestionMarks"] = url.count("?")

    features["NumEqual"] = url.count("=")

    features["NumAt"] = url.count("@")

    features["NumAmpersand"] = url.count("&")

    features["NumPercent"] = url.count("%")

    features["NumDigits"] = sum(
        char.isdigit()
        for char in url
    )

    features["NumLetters"] = sum(
        char.isalpha()
        for char in url
    )

    features["NumSpecialChars"] = sum(
        not char.isalnum()
        for char in url
    )

    # HTTPS
    features["IsHTTPS"] = int(
        parsed_url.scheme.lower() == "https"
    )

    # IP address
    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    features["IsDomainIP"] = int(
        bool(
            re.match(
                ipv4_pattern,
                domain_without_port
            )
        )
    )

    # Subdomains
    domain_parts = [
        part
        for part in domain_without_port.split(".")
        if part
    ]

    features["SubdomainCount"] = max(
        len(domain_parts) - 2,
        0
    )

    # Double slash
    features["HasDoubleSlash"] = int(
        "//" in url[8:]
    )

    # Suspicious words
    suspicious_words = [
        "login",
        "signin",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "security",
        "bank",
        "banking",
        "password",
        "credential",
        "confirm",
        "confirmation",
        "wallet",
        "payment",
        "paypal",
        "recover",
        "unlock",
        "bonus",
        "free",
        "claim",
        "urgent"
    ]

    url_lower = url.lower()

    features["SuspiciousWordCount"] = sum(
        word in url_lower
        for word in suspicious_words
    )

    # URL shortener
    shortening_domains = [
        "bit.ly",
        "tinyurl.com",
        "goo.gl",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly"
    ]

    features["IsShortenedURL"] = int(
        any(
            short_domain
            in domain_without_port.lower()
            for short_domain in shortening_domains
        )
    )

    # Domain characteristics
    features["DomainHasHyphen"] = int(
        "-"
        in domain_without_port
    )

    features["DomainHasDigits"] = int(
        any(
            char.isdigit()
            for char in domain_without_port
        )
    )

    # Query parameters
    features["QueryParameterCount"] = (
        query.count("=")
        if query
        else 0
    )

    # URL entropy
    if len(url) > 0:

        probabilities = [
            url.count(char) / len(url)
            for char in set(url)
        ]

        entropy = -sum(
            p * math.log2(p)
            for p in probabilities
            if p > 0
        )

    else:

        entropy = 0

    features["URLEntropy"] = entropy

    return features


# ============================================================
# HEADER
# ============================================================

st.markdown("""
<div class="hero">

    <div class="hero-title">
        PhishGuard
    </div>

    <div class="hero-subtitle">
        Machine Learning–based URL analysis for identifying
        potentially phishing websites before you interact with them.
    </div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# URL INPUT
# ============================================================

st.markdown(
    '<div class="input-card">',
    unsafe_allow_html=True
)

st.markdown(
    "### Analyze a Website URL"
)

st.write(
    "Enter a URL below. The system analyzes URL structure, "
    "domain characteristics, suspicious patterns and other "
    "URL-based indicators."
)

url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com/login",
    label_visibility="collapsed"
)

analyze = st.button(
    "Analyze URL"
)

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# ANALYSIS
# ============================================================

if analyze:

    if not url_input.strip():

        st.warning(
            "Please enter a website URL to analyze."
        )

        st.stop()

    url = url_input.strip()

    try:

        # Extract features
        features = extract_url_features(url)

        feature_df = pd.DataFrame(
            [features]
        )

        # Exact feature order used during training
        feature_df = feature_df[
            feature_columns
        ]

        feature_df = feature_df.astype(
            np.float32
        )

        # Scale
        scaled_features = scaler.transform(
            feature_df
        ).astype(np.float32)

        # Prediction
        prediction = model.predict(
            scaled_features
        )[0]

        probabilities = model.predict_proba(
            scaled_features
        )[0]

        phishing_probability = (
            probabilities[0] * 100
        )

        legitimate_probability = (
            probabilities[1] * 100
        )

        # ====================================================
        # RESULT
        # ====================================================

        if prediction == 0:

            result_title = "Potentially Phishing"

            result_class = "danger"

            result_description = (
                "The URL contains characteristics that "
                "are associated with phishing websites. "
                "Avoid entering passwords, payment details, "
                "or other sensitive information."
            )

        else:

            result_title = "Appears Legitimate"

            result_class = "safe"

            result_description = (
                "The URL appears legitimate based on "
                "the URL characteristics analyzed by "
                "the machine learning model."
            )

        st.markdown(
            '<div class="result-card">',
            unsafe_allow_html=True
        )

        st.markdown(
            f'<div class="result-title {result_class}">'
            f'{result_title}'
            f'</div>',
            unsafe_allow_html=True
        )

        st.write(
            result_description
        )

        st.markdown(
            f"""
            <div class="info-box">

                <div class="info-title">
                    Analyzed URL
                </div>

                <div class="info-text">
                    {url}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown(
            "</div>",
            unsafe_allow_html=True
        )

        # ====================================================
        # PROBABILITY METRICS
        # ====================================================

        st.markdown(
            "### Prediction Confidence"
        )

        col1, col2, col3 = st.columns(3)

        with col1:

            st.markdown(
                f"""
                <div class="metric-card">

                    <div class="metric-value">
                        {phishing_probability:.2f}%
                    </div>

                    <div class="metric-label">
                        Phishing probability
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with col2:

            st.markdown(
                f"""
                <div class="metric-card">

                    <div class="metric-value">
                        {legitimate_probability:.2f}%
                    </div>

                    <div class="metric-label">
                        Legitimate probability
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with col3:

            confidence = max(
                phishing_probability,
                legitimate_probability
            )

            st.markdown(
                f"""
                <div class="metric-card">

                    <div class="metric-value">
                        {confidence:.2f}%
                    </div>

                    <div class="metric-label">
                        Model confidence
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ====================================================
        # URL SECURITY INDICATORS
        # ====================================================

        st.markdown(
            "### URL Security Indicators"
        )

        indicator_col1, indicator_col2 = st.columns(2)

        with indicator_col1:

            https_status = (
                "Enabled"
                if features["IsHTTPS"]
                else "Not detected"
            )

            ip_status = (
                "Detected"
                if features["IsDomainIP"]
                else "Not detected"
            )

            short_status = (
                "Detected"
                if features["IsShortenedURL"]
                else "Not detected"
            )

            st.markdown(
                f"""
                <div class="info-box">

                    <div class="info-title">
                        Connection & Domain
                    </div>

                    <div class="info-text">
                        HTTPS: <b>{https_status}</b><br>
                        IP-based domain: <b>{ip_status}</b><br>
                        URL shortener: <b>{short_status}</b><br>
                        Subdomains: <b>{features["SubdomainCount"]}</b>
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with indicator_col2:

            st.markdown(
                f"""
                <div class="info-box">

                    <div class="info-title">
                        URL Structure
                    </div>

                    <div class="info-text">
                        URL length: <b>{features["URLLength"]}</b><br>
                        Dots: <b>{features["NumDots"]}</b><br>
                        Digits: <b>{features["NumDigits"]}</b><br>
                        Suspicious words: <b>{features["SuspiciousWordCount"]}</b>
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ====================================================
        # MODEL EXPLANATION
        # ====================================================

        st.markdown(
            "### How the Detection Works"
        )

        st.markdown(
            """
            <div class="info-box">

                <div class="info-text">

                <b>1. URL Feature Extraction</b><br>
                The application converts the URL into numerical
                characteristics such as length, domain structure,
                special characters, HTTPS usage and suspicious words.

                <br><br>

                <b>2. Feature Scaling</b><br>
                The extracted features are transformed using the
                same scaler used during model training.

                <br><br>

                <b>3. Machine Learning Prediction</b><br>
                A Gaussian Naive Bayes classifier evaluates the
                URL characteristics and estimates the probability
                of phishing or legitimate classification.

                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        # ====================================================
        # DISCLAIMER
        # ====================================================

        st.info(
            "Security note: This application analyzes URL "
            "characteristics only. A legitimate prediction does "
            "not guarantee that a website is completely safe. "
            "Always verify unfamiliar websites before entering "
            "sensitive information."
        )

    except Exception as e:

        st.error(
            f"Analysis failed: {str(e)}"
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">

        PhishGuard · Machine Learning URL Security<br>
        Built with Python, Scikit-learn and Streamlit

    </div>
    """,
    unsafe_allow_html=True
)