import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
import math
from urllib.parse import urlparse

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(37,99,235,0.12), transparent 28%),
        radial-gradient(circle at 90% 20%, rgba(124,58,237,0.10), transparent 28%),
        #080d18;
    color: #e5e7eb;
}

/* Remove top padding */
.block-container {
    max-width: 1150px;
    padding-top: 1.5rem;
    padding-bottom: 3rem;
}

/* Hide Streamlit menu/footer */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

/* ============================================================
   HERO
   ============================================================ */

.hero {
    text-align: center;
    padding: 35px 20px 25px;
}

.badge {
    display: inline-block;
    padding: 7px 16px;
    border-radius: 30px;
    background: rgba(37,99,235,0.12);
    border: 1px solid rgba(96,165,250,0.30);
    color: #93c5fd;
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.5px;
    margin-bottom: 18px;
}

.hero-title {
    font-size: 56px;
    font-weight: 800;
    letter-spacing: -2px;
    margin: 0;
    background: linear-gradient(
        90deg,
        #60a5fa,
        #a78bfa,
        #c4b5fd
    );
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.hero-subtitle {
    max-width: 720px;
    margin: 15px auto 0;
    color: #94a3b8;
    font-size: 16px;
    line-height: 1.7;
}

/* ============================================================
   SCANNER CARD
   ============================================================ */

.scanner {
    margin-top: 25px;
    padding: 32px;
    border-radius: 24px;
    background: rgba(15,23,42,0.82);
    border: 1px solid rgba(148,163,184,0.16);
    box-shadow:
        0 20px 60px rgba(0,0,0,0.35),
        inset 0 1px 0 rgba(255,255,255,0.03);
}

.scanner-title {
    font-size: 21px;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 5px;
}

.scanner-description {
    color: #64748b;
    font-size: 13px;
    margin-bottom: 20px;
}

/* Input */
.stTextInput > div > div > input {
    background: #0b1220 !important;
    color: #f8fafc !important;
    border: 1px solid #263449 !important;
    border-radius: 12px !important;
    height: 52px !important;
    padding-left: 16px !important;
    font-size: 15px !important;
}

.stTextInput > div > div > input:focus {
    border: 1px solid #60a5fa !important;
    box-shadow: 0 0 0 2px rgba(96,165,250,0.12) !important;
}

/* Scan button */
.stButton > button {
    width: 100%;
    height: 52px;
    border-radius: 12px;
    border: none;
    background: linear-gradient(
        90deg,
        #2563eb,
        #7c3aed
    );
    color: white;
    font-size: 15px;
    font-weight: 700;
    transition: 0.2s;
}

.stButton > button:hover {
    transform: translateY(-1px);
    box-shadow: 0 10px 30px rgba(59,130,246,0.25);
}

/* ============================================================
   RESULT
   ============================================================ */

.result-card {
    margin-top: 25px;
    padding: 30px;
    border-radius: 22px;
    background: rgba(15,23,42,0.9);
    border: 1px solid rgba(148,163,184,0.15);
}

.result-label {
    color: #64748b;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}

.result-danger {
    color: #f87171;
    font-size: 32px;
    font-weight: 800;
    margin-top: 7px;
}

.result-safe {
    color: #4ade80;
    font-size: 32px;
    font-weight: 800;
    margin-top: 7px;
}

.result-description {
    color: #94a3b8;
    line-height: 1.6;
    margin-top: 10px;
}

/* ============================================================
   METRICS
   ============================================================ */

.metric {
    background: #0b1220;
    border: 1px solid #1e293b;
    border-radius: 16px;
    padding: 20px;
    text-align: center;
}

.metric-value {
    font-size: 27px;
    font-weight: 750;
    color: #f8fafc;
}

.metric-name {
    margin-top: 6px;
    color: #64748b;
    font-size: 12px;
}

/* ============================================================
   INDICATORS
   ============================================================ */

.indicator {
    background: #0b1220;
    border: 1px solid #1e293b;
    border-radius: 15px;
    padding: 18px;
    margin-bottom: 10px;
}

.indicator-name {
    color: #64748b;
    font-size: 12px;
    margin-bottom: 6px;
}

.indicator-value {
    color: #e2e8f0;
    font-size: 16px;
    font-weight: 650;
}

/* ============================================================
   URL DISPLAY
   ============================================================ */

.url-box {
    background: #060b14;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 15px 18px;
    color: #93c5fd;
    font-family: monospace;
    font-size: 13px;
    word-break: break-all;
}

/* ============================================================
   SECTION TITLE
   ============================================================ */

.section-title {
    color: #f8fafc;
    font-size: 20px;
    font-weight: 700;
    margin-top: 32px;
    margin-bottom: 15px;
}

/* ============================================================
   INFO
   ============================================================ */

.info-card {
    background: rgba(15,23,42,0.75);
    border: 1px solid #1e293b;
    border-radius: 18px;
    padding: 23px;
    color: #94a3b8;
    line-height: 1.7;
    font-size: 13px;
}

.info-card strong {
    color: #e2e8f0;
}

/* ============================================================
   FOOTER
   ============================================================ */

.custom-footer {
    margin-top: 50px;
    padding-top: 25px;
    border-top: 1px solid #1e293b;
    text-align: center;
    color: #475569;
    font-size: 12px;
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

except Exception:

    st.error(
        "Model file not found. Please place "
        "'phishing_url_naive_bayes.pkl' "
        "in the same folder as app.py."
    )

    st.stop()


# ============================================================
# FEATURE EXTRACTION
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

    features["URLLength"] = len(url)
    features["DomainLength"] = len(domain_without_port)
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
        char.isdigit() for char in url
    )

    features["NumLetters"] = sum(
        char.isalpha() for char in url
    )

    features["NumSpecialChars"] = sum(
        not char.isalnum() for char in url
    )

    features["IsHTTPS"] = int(
        parsed_url.scheme.lower() == "https"
    )

    ipv4_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    features["IsDomainIP"] = int(
        bool(
            re.match(
                ipv4_pattern,
                domain_without_port
            )
        )
    )

    domain_parts = [
        part
        for part in domain_without_port.split(".")
        if part
    ]

    features["SubdomainCount"] = max(
        len(domain_parts) - 2,
        0
    )

    features["HasDoubleSlash"] = int(
        "//" in url[8:]
    )

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
            short_domain in
            domain_without_port.lower()
            for short_domain in shortening_domains
        )
    )

    features["DomainHasHyphen"] = int(
        "-" in domain_without_port
    )

    features["DomainHasDigits"] = int(
        any(
            char.isdigit()
            for char in domain_without_port
        )
    )

    features["QueryParameterCount"] = (
        query.count("=")
        if query
        else 0
    )

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
# HERO
# ============================================================

st.markdown("""
<div class="hero">

    <div class="badge">
        MACHINE LEARNING • URL SECURITY
    </div>

    <div class="hero-title">
        PhishGuard AI
    </div>

    <div class="hero-subtitle">
        Detect potentially malicious URLs using
        machine learning and structural URL analysis.
        Fast, simple and privacy-friendly.
    </div>

</div>
""", unsafe_allow_html=True)


# ============================================================
# SCANNER
# ============================================================

st.markdown("""
<div class="scanner">

    <div class="scanner-title">
        URL Security Scanner
    </div>

    <div class="scanner-description">
        Enter a website address to analyze its URL characteristics.
    </div>

</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns([5, 1.25])

with col1:

    url_input = st.text_input(
        "URL",
        placeholder="https://example.com/login",
        label_visibility="collapsed"
    )

with col2:

    analyze = st.button(
        "SCAN URL"
    )


# ============================================================
# ANALYSIS
# ============================================================

if analyze:

    if not url_input.strip():

        st.warning(
            "Enter a URL before starting the scan."
        )

        st.stop()

    url = url_input.strip()

    try:

        # Feature extraction
        features = extract_url_features(url)

        feature_df = pd.DataFrame(
            [features]
        )

        feature_df = feature_df[
            feature_columns
        ]

        feature_df = feature_df.astype(
            np.float32
        )

        # Scaling
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

        confidence = max(
            phishing_probability,
            legitimate_probability
        )

        # ====================================================
        # RESULT
        # ====================================================

        if prediction == 0:

            result_class = "result-danger"
            result_title = "POTENTIALLY PHISHING"

            description = (
                "The model detected URL characteristics "
                "commonly associated with phishing activity. "
                "Avoid entering sensitive information on this site."
            )

        else:

            result_class = "result-safe"
            result_title = "LIKELY LEGITIMATE"

            description = (
                "The URL does not show strong phishing-related "
                "characteristics according to the trained model."
            )

        st.markdown(
            f"""
            <div class="result-card">

                <div class="result-label">
                    Analysis Result
                </div>

                <div class="{result_class}">
                    {result_title}
                </div>

                <div class="result-description">
                    {description}
                </div>

                <br>

                <div class="result-label">
                    Scanned URL
                </div>

                <div class="url-box">
                    {url}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )

        # ====================================================
        # CONFIDENCE
        # ====================================================

        st.markdown(
            '<div class="section-title">Model Assessment</div>',
            unsafe_allow_html=True
        )

        c1, c2, c3 = st.columns(3)

        with c1:

            st.markdown(
                f"""
                <div class="metric">

                    <div class="metric-value">
                        {confidence:.1f}%
                    </div>

                    <div class="metric-name">
                        MODEL CONFIDENCE
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with c2:

            st.markdown(
                f"""
                <div class="metric">

                    <div class="metric-value">
                        {phishing_probability:.1f}%
                    </div>

                    <div class="metric-name">
                        PHISHING PROBABILITY
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with c3:

            st.markdown(
                f"""
                <div class="metric">

                    <div class="metric-value">
                        {legitimate_probability:.1f}%
                    </div>

                    <div class="metric-name">
                        LEGITIMATE PROBABILITY
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ====================================================
        # URL INDICATORS
        # ====================================================

        st.markdown(
            '<div class="section-title">URL Intelligence</div>',
            unsafe_allow_html=True
        )

        i1, i2, i3, i4 = st.columns(4)

        with i1:

            https_text = (
                "HTTPS detected"
                if features["IsHTTPS"]
                else "No HTTPS"
            )

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        CONNECTION
                    </div>

                    <div class="indicator-value">
                        {https_text}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with i2:

            domain_text = (
                "IP address"
                if features["IsDomainIP"]
                else "Named domain"
            )

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        DOMAIN TYPE
                    </div>

                    <div class="indicator-value">
                        {domain_text}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with i3:

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        SUSPICIOUS TERMS
                    </div>

                    <div class="indicator-value">
                        {features["SuspiciousWordCount"]}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with i4:

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        SUBDOMAINS
                    </div>

                    <div class="indicator-value">
                        {features["SubdomainCount"]}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ====================================================
        # SECONDARY INDICATORS
        # ====================================================

        j1, j2, j3, j4 = st.columns(4)

        with j1:

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        URL LENGTH
                    </div>

                    <div class="indicator-value">
                        {features["URLLength"]} characters
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with j2:

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        DIGITS
                    </div>

                    <div class="indicator-value">
                        {features["NumDigits"]}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with j3:

            short_text = (
                "Shortener detected"
                if features["IsShortenedURL"]
                else "Not detected"
            )

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        URL SHORTENER
                    </div>

                    <div class="indicator-value">
                        {short_text}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        with j4:

            st.markdown(
                f"""
                <div class="indicator">

                    <div class="indicator-name">
                        ENTROPY
                    </div>

                    <div class="indicator-value">
                        {features["URLEntropy"]:.2f}
                    </div>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ====================================================
        # HOW IT WORKS
        # ====================================================

        st.markdown(
            '<div class="section-title">How PhishGuard Works</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            """
            <div class="info-card">

            <strong>01 — URL Analysis</strong><br>
            The application examines the URL structure,
            domain characteristics, special characters,
            suspicious terms and other URL-level signals.

            <br><br>

            <strong>02 — Feature Engineering</strong><br>
            These characteristics are converted into numerical
            features that can be understood by the machine
            learning model.

            <br><br>

            <strong>03 — Gaussian Naive Bayes</strong><br>
            The trained classifier evaluates the extracted
            features and estimates the likelihood of phishing
            versus legitimate classification.

            <br><br>

            <strong>04 — Security Assessment</strong><br>
            The application presents the prediction,
            probability estimates and key URL indicators
            in an easy-to-understand security report.

            </div>
            """,
            unsafe_allow_html=True
        )

        # ====================================================
        # DISCLAIMER
        # ====================================================

        st.markdown("<br>", unsafe_allow_html=True)

        st.warning(
            "This tool performs URL-based analysis only. "
            "A 'Likely Legitimate' result does not guarantee "
            "that a website is completely safe. Do not enter "
            "sensitive information on unfamiliar websites."
        )

    except Exception as e:

        st.error(
            f"Unable to analyze this URL: {e}"
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="custom-footer">

        PHISHGUARD AI &nbsp;•&nbsp;
        Machine Learning URL Security &nbsp;•&nbsp;
        Gaussian Naive Bayes

        <br><br>

        Built with Python · Scikit-learn · Streamlit

    </div>
    """,
    unsafe_allow_html=True
)