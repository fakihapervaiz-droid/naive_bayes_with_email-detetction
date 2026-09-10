import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
import math
from urllib.parse import urlparse


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)


# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

.stApp {
    background: #070b12;
    color: #ffffff;
}

.block-container {
    max-width: 820px;
    padding-top: 3rem;
    padding-bottom: 3rem;
}


/* ---------- HEADER ---------- */

.main-title {
    text-align: center;
    font-size: 54px;
    font-weight: 800;
    letter-spacing: -2px;
    color: #ffffff;
    margin-bottom: 0px;
}

.main-subtitle {
    text-align: center;
    color: #8792a5;
    font-size: 15px;
    margin-top: 5px;
    margin-bottom: 38px;
}


/* ---------- SCANNER ---------- */

.scanner-box {
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 18px;
    padding: 25px;
    margin-bottom: 25px;
}


/* ---------- INPUT ---------- */

.stTextInput > div > div > input {
    background: #080d15 !important;
    color: #ffffff !important;
    border: 1px solid #303c50 !important;
    border-radius: 10px !important;
    height: 52px !important;
    font-size: 15px !important;
}

.stTextInput > div > div > input:focus {
    border: 1px solid #2563eb !important;
    box-shadow: 0 0 0 1px #2563eb !important;
}


/* ---------- BUTTON ---------- */

.stButton > button {
    width: 100%;
    height: 52px;
    border-radius: 10px;
    border: none;
    background: #2563eb;
    color: white;
    font-size: 15px;
    font-weight: 700;
    margin-top: 8px;
}

.stButton > button:hover {
    background: #1d4ed8;
}


/* ---------- RESULT BANNER ---------- */

.result-banner {
    border-radius: 18px;
    padding: 30px 25px;
    text-align: center;
    margin-top: 20px;
    margin-bottom: 20px;
}

.safe-banner {
    background: linear-gradient(
        135deg,
        #09271b,
        #0d3826
    );
    border: 1px solid #17663e;
}

.danger-banner {
    background: linear-gradient(
        135deg,
        #2b0d12,
        #3a1017
    );
    border: 1px solid #7f1d2d;
}

.result-icon {
    font-size: 38px;
    margin-bottom: 5px;
}

.result-title {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: 0.5px;
}

.safe-title {
    color: #22c55e;
}

.danger-title {
    color: #ef4444;
}

.result-description {
    color: #a7b0bf;
    font-size: 14px;
    margin-top: 7px;
}


/* ---------- RISK ---------- */

.risk-high {
    display: inline-block;
    margin-top: 15px;
    padding: 7px 18px;
    border-radius: 30px;
    background: #49131b;
    color: #ff6b78;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
}

.risk-low {
    display: inline-block;
    margin-top: 15px;
    padding: 7px 18px;
    border-radius: 30px;
    background: #103823;
    color: #4ade80;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 1px;
}


/* ---------- PROBABILITY CARD ---------- */

.card {
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 18px;
    padding: 25px;
    margin-top: 20px;
}

.card-title {
    font-size: 17px;
    font-weight: 700;
    color: #ffffff;
    margin-bottom: 22px;
}


/* ---------- PROBABILITY ROW ---------- */

.prob-row {
    margin-bottom: 18px;
}

.prob-label {
    display: flex;
    justify-content: space-between;
    color: #b5bfce;
    font-size: 13px;
    margin-bottom: 7px;
}

.progress-bg {
    width: 100%;
    height: 11px;
    background: #1b2533;
    border-radius: 20px;
    overflow: hidden;
}

.progress-blue {
    height: 100%;
    background: #3b82f6;
    border-radius: 20px;
}

.progress-red {
    height: 100%;
    background: #ef4444;
    border-radius: 20px;
}


/* ---------- METRIC CARDS ---------- */

.metric-container {
    display: flex;
    gap: 15px;
    margin-top: 20px;
}

.metric {
    flex: 1;
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 16px;
    padding: 22px 15px;
    text-align: center;
}

.metric-value {
    font-size: 27px;
    font-weight: 800;
    color: #ffffff;
}

.metric-label {
    color: #7f8a9d;
    font-size: 12px;
    margin-top: 5px;
}


/* ---------- URL CARD ---------- */

.url-card {
    background: #0c1119;
    border: 1px solid #1e2938;
    border-radius: 14px;
    padding: 17px;
    margin-top: 20px;
}

.url-heading {
    color: #7f8a9d;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.url-value {
    color: #cbd5e1;
    font-size: 13px;
    word-break: break-all;
}


/* ---------- FOOTER ---------- */

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 35px;
}


/* ---------- MOBILE ---------- */

@media (max-width: 600px) {

    .main-title {
        font-size: 42px;
    }

    .metric-container {
        flex-direction: column;
    }

}

</style>
""", unsafe_allow_html=True)


# =========================================================
# LOAD MODEL
# =========================================================

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

    st.error("Model could not be loaded.")

    st.code(str(e))

    st.stop()


# =========================================================
# URL FEATURE EXTRACTION
# =========================================================

def extract_url_features(url):

    url = str(url).strip()

    if re.match(r"^[a-zA-Z]+://", url):

        parsed_url = urlparse(url)

    else:

        parsed_url = urlparse(
            "http://" + url
        )

    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    domain_without_port = domain.split(":")[0]

    features = {}

    # Basic URL features

    features["URLLength"] = len(url)

    features["DomainLength"] = len(
        domain_without_port
    )

    features["PathLength"] = len(path)

    features["QueryLength"] = len(query)

    # Character features

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

    ipv4_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

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

    # URL shortening services

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

            for short_domain
            in shortening_domains

        )

    )

    # Domain characteristics

    features["DomainHasHyphen"] = int(
        "-" in domain_without_port
    )

    features["DomainHasDigits"] = int(

        any(

            char.isdigit()

            for char
            in domain_without_port

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

            for char
            in set(url)

        ]

        entropy = -sum(

            p * math.log2(p)

            for p
            in probabilities

            if p > 0

        )

    else:

        entropy = 0

    features["URLEntropy"] = entropy

    return features


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="main-title">PhishGuard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="main-subtitle">'
    'AI-Powered Phishing URL Detection'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# URL INPUT
# =========================================================

st.markdown(
    '<div class="scanner-box">',
    unsafe_allow_html=True
)

url_input = st.text_input(
    "Website URL",
    placeholder="Enter a website URL to scan...",
    label_visibility="collapsed"
)

scan = st.button(
    "SCAN URL"
)

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# SCAN
# =========================================================

if scan:

    if not url_input.strip():

        st.warning(
            "Please enter a URL to analyze."
        )

        st.stop()

    url = url_input.strip()

    try:

        # -------------------------------------------------
        # EXTRACT FEATURES
        # -------------------------------------------------

        features = extract_url_features(url)

        # Check required model features

        missing_features = [

            column

            for column
            in feature_columns

            if column not in features

        ]

        if missing_features:

            st.error(
                "The saved model expects features "
                "that are not available from the URL."
            )

            st.code(
                str(missing_features)
            )

            st.stop()

        # Keep exact model feature order

        feature_df = pd.DataFrame([

            {
                column: features[column]

                for column
                in feature_columns
            }

        ])

        feature_df = feature_df.astype(
            np.float32
        )

        # -------------------------------------------------
        # SCALE
        # -------------------------------------------------

        scaled_features = scaler.transform(
            feature_df
        ).astype(np.float32)

        # -------------------------------------------------
        # PREDICTION
        # -------------------------------------------------

        prediction = model.predict(
            scaled_features
        )[0]

        probabilities = model.predict_proba(
            scaled_features
        )[0]

        # -------------------------------------------------
        # ROBUST CLASS INDEX
        # -------------------------------------------------

        classes = list(
            model.classes_
        )

        phishing_index = classes.index(0)
        legitimate_index = classes.index(1)

        phishing_probability = (
            probabilities[phishing_index] * 100
        )

        legitimate_probability = (
            probabilities[legitimate_index] * 100
        )

        confidence = max(
            phishing_probability,
            legitimate_probability
        )

        # -------------------------------------------------
        # RESULT
        # -------------------------------------------------

        if prediction == 0:

            result = "THREAT DETECTED"

            description = (
                "This URL shows characteristics "
                "associated with phishing activity."
            )

            risk = "HIGH RISK"

            banner_class = "danger-banner"
            title_class = "danger-title"
            icon = "!"

        else:

            result = "URL APPEARS SAFE"

            description = (
                "No strong phishing indicators "
                "were detected in this URL."
            )

            risk = "LOW RISK"

            banner_class = "safe-banner"
            title_class = "safe-title"
            icon = "✓"


        # =================================================
        # RESULT BANNER
        # =================================================

        st.markdown(

            f"""
            <div class="result-banner {banner_class}">

                <div class="result-icon">
                    {icon}
                </div>

                <div class="result-title {title_class}">
                    {result}
                </div>

                <div class="result-description">
                    {description}
                </div>

                <div class="{ 
                    'risk-high'
                    if prediction == 0
                    else
                    'risk-low'
                }">
                    {risk}
                </div>

            </div>
            """,

            unsafe_allow_html=True

        )


        # =================================================
        # PROBABILITY CARD
        # =================================================

        st.markdown(

            f"""
            <div class="card">

                <div class="card-title">
                    Prediction Probability
                </div>

                <div class="prob-row">

                    <div class="prob-label">

                        <span>
                            Phishing
                        </span>

                        <span>
                            {phishing_probability:.2f}%
                        </span>

                    </div>

                    <div class="progress-bg">

                        <div
                            class="progress-red"
                            style="width:
                            {phishing_probability}%;">
                        </div>

                    </div>

                </div>


                <div class="prob-row">

                    <div class="prob-label">

                        <span>
                            Legitimate
                        </span>

                        <span>
                            {legitimate_probability:.2f}%
                        </span>

                    </div>

                    <div class="progress-bg">

                        <div
                            class="progress-blue"
                            style="width:
                            {legitimate_probability}%;">
                        </div>

                    </div>

                </div>

            </div>
            """,

            unsafe_allow_html=True

        )


        # =================================================
        # METRICS
        # =================================================

        # Your previously measured model accuracy
        # Replace this value if you retrain the model.

        model_accuracy = 99.94

        st.markdown(

            f"""
            <div class="metric-container">

                <div class="metric">

                    <div class="metric-value">
                        {model_accuracy:.2f}%
                    </div>

                    <div class="metric-label">
                        MODEL ACCURACY
                    </div>

                </div>


                <div class="metric">

                    <div class="metric-value">
                        {confidence:.1f}%
                    </div>

                    <div class="metric-label">
                        PREDICTION CONFIDENCE
                    </div>

                </div>


                <div class="metric">

                    <div class="metric-value">
                        {'HIGH' if prediction == 0 else 'LOW'}
                    </div>

                    <div class="metric-label">
                        RISK LEVEL
                    </div>

                </div>

            </div>
            """,

            unsafe_allow_html=True

        )


        # =================================================
        # URL DISPLAY
        # =================================================

        st.markdown(

            f"""
            <div class="url-card">

                <div class="url-heading">
                    Analyzed URL
                </div>

                <div class="url-value">
                    {url}
                </div>

            </div>
            """,

            unsafe_allow_html=True

        )


    except Exception as e:

        st.error(
            "Unable to analyze this URL."
        )

        st.code(
            str(e)
        )


# =========================================================
# FOOTER
# =========================================================

st.markdown(

    """
    <div class="footer">
        PhishGuard • Machine Learning URL Security
    </div>
    """,

    unsafe_allow_html=True

)