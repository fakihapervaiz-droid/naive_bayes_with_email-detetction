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
    color: white;
}

.block-container {
    max-width: 800px;
    padding-top: 3rem;
    padding-bottom: 3rem;
}


/* HEADER */

.title {
    text-align: center;
    font-size: 54px;
    font-weight: 800;
    letter-spacing: -2px;
    color: white;
    margin-bottom: 3px;
}

.subtitle {
    text-align: center;
    color: #8792a5;
    font-size: 15px;
    margin-bottom: 40px;
}


/* SCANNER */

.scanner {
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 18px;
    padding: 25px;
    margin-bottom: 25px;
}


/* INPUT */

.stTextInput > div > div > input {
    background: #080d15 !important;
    color: white !important;
    border: 1px solid #303c50 !important;
    border-radius: 10px !important;
    height: 52px !important;
    font-size: 15px !important;
}

.stTextInput > div > div > input:focus {
    border: 1px solid #3b82f6 !important;
    box-shadow: 0 0 0 1px #3b82f6 !important;
}


/* BUTTON */

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


/* =========================================================
   MAIN RESULT BANNER
   ========================================================= */

.result-banner {
    width: 100%;
    box-sizing: border-box;
    border-radius: 22px;
    padding: 45px 25px;
    text-align: center;
    margin-top: 25px;
    margin-bottom: 20px;
}


/* MALICIOUS */

.malicious-banner {
    background: linear-gradient(
        135deg,
        #3b0a12 0%,
        #7f1624 50%,
        #4a0c15 100%
    );

    border: 1px solid #ef4444;

    box-shadow:
        0 0 35px rgba(239, 68, 68, 0.18);
}


/* LEGITIMATE */

.safe-banner {
    background: linear-gradient(
        135deg,
        #06351f 0%,
        #087443 50%,
        #06452b 100%
    );

    border: 1px solid #22c55e;

    box-shadow:
        0 0 35px rgba(34, 197, 94, 0.18);
}


/* RESULT TITLE */

.result-title {
    font-size: 34px;
    font-weight: 800;
    letter-spacing: 1px;
    color: white;
    margin-bottom: 15px;
}


/* BIG PROBABILITY */

.big-probability {
    font-size: 64px;
    font-weight: 900;
    color: white;
    line-height: 1;
    margin: 10px 0;
    letter-spacing: -2px;
}


/* PROBABILITY LABEL */

.probability-label {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 2px;
    color: rgba(255,255,255,0.75);
    text-transform: uppercase;
}


/* RISK */

.risk {
    display: inline-block;
    margin-top: 22px;
    padding: 8px 22px;
    border-radius: 30px;
    background: rgba(0,0,0,0.25);
    border: 1px solid rgba(255,255,255,0.2);
    color: white;
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 1.5px;
}


/* DESCRIPTION */

.result-description {
    color: rgba(255,255,255,0.75);
    font-size: 13px;
    margin-top: 18px;
}


/* =========================================================
   METRICS
   ========================================================= */

.metrics {
    display: flex;
    gap: 15px;
    margin-top: 20px;
}

.metric {
    flex: 1;
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 16px;
    padding: 22px 10px;
    text-align: center;
}

.metric-value {
    color: white;
    font-size: 25px;
    font-weight: 800;
}

.metric-label {
    color: #7f8a9d;
    font-size: 11px;
    margin-top: 6px;
    letter-spacing: 0.5px;
}


/* =========================================================
   URL CARD
   ========================================================= */

.url-card {
    background: #0c1119;
    border: 1px solid #202b3b;
    border-radius: 14px;
    padding: 18px;
    margin-top: 20px;
}

.url-heading {
    color: #66748a;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 8px;
}

.url-value {
    color: #cbd5e1;
    font-size: 13px;
    word-break: break-all;
}


/* FOOTER */

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 35px;
}


/* MOBILE */

@media (max-width: 600px) {

    .title {
        font-size: 42px;
    }

    .big-probability {
        font-size: 52px;
    }

    .result-title {
        font-size: 27px;
    }

    .metrics {
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

        return pickle.load(file)


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
        parsed_url = urlparse("http://" + url)

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
        c.isdigit() for c in url
    )

    features["NumLetters"] = sum(
        c.isalpha() for c in url
    )

    features["NumSpecialChars"] = sum(
        not c.isalnum() for c in url
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
            domain_name in domain_without_port.lower()
            for domain_name in shortening_domains
        )
    )

    features["DomainHasHyphen"] = int(
        "-" in domain_without_port
    )

    features["DomainHasDigits"] = int(
        any(
            c.isdigit()
            for c in domain_without_port
        )
    )

    features["QueryParameterCount"] = (
        query.count("=")
        if query
        else 0
    )

    # URL entropy

    if len(url) > 0:

        probabilities = [
            url.count(c) / len(url)
            for c in set(url)
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


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="title">PhishGuard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-Powered Phishing URL Detection'
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# SCANNER
# =========================================================

st.markdown(
    '<div class="scanner">',
    unsafe_allow_html=True
)

url_input = st.text_input(
    "Website URL",
    placeholder="Enter website URL to scan...",
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
# ANALYSIS
# =========================================================

if scan:

    if not url_input.strip():

        st.warning(
            "Please enter a URL to scan."
        )

        st.stop()

    url = url_input.strip()

    try:

        # Extract URL features

        features = extract_url_features(url)

        # Check model requirements

        missing = [
            column
            for column in feature_columns
            if column not in features
        ]

        if missing:

            st.error(
                "Some features required by the model "
                "are missing."
            )

            st.code(str(missing))

            st.stop()

        # Exact feature order

        feature_df = pd.DataFrame([
            {
                column: features[column]
                for column in feature_columns
            }
        ])

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

        # Get correct probability indexes

        classes = list(model.classes_)

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

        # =================================================
        # RESULT
        # =================================================

        if prediction == 0:

            result_title = "PHISHING DETECTED"

            probability = phishing_probability

            risk = "HIGH RISK"

            description = (
                "This URL has characteristics associated "
                "with phishing activity. Avoid entering "
                "personal or sensitive information."
            )

            banner = "malicious-banner"

        else:

            result_title = "URL APPEARS SAFE"

            probability = legitimate_probability

            risk = "LOW RISK"

            description = (
                "This URL does not show strong phishing "
                "characteristics based on the trained model."
            )

            banner = "safe-banner"


        # =================================================
        # BIG FULL-COLOR RESULT BANNER
        # =================================================

        st.markdown(
            f"""
            <div class="result-banner {banner}">

                <div class="result-title">
                    {result_title}
                </div>

                <div class="big-probability">
                    {probability:.2f}%
                </div>

                <div class="probability-label">
                    Prediction Probability
                </div>

                <div class="risk">
                    {risk}
                </div>

                <div class="result-description">
                    {description}
                </div>

            </div>
            """,
            unsafe_allow_html=True
        )


        # =================================================
        # METRICS
        # =================================================

        model_accuracy = 99.94

        st.markdown(
            f"""
            <div class="metrics">

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
                        {confidence:.2f}%
                    </div>

                    <div class="metric-label">
                        CONFIDENCE
                    </div>

                </div>

                <div class="metric">

                    <div class="metric-value">
                        {risk.replace(" RISK", "")}
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
        # ANALYZED URL
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

        st.code(str(e))


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