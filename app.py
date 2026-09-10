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
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

.stApp {
    background: #080b12;
}

.block-container {
    max-width: 750px;
    padding-top: 4rem;
    padding-bottom: 3rem;
}


/* =========================
   HEADER
   ========================= */

.title {
    text-align: center;
    font-size: 52px;
    font-weight: 800;
    letter-spacing: -2px;
    color: #ffffff;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    color: #8b95a7;
    font-size: 15px;
    margin-bottom: 45px;
}


/* =========================
   SCANNER
   ========================= */

.scanner {
    background: #111722;
    border: 1px solid #202938;
    border-radius: 18px;
    padding: 25px;
}


/* =========================
   URL INPUT
   ========================= */

.stTextInput > div > div > input {
    background: #080c14 !important;
    color: #ffffff !important;
    border: 1px solid #303b4f !important;
    border-radius: 10px !important;
    height: 52px !important;
    font-size: 15px !important;
}

.stTextInput > div > div > input:focus {
    border: 1px solid #2563eb !important;
    box-shadow: 0 0 0 1px #2563eb !important;
}


/* =========================
   BUTTON
   ========================= */

.stButton > button {
    width: 100%;
    height: 50px;
    border-radius: 10px;
    background: #2563eb;
    color: white;
    border: none;
    font-weight: 700;
    font-size: 15px;
}

.stButton > button:hover {
    background: #1d4ed8;
}


/* =========================
   RESULT CARD
   ========================= */

.result {
    margin-top: 25px;
    padding: 38px 20px;
    border-radius: 18px;
    text-align: center;
    background: #111722;
    border: 1px solid #202938;
}


/* =========================
   RESULT TEXT
   ========================= */

.legitimate {
    color: #22c55e;
    font-size: 38px;
    font-weight: 800;
    letter-spacing: 1px;
}

.malicious {
    color: #ef4444;
    font-size: 38px;
    font-weight: 800;
    letter-spacing: 1px;
}


/* =========================
   CONFIDENCE
   ========================= */

.confidence {
    color: #a1aabb;
    margin-top: 10px;
    font-size: 14px;
}


/* =========================
   URL
   ========================= */

.url {
    color: #64748b;
    font-size: 12px;
    margin-top: 20px;
    word-break: break-all;
}


/* =========================
   FOOTER
   ========================= */

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 35px;
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
        "Model could not be loaded."
    )

    st.code(str(e))

    st.stop()


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url):

    url = str(url).strip()

    # Add scheme if missing
    if re.match(
        r"^[a-zA-Z]+://",
        url
    ):

        parsed_url = urlparse(url)

    else:

        parsed_url = urlparse(
            "http://" + url
        )

    domain = parsed_url.netloc

    path = parsed_url.path

    query = parsed_url.query

    # Remove port
    domain_without_port = domain.split(":")[0]

    features = {}


    # ========================================================
    # BASIC URL FEATURES
    # ========================================================

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


    # ========================================================
    # LETTERS / DIGITS / SPECIAL CHARACTERS
    # ========================================================

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


    # ========================================================
    # HTTPS
    # ========================================================

    features["IsHTTPS"] = int(
        parsed_url.scheme.lower() == "https"
    )


    # ========================================================
    # IP ADDRESS DETECTION
    # ========================================================

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


    # ========================================================
    # SUBDOMAIN COUNT
    # ========================================================

    domain_parts = [
        part
        for part in domain_without_port.split(".")
        if part
    ]

    features["SubdomainCount"] = max(
        len(domain_parts) - 2,
        0
    )


    # ========================================================
    # DOUBLE SLASH
    # ========================================================

    features["HasDoubleSlash"] = int(
        "//" in url[8:]
    )


    # ========================================================
    # SUSPICIOUS WORDS
    # ========================================================

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


    # ========================================================
    # URL SHORTENER
    # ========================================================

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


    # ========================================================
    # DOMAIN FEATURES
    # ========================================================

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


    # ========================================================
    # QUERY PARAMETERS
    # ========================================================

    features["QueryParameterCount"] = (

        query.count("=")

        if query

        else 0

    )


    # ========================================================
    # URL ENTROPY
    # ========================================================

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

st.markdown(
    '<div class="title">PhishGuard</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'AI-powered phishing URL detection'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# URL SCANNER
# ============================================================

st.markdown(
    '<div class="scanner">',
    unsafe_allow_html=True
)

url_input = st.text_input(
    "Website URL",
    placeholder="Enter website URL...",
    label_visibility="collapsed"
)

scan = st.button(
    "SCAN URL"
)

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# PREDICTION
# ============================================================

if scan:

    if not url_input.strip():

        st.warning(
            "Please enter a URL."
        )

        st.stop()


    url = url_input.strip()


    try:

        # ----------------------------------------------------
        # Extract features
        # ----------------------------------------------------

        features = extract_url_features(
            url
        )

        feature_df = pd.DataFrame(
            [features]
        )


        # ----------------------------------------------------
        # Make feature order identical
        # to the training dataset
        # ----------------------------------------------------

        feature_df = feature_df[
            feature_columns
        ]


        feature_df = feature_df.astype(
            np.float32
        )


        # ----------------------------------------------------
        # Scale
        # ----------------------------------------------------

        scaled_features = scaler.transform(
            feature_df
        ).astype(np.float32)


        # ----------------------------------------------------
        # Prediction
        # ----------------------------------------------------

        prediction = model.predict(
            scaled_features
        )[0]


        probabilities = model.predict_proba(
            scaled_features
        )[0]


        # label 0 = phishing
        # label 1 = legitimate

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
        # DISPLAY RESULT
        # ====================================================

        if prediction == 0:

            result = "MALICIOUS"

            result_class = "malicious"

        else:

            result = "LEGITIMATE"

            result_class = "legitimate"


        st.markdown(
            f"""
            <div class="result">

                <div class="{result_class}">
                    {result}
                </div>

                <div class="confidence">
                    Confidence: {confidence:.1f}%
                </div>

                <div class="url">
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


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="footer">
        PhishGuard • Machine Learning URL Security
    </div>
    """,
    unsafe_allow_html=True
)