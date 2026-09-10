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


/* ================= HEADER ================= */

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


/* ================= SCANNER ================= */

.scanner {
    background: #101620;
    border: 1px solid #202b3b;
    border-radius: 18px;
    padding: 25px;
    margin-bottom: 25px;
}


/* ================= URL INPUT ================= */

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


/* ================= BUTTON ================= */

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


/* ================= METRIC CARDS ================= */

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


/* ================= URL CARD ================= */

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


/* ================= FOOTER ================= */

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 35px;
}


/* ================= MOBILE ================= */

@media (max-width: 600px) {

    .title {
        font-size: 42px;
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

        parsed_url = urlparse(
            "http://" + url
        )

    domain = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    domain_without_port = domain.split(":")[0]

    features = {}

    # -------------------------------
    # URL LENGTH
    # -------------------------------

    features["URLLength"] = len(url)

    features["DomainLength"] = len(
        domain_without_port
    )

    features["PathLength"] = len(path)

    features["QueryLength"] = len(query)


    # -------------------------------
    # SPECIAL CHARACTERS
    # -------------------------------

    features["NumDots"] = url.count(".")

    features["NumHyphens"] = url.count("-")

    features["NumUnderscores"] = url.count("_")

    features["NumSlashes"] = url.count("/")

    features["NumQuestionMarks"] = url.count("?")

    features["NumEqual"] = url.count("=")

    features["NumAt"] = url.count("@")

    features["NumAmpersand"] = url.count("&")

    features["NumPercent"] = url.count("%")


    # -------------------------------
    # CHARACTER COUNTS
    # -------------------------------

    features["NumDigits"] = sum(
        character.isdigit()
        for character in url
    )

    features["NumLetters"] = sum(
        character.isalpha()
        for character in url
    )

    features["NumSpecialChars"] = sum(
        not character.isalnum()
        for character in url
    )


    # -------------------------------
    # HTTPS
    # -------------------------------

    features["IsHTTPS"] = int(
        parsed_url.scheme.lower() == "https"
    )


    # -------------------------------
    # IP ADDRESS
    # -------------------------------

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


    # -------------------------------
    # SUBDOMAIN
    # -------------------------------

    domain_parts = [
        part
        for part in domain_without_port.split(".")
        if part
    ]

    features["SubdomainCount"] = max(
        len(domain_parts) - 2,
        0
    )


    # -------------------------------
    # DOUBLE SLASH
    # -------------------------------

    features["HasDoubleSlash"] = int(
        "//" in url[8:]
    )


    # -------------------------------
    # SUSPICIOUS WORDS
    # -------------------------------

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

        for word
        in suspicious_words

    )


    # -------------------------------
    # SHORTENED URL
    # -------------------------------

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


    # -------------------------------
    # DOMAIN CHARACTERISTICS
    # -------------------------------

    features["DomainHasHyphen"] = int(
        "-" in domain_without_port
    )

    features["DomainHasDigits"] = int(

        any(

            character.isdigit()

            for character
            in domain_without_port

        )

    )


    # -------------------------------
    # QUERY PARAMETERS
    # -------------------------------

    features["QueryParameterCount"] = (

        query.count("=")

        if query

        else 0

    )


    # -------------------------------
    # URL ENTROPY
    # -------------------------------

    if len(url) > 0:

        probabilities = [

            url.count(character) / len(url)

            for character
            in set(url)

        ]

        entropy = -sum(

            probability
            * math.log2(probability)

            for probability
            in probabilities

            if probability > 0

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
# SCAN URL
# =========================================================

if scan:

    if not url_input.strip():

        st.warning(
            "Please enter a URL to scan."
        )

        st.stop()


    url = url_input.strip()


    try:

        # =================================================
        # FEATURE EXTRACTION
        # =================================================

        features = extract_url_features(url)


        # =================================================
        # CHECK MODEL FEATURES
        # =================================================

        missing_features = [

            column

            for column
            in feature_columns

            if column not in features

        ]


        if missing_features:

            st.error(
                "The model requires features that "
                "are not available."
            )

            st.code(
                str(missing_features)
            )

            st.stop()


        # =================================================
        # CREATE DATAFRAME
        # =================================================

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


        # =================================================
        # SCALE FEATURES
        # =================================================

        scaled_features = scaler.transform(
            feature_df
        ).astype(np.float32)


        # =================================================
        # MODEL PREDICTION
        # =================================================

        prediction = model.predict(
            scaled_features
        )[0]


        probabilities = model.predict_proba(
            scaled_features
        )[0]


        # =================================================
        # GET CORRECT CLASS PROBABILITIES
        # =================================================

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


        # =================================================
        # RESULT INFORMATION
        # =================================================

        if prediction == 0:

            result_title = "PHISHING DETECTED"

            probability = phishing_probability

            risk = "HIGH RISK"

            description = (
                "This URL shows characteristics "
                "associated with phishing activity. "
                "Avoid entering personal or sensitive "
                "information."
            )

            background = (
                "linear-gradient("
                "135deg, #450a0a, #991b1b, #450a0a)"
            )

            border = "#ef4444"

            accent = "#fca5a5"


        else:

            result_title = "URL APPEARS SAFE"

            probability = legitimate_probability

            risk = "LOW RISK"

            description = (
                "This URL does not show strong phishing "
                "characteristics based on the trained "
                "machine learning model."
            )

            background = (
                "linear-gradient("
                "135deg, #052e16, #15803d, #052e16)"
            )

            border = "#22c55e"

            accent = "#86efac"


        # =================================================
        # FULL COLOR RESULT BANNER
        # =================================================

        st.html(f"""

        <div style="
            width:100%;
            box-sizing:border-box;

            background:{background};

            border:2px solid {border};

            border-radius:22px;

            padding:45px 25px;

            text-align:center;

            margin:25px 0 20px 0;

            font-family:Arial,sans-serif;

            box-shadow:
                0 10px 35px rgba(0,0,0,0.30);
        ">

            <div style="
                color:white;
                font-size:31px;
                font-weight:800;
                letter-spacing:1px;
                margin-bottom:18px;
            ">
                {result_title}
            </div>


            <div style="
                color:white;
                font-size:68px;
                font-weight:900;
                line-height:1;
                margin:10px 0;
            ">
                {probability:.2f}%
            </div>


            <div style="
                color:{accent};
                font-size:12px;
                font-weight:800;
                letter-spacing:2px;
                text-transform:uppercase;
            ">
                PREDICTION PROBABILITY
            </div>


            <div style="
                display:inline-block;

                margin-top:22px;

                padding:9px 24px;

                border-radius:30px;

                background:rgba(0,0,0,0.28);

                border:1px solid
                rgba(255,255,255,0.25);

                color:white;

                font-size:12px;

                font-weight:800;

                letter-spacing:1.5px;
            ">
                {risk}
            </div>


            <div style="
                color:rgba(255,255,255,0.78);

                font-size:13px;

                line-height:1.6;

                max-width:600px;

                margin:20px auto 0 auto;
            ">
                {description}
            </div>

        </div>

        """)


        # =================================================
        # MODEL METRICS
        # =================================================

        model_accuracy = 99.94


        st.html(f"""

        <div style="
            display:flex;
            gap:15px;
            width:100%;
            margin-top:20px;
            font-family:Arial,sans-serif;
        ">

            <div style="
                flex:1;
                background:#101620;
                border:1px solid #202b3b;
                border-radius:16px;
                padding:22px 10px;
                text-align:center;
            ">

                <div style="
                    color:white;
                    font-size:25px;
                    font-weight:800;
                ">
                    {model_accuracy:.2f}%
                </div>

                <div style="
                    color:#7f8a9d;
                    font-size:10px;
                    margin-top:6px;
                    letter-spacing:1px;
                ">
                    MODEL ACCURACY
                </div>

            </div>


            <div style="
                flex:1;
                background:#101620;
                border:1px solid #202b3b;
                border-radius:16px;
                padding:22px 10px;
                text-align:center;
            ">

                <div style="
                    color:white;
                    font-size:25px;
                    font-weight:800;
                ">
                    {confidence:.2f}%
                </div>

                <div style="
                    color:#7f8a9d;
                    font-size:10px;
                    margin-top:6px;
                    letter-spacing:1px;
                ">
                    CONFIDENCE
                </div>

            </div>


            <div style="
                flex:1;
                background:#101620;
                border:1px solid #202b3b;
                border-radius:16px;
                padding:22px 10px;
                text-align:center;
            ">

                <div style="
                    color:white;
                    font-size:25px;
                    font-weight:800;
                ">
                    {'HIGH' if prediction == 0 else 'LOW'}
                </div>

                <div style="
                    color:#7f8a9d;
                    font-size:10px;
                    margin-top:6px;
                    letter-spacing:1px;
                ">
                    RISK LEVEL
                </div>

            </div>

        </div>

        """)


        # =================================================
        # URL CARD
        # =================================================

        st.html(f"""

        <div style="
            background:#0c1119;
            border:1px solid #202b3b;
            border-radius:14px;
            padding:18px;
            margin-top:20px;
            font-family:Arial,sans-serif;
        ">

            <div style="
                color:#66748a;
                font-size:10px;
                font-weight:700;
                letter-spacing:1.5px;
                text-transform:uppercase;
                margin-bottom:8px;
            ">
                ANALYZED URL
            </div>

            <div style="
                color:#cbd5e1;
                font-size:13px;
                word-break:break-all;
            ">
                {url}
            </div>

        </div>

        """)


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

st.html("""

<div style="
    text-align:center;
    color:#475569;
    font-size:11px;
    margin-top:35px;
    font-family:Arial,sans-serif;
">
    PhishGuard • Machine Learning URL Security
</div>

""")