# ============================================================
# PHISHGUARD - SIMPLE PROFESSIONAL UI
# ============================================================

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>

.stApp {
    background: #080b12;
}

.block-container {
    max-width: 750px;
    padding-top: 5rem;
}

/* Title */
.title {
    text-align: center;
    font-size: 48px;
    font-weight: 800;
    color: white;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    color: #8b95a7;
    font-size: 15px;
    margin-bottom: 45px;
}

/* Scanner */
.scanner {
    background: #111722;
    border: 1px solid #202938;
    border-radius: 18px;
    padding: 25px;
}

/* Input */
.stTextInput input {
    background: #080c14 !important;
    color: white !important;
    border: 1px solid #303b4f !important;
    border-radius: 10px !important;
    height: 52px !important;
    font-size: 15px !important;
}

/* Button */
.stButton button {
    width: 100%;
    height: 50px;
    border-radius: 10px;
    background: #2563eb;
    color: white;
    border: none;
    font-weight: 700;
    font-size: 15px;
}

.stButton button:hover {
    background: #1d4ed8;
}

/* Result */
.result {
    margin-top: 25px;
    padding: 35px 20px;
    border-radius: 18px;
    text-align: center;
    background: #111722;
    border: 1px solid #202938;
}

.legitimate {
    color: #22c55e;
    font-size: 38px;
    font-weight: 800;
}

.malicious {
    color: #ef4444;
    font-size: 38px;
    font-weight: 800;
}

.confidence {
    color: #8b95a7;
    margin-top: 8px;
    font-size: 14px;
}

.url {
    color: #64748b;
    font-size: 12px;
    margin-top: 20px;
    word-break: break-all;
}

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 35px;
}

</style>
""", unsafe_allow_html=True)


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
# SCANNER
# ============================================================

st.markdown(
    '<div class="scanner">',
    unsafe_allow_html=True
)

url_input = st.text_input(
    "URL",
    placeholder="Enter website URL...",
    label_visibility="collapsed"
)

scan = st.button("SCAN URL")

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# PREDICTION
# ============================================================

if scan:

    if not url_input.strip():

        st.warning("Please enter a URL.")

    else:

        try:

            url = url_input.strip()

            # Extract URL features
            features = extract_url_features(url)

            feature_df = pd.DataFrame([features])

            # Match training feature order
            feature_df = feature_df[feature_columns]

            feature_df = feature_df.astype(np.float32)

            # Scale
            scaled = scaler.transform(
                feature_df
            ).astype(np.float32)

            # Prediction
            prediction = model.predict(scaled)[0]

            probability = model.predict_proba(scaled)[0]

            confidence = max(probability) * 100

            # =================================================
            # RESULT
            # =================================================

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
                f"Unable to analyze URL: {e}"
            )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    '<div class="footer">'
    'PhishGuard • Gaussian Naive Bayes • URL Analysis'
    '</div>',
    unsafe_allow_html=True
)