import streamlit as st
import pandas as pd
import numpy as np
import pickle

# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="wide"
)

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown("""
<style>

.main {
    padding-top: 1rem;
}

.title {
    font-size: 42px;
    font-weight: 700;
    text-align: center;
    margin-bottom: 5px;
}

.subtitle {
    text-align: center;
    font-size: 18px;
    margin-bottom: 30px;
}

.result-box {
    padding: 25px;
    border-radius: 12px;
    text-align: center;
    margin-top: 20px;
}

.phishing {
    background-color: #ffe5e5;
    border: 2px solid #d32f2f;
}

.legitimate {
    background-color: #e6f4ea;
    border: 2px solid #2e7d32;
}

.result-title {
    font-size: 30px;
    font-weight: 700;
}

.result-text {
    font-size: 18px;
}

</style>
""", unsafe_allow_html=True)

# ============================================================
# LOAD PICKLE
# ============================================================

@st.cache_resource
def load_model():

    with open("phishing_naive_bayes.pkl", "rb") as file:
        package = pickle.load(file)

    return (
        package["model"],
        package["scaler"],
        package["feature_columns"]
    )


try:

    model, scaler, feature_columns = load_model()

except Exception as e:

    st.error("Unable to load the model.")

    st.code(str(e))

    st.stop()

# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="title">Phishing URL Detection System</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Machine Learning based classification using Gaussian Naive Bayes'
    '</div>',
    unsafe_allow_html=True
)

st.divider()

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("About the Model")

st.sidebar.write(
    "This application uses a trained Gaussian Naive Bayes "
    "classifier to classify URL characteristics as "
    "Phishing or Legitimate."
)

st.sidebar.write(
    f"Number of features: {len(feature_columns)}"
)

st.sidebar.write(
    "Model: Gaussian Naive Bayes"
)

# ============================================================
# INPUT SECTION
# ============================================================

st.subheader("URL Feature Analysis")

st.write(
    "Enter the URL characteristics used during model training."
)

# Create columns
col1, col2, col3 = st.columns(3)

inputs = {}

# ============================================================
# FEATURE INPUTS
# ============================================================

for i, feature in enumerate(feature_columns):

    # Determine column
    if i % 3 == 0:
        column = col1
    elif i % 3 == 1:
        column = col2
    else:
        column = col3

    # Use numeric input for every feature
    inputs[feature] = column.number_input(
        feature,
        value=0.0,
        step=1.0,
        format="%.4f"
    )

# ============================================================
# PREDICTION BUTTON
# ============================================================

st.divider()

predict_button = st.button(
    "Analyze URL",
    type="primary",
    use_container_width=True
)

# ============================================================
# PREDICTION
# ============================================================

if predict_button:

    try:

        # Create dataframe in EXACT feature order
        input_df = pd.DataFrame(
            [inputs],
            columns=feature_columns
        )

        # Convert to numeric
        input_df = input_df.apply(
            pd.to_numeric,
            errors="coerce"
        )

        input_df = input_df.fillna(0)

        # Scale exactly like training
        input_scaled = scaler.transform(input_df)

        input_scaled = input_scaled.astype(
            np.float32
        )

        # Prediction
        prediction = model.predict(
            input_scaled
        )[0]

        # Probability
        probability = model.predict_proba(
            input_scaled
        )[0]

        # ----------------------------------------------------
        # IMPORTANT:
        # Dataset:
        # 0 = Phishing
        # 1 = Legitimate
        # ----------------------------------------------------

        if prediction == 0:

            result = "Potentially Phishing"
            confidence = probability[0] * 100

            st.markdown(
                f"""
                <div class="result-box phishing">

                <div class="result-title">
                Potentially Phishing
                </div>

                <div class="result-text">
                The URL characteristics show patterns
                associated with phishing.
                </div>

                <br>

                <strong>Model Confidence: {confidence:.2f}%</strong>

                </div>
                """,
                unsafe_allow_html=True
            )

        else:

            result = "Legitimate"
            confidence = probability[1] * 100

            st.markdown(
                f"""
                <div class="result-box legitimate">

                <div class="result-title">
                Legitimate
                </div>

                <div class="result-text">
                The URL characteristics appear consistent
                with legitimate websites.
                </div>

                <br>

                <strong>Model Confidence: {confidence:.2f}%</strong>

                </div>
                """,
                unsafe_allow_html=True
            )

        # ----------------------------------------------------
        # PROBABILITY
        # ----------------------------------------------------

        st.subheader("Prediction Probability")

        probability_df = pd.DataFrame(
            {
                "Class": [
                    "Phishing",
                    "Legitimate"
                ],
                "Probability": [
                    probability[0],
                    probability[1]
                ]
            }
        )

        st.bar_chart(
            probability_df.set_index("Class")
        )

        # ----------------------------------------------------
        # MODEL INFORMATION
        # ----------------------------------------------------

        st.subheader("Analysis Summary")

        summary_col1, summary_col2, summary_col3 = st.columns(3)

        summary_col1.metric(
            "Prediction",
            result
        )

        summary_col2.metric(
            "Phishing Probability",
            f"{probability[0] * 100:.2f}%"
        )

        summary_col3.metric(
            "Legitimate Probability",
            f"{probability[1] * 100:.2f}%"
        )

    except Exception as e:

        st.error(
            "Prediction failed. Please check the feature values."
        )

        st.code(str(e))

# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "Phishing URL Detection | Gaussian Naive Bayes | "
    "Machine Learning Project"
)