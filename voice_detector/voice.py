# voice.py
import streamlit as st
import tempfile
import os
import numpy as np
import pandas as pd
from config_and_utils import (
    GENUINE_DIR, CLONED_DIR, MODEL_SAVE_PATH,
    load_model, extract_features, load_dataset,
    train_model, save_model, log_training_event
)
from auto_training import auto_add_file

st.set_page_config(page_title="Voice Cloning Scam Detector", page_icon="🔊", layout="wide")

# ---------------- CUSTOM PROFESSIONAL STYLING ----------------
st.markdown("""
<style>
.big-title {
    font-size: 42px;
    font-weight: 800;
    text-align: center;
    animation: glow 2s ease-in-out infinite alternate;
}
@keyframes glow {
    from { color: #00c6ff; }
    to { color: #0072ff; }
}
.result-box {
    padding: 20px;
    border-radius: 15px;
    background: linear-gradient(135deg, #1f1f1f, #2b2b2b);
    box-shadow: 0px 4px 20px rgba(0,0,0,0.4);
    color: white;
}
.metric-card {
    padding: 15px;
    border-radius: 10px;
    background-color: #111827;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

if 'model' not in st.session_state:
    st.session_state.model = None
if 'trained' not in st.session_state:
    st.session_state.trained = False

def main():
    st.markdown('<div class="big-title">🔊 Voice Cloning Scam Detection System</div>', unsafe_allow_html=True)

    menu = st.sidebar.selectbox("Select Mode", ["🏠 Home", "📊 Train Model", "🔍 Detect Scam"])

    # ---------------- HOME ----------------
    if menu == "🏠 Home":
        st.markdown("### 📊 Dataset Overview")

        genuine_count = len([f for f in os.listdir(GENUINE_DIR) if f.endswith(('.wav','.mp3','.flac','.ogg'))])
        cloned_count = len([f for f in os.listdir(CLONED_DIR) if f.endswith(('.wav','.mp3','.flac','.ogg'))])

        col1, col2, col3 = st.columns(3)
        col1.metric("Genuine Files", genuine_count)
        col2.metric("Cloned Files", cloned_count)
        col3.metric("Total Samples", genuine_count + cloned_count)

        if os.path.exists(MODEL_SAVE_PATH):
            st.success("✅ Model trained and ready!")
        else:
            st.warning("⚠️ Model not trained yet. Go to 'Train Model'.")

    # ---------------- TRAIN ----------------
    elif menu == "📊 Train Model":
        st.header("📊 Train Detection Model")

        genuine_files = st.file_uploader("Upload Genuine Audio", type=['wav','mp3','flac','ogg'], accept_multiple_files=True, key="genuine")
        cloned_files = st.file_uploader("Upload Cloned Audio", type=['wav','mp3','flac','ogg'], accept_multiple_files=True, key="cloned")

        for file in (genuine_files or []):
            file_path = os.path.join(GENUINE_DIR, file.name)
            if not os.path.exists(file_path):
                with open(file_path, "wb") as f:
                    f.write(file.getbuffer())

        for file in (cloned_files or []):
            file_path = os.path.join(CLONED_DIR, file.name)
            if not os.path.exists(file_path):
                with open(file_path, "wb") as f:
                    f.write(file.getbuffer())

        st.success("✅ Files saved to dataset!")

        if st.button("🚀 Train Model"):
            X, y = load_dataset(GENUINE_DIR, CLONED_DIR)
            if len(X) < 10:
                st.error("Not enough samples to train!")
            else:
                model, accuracy = train_model(X, y)
                if save_model(model, MODEL_SAVE_PATH):
                    st.session_state.model = model
                    st.session_state.trained = True
                    st.success(f"✅ Model trained! Accuracy: {accuracy*100:.2f}%")
                    log_training_event(f"Model trained manually. Accuracy: {accuracy:.4f}")

    # ---------------- DETECT ----------------
    elif menu == "🔍 Detect Scam":
        st.header("🔍 AI Voice Authenticity Analyzer")

        model = load_model(MODEL_SAVE_PATH)
        if model is None:
            st.error("❌ No trained model found!")
            return

        uploaded_file = st.file_uploader("Upload Audio", type=['wav','mp3','flac','ogg'])

        if uploaded_file:
            st.audio(uploaded_file)

            if st.button("Analyze Audio"):
                with st.spinner("Analyzing voice patterns..."):
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp_file:
                        tmp_file.write(uploaded_file.getbuffer())
                        tmp_path = tmp_file.name

                    features = extract_features(tmp_path)

                    if features is not None:
                        features = features.reshape(1, -1)
                        prediction = model.predict(features)[0]
                        probabilities = model.predict_proba(features)[0]
                        confidence = max(probabilities)

                        # ---------------- RESULT DISPLAY ----------------
                        st.markdown('<div class="result-box">', unsafe_allow_html=True)

                        if prediction == 1:
                            st.error("🚨 CLONED VOICE DETECTED")
                        else:
                            st.success("✅ GENUINE VOICE DETECTED")

                        st.progress(confidence)
                        st.write(f"### 🎯 Confidence Level: {confidence*100:.2f}%")

                        st.markdown("---")
                        st.write("## 🧠 Why this Result?")

                        # Probability comparison
                        prob_df = pd.DataFrame({
                            "Category": ["Genuine", "Cloned"],
                            "Probability": probabilities
                        })
                        st.bar_chart(prob_df.set_index("Category"))

                        # Feature breakdown
                        st.write("### 📊 Extracted Audio Features")
                        feature_values = features.flatten()
                        feature_df = pd.DataFrame({
                            "Feature Index": np.arange(len(feature_values)),
                            "Value": feature_values
                        })

                        st.dataframe(feature_df)

                        st.markdown("""
                        **Explanation:**
                        - The AI model analyzes frequency spectrum patterns.
                        - It evaluates acoustic consistency.
                        - It compares learned patterns from genuine vs cloned datasets.
                        - The probabilities above show how strongly the sample matches each category.
                        """)

                        st.markdown('</div>', unsafe_allow_html=True)

                        auto_add_file(uploaded_file, prediction, confidence)

                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)


if __name__ == "__main__":
    main()
    