# voice.py
import streamlit as st
import tempfile
import os
from config_and_utils import (
    GENUINE_DIR, CLONED_DIR, MODEL_SAVE_PATH,
    load_model, extract_features, load_dataset,
    train_model, save_model, log_training_event
)
from auto_training import auto_add_file

st.set_page_config(page_title="Voice Cloning Scam Detector", page_icon="🔊", layout="wide")

if 'model' not in st.session_state:
    st.session_state.model = None
if 'trained' not in st.session_state:
    st.session_state.trained = False

def main():
    st.title("🔊 Voice Cloning Scam Detection System")
    menu = st.sidebar.selectbox("Select Mode", ["🏠 Home", "📊 Train Model", "🔍 Detect Scam"])

    # ---------------- HOME ----------------
    if menu == "🏠 Home":
        st.markdown("### Welcome to Voice Cloning Scam Detector!")
        genuine_count = len([f for f in os.listdir(GENUINE_DIR) if f.endswith(('.wav','.mp3','.flac','.ogg'))])
        cloned_count = len([f for f in os.listdir(CLONED_DIR) if f.endswith(('.wav','.mp3','.flac','.ogg'))])
        st.metric("Genuine Audio Files", genuine_count)
        st.metric("Cloned Audio Files", cloned_count)
        st.metric("Total Samples", genuine_count + cloned_count)
        if os.path.exists(MODEL_SAVE_PATH):
            st.success("✅ Model trained and ready!")
        else:
            st.warning("⚠️ Model not trained yet. Go to 'Train Model'.")

    # ---------------- TRAIN ----------------
    elif menu == "📊 Train Model":
        st.header("📊 Train Detection Model")
        genuine_files = st.file_uploader("Upload Genuine Audio", type=['wav','mp3','flac','ogg'], accept_multiple_files=True, key="genuine")
        cloned_files = st.file_uploader("Upload Cloned Audio", type=['wav','mp3','flac','ogg'], accept_multiple_files=True, key="cloned")

        # Save uploaded files
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
        st.header("🔍 Detect Voice Cloning Scam")
        model = load_model(MODEL_SAVE_PATH)
        if model is None:
            st.error("❌ No trained model found!")
            return

        uploaded_file = st.file_uploader("Upload Audio", type=['wav','mp3','flac','ogg'])
        if uploaded_file:
            st.audio(uploaded_file)
            if st.button("Analyze Audio"):
                with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp_file:
                    tmp_file.write(uploaded_file.getbuffer())
                    tmp_path = tmp_file.name
                features = extract_features(tmp_path)
                if features is not None:
                    features = features.reshape(1, -1)
                    prediction = model.predict(features)[0]
                    probabilities = model.predict_proba(features)[0]
                    confidence = max(probabilities)
                    st.progress(confidence)
                    if prediction == 1:
                        st.error("🚨 CLONED VOICE DETECTED!")
                    else:
                        st.success("✅ GENUINE VOICE")
                    st.write(f"Confidence: {confidence*100:.2f}%")
                    # Auto-add file safely
                    auto_add_file(uploaded_file, prediction, confidence)
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

if __name__ == "__main__":
    main()
    