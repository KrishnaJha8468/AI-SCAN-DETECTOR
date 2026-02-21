# config_and_utils.py
import os
import pickle
import datetime
import librosa
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import hashlib

# ============================================
# CONFIGURATION
# ============================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GENUINE_DIR = os.path.join(BASE_DIR, "genuine_audio")
CLONED_DIR = os.path.join(BASE_DIR, "cloned_audio")
MODEL_SAVE_PATH = os.path.join(BASE_DIR, "voice_detector_model.pkl")
MODEL_BACKUP_DIR = os.path.join(BASE_DIR, "model_versions")
LOG_FILE = os.path.join(BASE_DIR, "training_log.txt")
RETRAIN_THRESHOLD = 3

# Ensure folders exist
os.makedirs(GENUINE_DIR, exist_ok=True)
os.makedirs(CLONED_DIR, exist_ok=True)
os.makedirs(MODEL_BACKUP_DIR, exist_ok=True)

# ============================================
# FEATURE EXTRACTION
# ============================================
def extract_features(file_path):
    try:
        y, sr = librosa.load(file_path, sr=22050, duration=3.0)
        if len(y) < sr * 3.0:
            y = np.pad(y, (0, int(sr * 3.0 - len(y))), mode='constant')

        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
        mfccs_mean = np.mean(mfccs, axis=1)
        mfccs_std = np.std(mfccs, axis=1)
        mfccs_max = np.max(mfccs, axis=1)
        mfccs_min = np.min(mfccs, axis=1)
        delta_mfcc = librosa.feature.delta(mfccs)
        delta_mfcc_mean = np.mean(delta_mfcc, axis=1)
        spectral_contrast = librosa.feature.spectral_contrast(y=y, sr=sr)
        spectral_contrast_mean = np.mean(spectral_contrast, axis=1)
        spectral_contrast_std = np.std(spectral_contrast, axis=1)
        chroma = librosa.feature.chroma_stft(y=y, sr=sr)
        chroma_mean = np.mean(chroma, axis=1)
        zcr_mean = np.mean(librosa.feature.zero_crossing_rate(y))
        spectral_centroid_mean = np.mean(librosa.feature.spectral_centroid(y=y, sr=sr))
        spectral_rolloff_mean = np.mean(librosa.feature.spectral_rolloff(y=y, sr=sr))
        rms_mean = np.mean(librosa.feature.rms(y=y))
        features = np.concatenate([
            mfccs_mean, mfccs_std, mfccs_max, mfccs_min,
            delta_mfcc_mean,
            spectral_contrast_mean, spectral_contrast_std,
            chroma_mean,
            [zcr_mean, spectral_centroid_mean, spectral_rolloff_mean, rms_mean]
        ])
        return features
    except Exception as e:
        print(f"Error processing audio: {e}")
        return None

# ============================================
# DATASET & MODEL FUNCTIONS
# ============================================
def load_dataset(genuine_dir, cloned_dir):
    features, labels = [], []
    for folder, label in [(genuine_dir, 0), (cloned_dir, 1)]:
        for file in os.listdir(folder):
            if file.endswith(('.wav', '.mp3', '.flac', '.ogg')):
                path = os.path.join(folder, file)
                feat = extract_features(path)
                if feat is not None:
                    features.append(feat)
                    labels.append(label)
    return np.array(features), np.array(labels)

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=300, max_depth=25,
            min_samples_split=5, min_samples_leaf=2,
            random_state=42, n_jobs=-1
        ))
    ])
    pipeline.fit(X_train, y_train)
    accuracy = accuracy_score(y_test, pipeline.predict(X_test))
    return pipeline, accuracy

def save_model(model, path):
    try:
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        return True
    except Exception as e:
        print(f"Error saving model: {e}")
        return False

def load_model(path):
    try:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return pickle.load(f)
        return None
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

# ============================================
# BACKUP & LOGGING
# ============================================
def backup_existing_model():
    if os.path.exists(MODEL_SAVE_PATH):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        os.rename(MODEL_SAVE_PATH, os.path.join(MODEL_BACKUP_DIR, f"model_{timestamp}.pkl"))

def log_training_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

# ============================================
# FILE HASH / DUPLICATE CHECK
# ============================================
def calculate_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def is_duplicate_file(file_path, target_dir):
    new_hash = calculate_file_hash(file_path)
    for f in os.listdir(target_dir):
        if calculate_file_hash(os.path.join(target_dir, f)) == new_hash:
            return True
    return False
