# config_and_utils.py

import os
import pickle
import datetime
import librosa
import numpy as np
import hashlib
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

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

# Ensure required directories exist
os.makedirs(GENUINE_DIR, exist_ok=True)
os.makedirs(CLONED_DIR, exist_ok=True)
os.makedirs(MODEL_BACKUP_DIR, exist_ok=True)

# ============================================
# FEATURE EXTRACTION
# ============================================

def extract_features(file_path):
    """
    Extract advanced acoustic features from audio file.
    Returns numpy array or None if failure.
    """
    try:
        y, sr = librosa.load(file_path, sr=22050, duration=3.0)

        if len(y) < sr * 3.0:
            y = np.pad(y, (0, int(sr * 3.0 - len(y))), mode='constant')

        mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
        delta_mfcc = librosa.feature.delta(mfccs)

        features = np.concatenate([
            np.mean(mfccs, axis=1),
            np.std(mfccs, axis=1),
            np.max(mfccs, axis=1),
            np.min(mfccs, axis=1),
            np.mean(delta_mfcc, axis=1),
            np.mean(librosa.feature.spectral_contrast(y=y, sr=sr), axis=1),
            np.std(librosa.feature.spectral_contrast(y=y, sr=sr), axis=1),
            np.mean(librosa.feature.chroma_stft(y=y, sr=sr), axis=1),
            [
                np.mean(librosa.feature.zero_crossing_rate(y)),
                np.mean(librosa.feature.spectral_centroid(y=y, sr=sr)),
                np.mean(librosa.feature.spectral_rolloff(y=y, sr=sr)),
                np.mean(librosa.feature.rms(y=y))
            ]
        ])

        return features

    except Exception as e:
        log_training_event(f"Feature extraction error | {file_path} | {str(e)}")
        return None


# ============================================
# DATASET & MODEL FUNCTIONS
# ============================================

def load_dataset(genuine_dir, cloned_dir):
    """
    Load dataset and return (X, y)
    """
    features = []
    labels = []

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
    """
    Train ML pipeline and return (model, accuracy)
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    pipeline = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', RandomForestClassifier(
            n_estimators=300,
            max_depth=25,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        ))
    ])

    pipeline.fit(X_train, y_train)

    accuracy = accuracy_score(y_test, pipeline.predict(X_test))

    log_training_event(
        f"Model trained | Accuracy: {accuracy:.4f} | "
        f"Samples: {len(X)}"
    )

    return pipeline, accuracy


def save_model(model, path):
    """
    Save trained model safely.
    """
    try:
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        log_training_event(f"Model saved | Path: {path}")
        return True
    except Exception as e:
        log_training_event(f"Model save error | {str(e)}")
        return False


def load_model(path):
    """
    Load model safely.
    """
    try:
        if os.path.exists(path):
            with open(path, 'rb') as f:
                return pickle.load(f)
        return None
    except Exception as e:
        log_training_event(f"Model load error | {str(e)}")
        return None


# ============================================
# BACKUP & LOGGING
# ============================================

def backup_existing_model():
    """
    Backup current model with timestamp versioning.
    """
    if os.path.exists(MODEL_SAVE_PATH):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(
            MODEL_BACKUP_DIR,
            f"model_{timestamp}.pkl"
        )
        os.rename(MODEL_SAVE_PATH, backup_path)
        log_training_event(f"Model backup created | {backup_path}")


def log_training_event(message):
    """
    Append training log entry with timestamp.
    """
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")


# ============================================
# FILE HASH / DUPLICATE CHECK
# ============================================

def calculate_file_hash(file_path):
    """
    Calculate SHA256 hash of file.
    """
    hash_sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    except Exception as e:
        log_training_event(f"Hashing error | {file_path} | {str(e)}")
        return None


def is_duplicate_file(file_path, target_dir):
    """
    Check whether file already exists in directory using SHA256.
    """
    new_hash = calculate_file_hash(file_path)

    if new_hash is None:
        return False

    for f in os.listdir(target_dir):
        existing_file = os.path.join(target_dir, f)
        existing_hash = calculate_file_hash(existing_file)
        if existing_hash == new_hash:
            return True

    return False
