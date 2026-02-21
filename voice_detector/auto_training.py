# auto_training.py
import os
import json
import tempfile
import time
from datetime import datetime
from config_and_utils import (
    GENUINE_DIR, CLONED_DIR, RETRAIN_THRESHOLD,
    log_training_event, backup_existing_model,
    save_model, load_dataset, train_model
)
from config_and_utils import is_duplicate_file, load_model

NEW_SAMPLE_COUNTER = 0
MODEL_HISTORY_FILE = "training__history.json"
MODEL_VERSION_COUNTER = 1


def save_training_history(entry): 
    """
    Save structured training metadata to JSON file.
    """
    history = []

    if os.path.exists(MODEL_HISTORY_FILE):
        try:
            with open(MODEL_HISTORY_FILE, "r") as f:
                history = json.load(f)
        except:
            history = []

    history.append(entry)

    with open(MODEL_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)


def auto_add_file(uploaded_file, prediction, confidence):
    """
    Automatically add file to dataset if:
    - Confidence >= 0.7
    - Not duplicate
    - Name not already existing

    Retrains model when threshold reached.
    """

    global NEW_SAMPLE_COUNTER
    global MODEL_VERSION_COUNTER

    # ---------------- CONFIDENCE CHECK ----------------
    if confidence < 0.7:
        log_training_event(
            f"Skipped auto-add | {uploaded_file.name} | "
            f"Low confidence: {confidence:.4f}"
        )
        return

    target_dir = CLONED_DIR if prediction == 1 else GENUINE_DIR
    file_path = os.path.join(target_dir, uploaded_file.name)

    # ---------------- EXISTENCE CHECK ----------------
    if os.path.exists(file_path):
        log_training_event(
            f"Skipped auto-add | {uploaded_file.name} already exists"
        )
        return

    # ---------------- DUPLICATE CHECK ----------------
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp_file:
            tmp_file.write(uploaded_file.getbuffer())
            tmp_path = tmp_file.name

        if is_duplicate_file(tmp_path, target_dir):
            log_training_event(
                f"Duplicate detected | {uploaded_file.name} not added"
            )
            os.unlink(tmp_path)
            return

        # Move to dataset
        os.rename(tmp_path, file_path)
        NEW_SAMPLE_COUNTER += 1

        log_training_event(
            f"Auto-added | {uploaded_file.name} | "
            f"{'CLONED' if prediction == 1 else 'GENUINE'} | "
            f"Confidence: {confidence:.4f} | "
            f"New Count: {NEW_SAMPLE_COUNTER}"
        )

    except Exception as e:
        log_training_event(
            f"Auto-add error | {uploaded_file.name} | {str(e)}"
        )
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return

    # ---------------- AUTO RETRAIN System----------------
    if NEW_SAMPLE_COUNTER >= RETRAIN_THRESHOLD:
        try:
            log_training_event("Retrain threshold reached. Starting retraining...")

            backup_existing_model()

            start_time = time.time()

            X, y = load_dataset(GENUINE_DIR, CLONED_DIR)
            dataset_size = len(X)

            model, accuracy = train_model(X, y)

            versioned_model_name = f"{GENUINE_DIR}/voice_detector_model_v{MODEL_VERSION_COUNTER}.pkl"

            if save_model(model, versioned_model_name):
                duration = time.time() - start_time

                training_metadata = {
                    "version": MODEL_VERSION_COUNTER,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "accuracy": round(float(accuracy), 4),
                    "training_duration_sec": round(duration, 2),
                    "dataset_size": dataset_size
                }

                save_training_history(training_metadata)

                log_training_event(
                    f"Model retrained successfully | "
                    f"Version: v{MODEL_VERSION_COUNTER} | "
                    f"Accuracy: {accuracy:.4f} | "
                    f"Duration: {duration:.2f}s | "
                    f"Dataset Size: {dataset_size}"
                )

                MODEL_VERSION_COUNTER += 1
                NEW_SAMPLE_COUNTER = 0

        except Exception as e:
            log_training_event(
                f"Retraining failed | Error: {str(e)}"
            )

