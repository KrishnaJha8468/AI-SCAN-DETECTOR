# auto_training.py
import os
import tempfile
from config_and_utils import (
    GENUINE_DIR, CLONED_DIR, RETRAIN_THRESHOLD,
    log_training_event, backup_existing_model,
    save_model, load_dataset, train_model
)
from config_and_utils import is_duplicate_file, load_model

NEW_SAMPLE_COUNTER = 0

def auto_add_file(uploaded_file, prediction, confidence):
    """
    Automatically add file to dataset if confidence >= 0.7 and not duplicate
    """
    global NEW_SAMPLE_COUNTER
    if confidence < 0.7:
        return

    target_dir = CLONED_DIR if prediction == 1 else GENUINE_DIR
    file_path = os.path.join(target_dir, uploaded_file.name)

    # Already exists by name
    if os.path.exists(file_path):
        return

    # Save temp file to check duplicates
    with tempfile.NamedTemporaryFile(delete=False, suffix=".wav") as tmp_file:
        tmp_file.write(uploaded_file.getbuffer())
        tmp_path = tmp_file.name

    if is_duplicate_file(tmp_path, target_dir):
        os.unlink(tmp_path)
        return

    # Move file to target dir
    os.rename(tmp_path, file_path)
    NEW_SAMPLE_COUNTER += 1
    log_training_event(f"Auto-added new file: {uploaded_file.name}")

    # Retrain if threshold reached
    if NEW_SAMPLE_COUNTER >= RETRAIN_THRESHOLD:
        backup_existing_model()
        X, y = load_dataset(GENUINE_DIR, CLONED_DIR)
        model, accuracy = train_model(X, y)
        if save_model(model, GENUINE_DIR + "/voice_detector_model.pkl"):
            NEW_SAMPLE_COUNTER = 0
            log_training_event(f"Model retrained automatically. Accuracy: {accuracy:.4f}")
            