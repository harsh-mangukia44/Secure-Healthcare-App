import sqlite3
import os
import json
from datetime import datetime
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
import fitz  # PyMuPDF
from PIL import Image, ExifTags
import logging
import pandas as pd

# --- Configuration ---
DATABASE_PATH = os.path.join("database", "health_app.db")
UPLOAD_FOLDER = "uploads"
ENCRYPTION_KEY_ENV_VAR = "APP_ENCRYPTION_KEY" # Store this securely, e.g., in HF Spaces secrets

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

# --- Encryption ---
_key = None
_fernet_instance = None

def load_or_generate_key():
    global _key, _fernet_instance
    if _fernet_instance: # If instance exists, key is already loaded and validated
        return _key

    env_key_str = os.getenv(ENCRYPTION_KEY_ENV_VAR)
    if env_key_str:
        logger.info(f"Found encryption key in env var {ENCRYPTION_KEY_ENV_VAR}.")
        current_key_bytes = env_key_str.encode()
    else:
        logger.warning(f"WARNING: {ENCRYPTION_KEY_ENV_VAR} not set. Generating a new key FOR THIS SESSION.")
        current_key_bytes = Fernet.generate_key() # This generates bytes
        logger.warning(f"Generated demo key: {current_key_bytes.decode()}. Set this as {ENCRYPTION_KEY_ENV_VAR} for persistence across sessions.")

    try:
        # Validate key by creating a Fernet instance. This will raise error if key is bad.
        temp_fernet = Fernet(current_key_bytes)
        # Test encryption/decryption with the key
        test_data = b"test_encryption_validation"
        token = temp_fernet.encrypt(test_data)
        if temp_fernet.decrypt(token) != test_data:
            raise ValueError("Fernet key validation failed: encrypt/decrypt test mismatch.")
        
        _key = current_key_bytes
        _fernet_instance = temp_fernet # Store the validated instance
        logger.info("Encryption key loaded and validated successfully.")
    except Exception as e:
        logger.error(f"Failed to load or validate encryption key: {e}. Key (first 10 bytes if available): '{str(current_key_bytes)[:10]}...'")
        _key = None 
        _fernet_instance = None
        # Critical error, re-raise or handle appropriately for your app's startup
        raise ValueError(f"Invalid or unusable encryption key setup: {e}") from e
    return _key

def get_fernet():
    global _fernet_instance
    if not _fernet_instance:
        load_or_generate_key() # This will set _fernet_instance or raise error
        if not _fernet_instance: # Should ideally not be reached if load_or_generate_key raises
             raise Exception("CRITICAL: Fernet instance could not be initialized.")
    return _fernet_instance

def encrypt_data(data): # Expects bytes or str, returns encrypted bytes
    if isinstance(data, str):
        data = data.encode()
    return get_fernet().encrypt(data)

def encrypt_data(data):
    if isinstance(data, str):
        data = data.encode()
    return get_fernet().encrypt(data)

def decrypt_data_as_bytes(token): # Specifically for decrypting to raw bytes
    if isinstance(token, str): # Should ideally be bytes already if read from file
        token = token.encode()
    try:
        logger.debug(f"Attempting to decrypt token of length: {len(token)} with key {_key[:10 if _key else 0]}...")
        decrypted_bytes = get_fernet().decrypt(token)
        logger.debug(f"Successfully decrypted to {len(decrypted_bytes)} bytes.")
        return decrypted_bytes
    except InvalidToken:
        logger.error("DECRYPTION FAILED: InvalidToken. VERY LIKELY an incorrect encryption key or corrupted data.")
        return None
    except Exception as e:
        logger.error(f"Decryption to bytes failed with unexpected error: {e}")
        return None

def decrypt_data(token): # For decrypting to string (e.g., metadata)
    decrypted_bytes = decrypt_data_as_bytes(token)
    if decrypted_bytes:
        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as ude:
            logger.error(f"Failed to decode decrypted bytes to UTF-8 string: {ude}. Returning raw bytes representation.")
            return str(decrypted_bytes) # Or handle as error
    return None

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

# --- Database ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('patient', 'doctor', 'admin')),
            full_name TEXT,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Patient Profiles (can be extended)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patient_profiles (
            patient_user_id INTEGER PRIMARY KEY,
            dob TEXT, -- YYYY-MM-DD
            -- other demographic data
            FOREIGN KEY (patient_user_id) REFERENCES users(id)
        )
    ''')

    # Health Records
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS health_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_user_id INTEGER NOT NULL,
            record_type TEXT NOT NULL, -- 'Lab Report', 'Imaging', 'Prescription', 'Note'
            original_file_name TEXT, -- Encrypted
            encrypted_file_path TEXT NOT NULL, -- Path to the encrypted file
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT, -- JSON string, encrypted (e.g., summary, extracted fields)
            file_hash TEXT, -- Hash of the original file to detect duplicates/tampering (optional)
            FOREIGN KEY (patient_user_id) REFERENCES users(id)
        )
    ''')

    # Record Access Permissions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS record_access_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id INTEGER NOT NULL,
            doctor_user_id INTEGER NOT NULL,
            granted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'granted' CHECK(status IN ('granted', 'revoked')),
            FOREIGN KEY (record_id) REFERENCES health_records(id),
            FOREIGN KEY (doctor_user_id) REFERENCES users(id),
            UNIQUE(record_id, doctor_user_id) -- Ensure a doctor can't have multiple grant statuses for the same record
        )
    ''')

    # Appointments
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_user_id INTEGER NOT NULL,
            doctor_user_id INTEGER NOT NULL,
            appointment_datetime TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed', 'completed', 'cancelled')),
            notes TEXT, -- Encrypted
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_user_id) REFERENCES users(id),
            FOREIGN KEY (doctor_user_id) REFERENCES users(id)
        )
    ''')

    # Access Logs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, -- Can be NULL if system action
            action TEXT NOT NULL,
            target_type TEXT, -- e.g., 'record', 'patient_profile', 'appointment'
            target_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT, -- JSON string for extra info
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(module)s - %(funcName)s - %(message)s')
logger = logging.getLogger(__name__)

def log_access(user_id, action, target_type=None, target_id=None, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    details_json = json.dumps(details) if details else None
    cursor.execute('''
        INSERT INTO access_logs (user_id, action, target_type, target_id, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, action, target_type, target_id, details_json))
    conn.commit()
    conn.close()
    logger.info(f"User {user_id} action: {action}, Target: {target_type}/{target_id}, Details: {details_json}")


# --- File Handling & Parsing ---
def save_uploaded_file(uploaded_file, patient_user_id):
    original_filename = uploaded_file.name
    file_extension = os.path.splitext(original_filename)[1]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    encrypted_filename_base = f"user_{patient_user_id}_record_{timestamp}{file_extension}.enc"
    # Store full path for robustness if CWD changes, though relative should work if structure is maintained
    encrypted_file_path = os.path.abspath(os.path.join(UPLOAD_FOLDER, encrypted_filename_base))

    logger.info(f"Saving uploaded file. Original: '{original_filename}', Target Encrypted Path: '{encrypted_file_path}'")

    file_bytes = uploaded_file.read()
    encrypted_content = encrypt_data(file_bytes) # encrypt_data returns bytes

    try:
        with open(encrypted_file_path, "wb") as f:
            f.write(encrypted_content)
        logger.info(f"Successfully saved encrypted file to '{encrypted_file_path}'")
        # Return the relative path for storage in DB, as UPLOAD_FOLDER is known
        return original_filename, os.path.join(UPLOAD_FOLDER, encrypted_filename_base)
    except Exception as e:
        logger.error(f"Failed to write encrypted file to '{encrypted_file_path}': {e}")
        return original_filename, None

def read_encrypted_file(relative_encrypted_file_path):
    # Construct absolute path based on UPLOAD_FOLDER
    # This assumes UPLOAD_FOLDER is relative to where the script is running or an absolute path itself.
    # For consistency, let's make it always relative to the script's current understanding of UPLOAD_FOLDER.
    absolute_encrypted_file_path = os.path.abspath(relative_encrypted_file_path)

    logger.info(f"Attempting to read encrypted file. Relative path from DB: '{relative_encrypted_file_path}', Absolute path used: '{absolute_encrypted_file_path}'")
    
    if not os.path.exists(absolute_encrypted_file_path):
        logger.error(f"Encrypted file NOT FOUND at resolved absolute path: '{absolute_encrypted_file_path}' (original relative: '{relative_encrypted_file_path}')")
        # Also check if the path relative to UPLOAD_FOLDER exists, in case os.path.abspath went wrong due to CWD
        check_path_alt = os.path.join(UPLOAD_FOLDER, os.path.basename(relative_encrypted_file_path))
        if os.path.exists(check_path_alt):
             logger.warning(f"Alternative check: File found at {check_path_alt}. There might be a CWD issue or path storage issue.")
        return None

    try:
        with open(absolute_encrypted_file_path, "rb") as f:
            encrypted_content = f.read()
        logger.info(f"Read {len(encrypted_content)} encrypted bytes from '{absolute_encrypted_file_path}'")
        
        # Use the function that returns raw bytes
        decrypted_bytes = decrypt_data_as_bytes(encrypted_content) 
        
        if decrypted_bytes is None:
            logger.error(f"decrypt_data_as_bytes returned None for file '{absolute_encrypted_file_path}'. Check for 'InvalidToken' errors above this log.")
        return decrypted_bytes # Returns raw bytes, suitable for st.download_button

    except FileNotFoundError: # Should be caught by os.path.exists, but as a fallback.
        logger.error(f"Encrypted file not found (FileNotFoundError exception) at: '{absolute_encrypted_file_path}'")
        return None
    except Exception as e:
        logger.error(f"Unexpected error reading or decrypting file '{absolute_encrypted_file_path}': {e}")
        return None

def parse_document(file_bytes, filename):
    """
    Extracts text and basic metadata from PDF or Image.
    Returns a dictionary with 'text' and 'summary'.
    """
    summary = "Summary not available."
    text_content = ""
    file_type = "unknown"

    try:
        if filename.lower().endswith('.pdf'):
            file_type = "PDF"
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            for page_num in range(len(doc)):
                page = doc.load_page(page_num)
                text_content += page.get_text()
            if text_content:
                summary = " ".join(text_content.split()[:50]) + "..." # First 50 words
            doc.close()
        
        elif filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            file_type = "Image"
            img = Image.open(file_bytes) # BytesIO(file_bytes) might be needed
            text_content = f"Image Details: Mode={img.mode}, Size={img.size}. OCR not implemented."
            # Basic EXIF data if available
            try:
                exif_data = {ExifTags.TAGS[k]: v for k, v in img._getexif().items() if k in ExifTags.TAGS}
                if exif_data:
                    text_content += f"\nEXIF: {json.dumps({k: str(v)[:50] for k,v in exif_data.items()}, indent=2)}" # Truncate long exif values
            except Exception:
                pass # No EXIF or error reading
            summary = text_content[:200] + "..."
            img.close()
        
        elif filename.lower().endswith('.txt'):
            file_type = "Text"
            text_content = file_bytes.decode('utf-8', errors='ignore')
            summary = " ".join(text_content.split()[:50]) + "..."
        
        else:
            summary = "Unsupported file type for parsing."
            text_content = "File content not parsed."

    except Exception as e:
        logger.error(f"Error parsing file {filename}: {e}")
        summary = f"Error parsing file: {e}"
        text_content = f"Error during parsing: {e}"

    return {"text": text_content, "summary": summary, "parsed_file_type": file_type}


# --- User Management Specific Functions ---
def create_user(username, password, role, full_name, email, dob=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_pwd = hash_password(password)
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, full_name, email) VALUES (?, ?, ?, ?, ?)",
            (username, hashed_pwd, role, full_name, email)
        )
        user_id = cursor.lastrowid
        if role == 'patient' and dob:
            cursor.execute(
                "INSERT INTO patient_profiles (patient_user_id, dob) VALUES (?, ?)",
                (user_id, dob)
            )
        conn.commit()
        log_access(None, "user_created", target_type="user", target_id=user_id, details={"username": username, "role": role})
        return user_id
    except sqlite3.IntegrityError: # Username or email already exists
        return None
    finally:
        conn.close()

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

def get_all_doctors():
    conn = get_db_connection()
    doctors = conn.execute("SELECT id, full_name, email FROM users WHERE role = 'doctor'").fetchall()
    conn.close()
    return doctors

def get_all_patients_for_doctor(doctor_user_id):
    # This is a simplified version. A doctor should only see patients
    # who have granted them access or have appointments with them.
    # For now, let's list patients who have granted access to at least one record OR have an appointment.
    conn = get_db_connection()
    # Patients who granted access to any record to this doctor
    query = """
    SELECT DISTINCT u.id, u.full_name, u.email, pp.dob
    FROM users u
    LEFT JOIN patient_profiles pp ON u.id = pp.patient_user_id
    WHERE u.role = 'patient'
      AND (
        EXISTS (
            SELECT 1
            FROM health_records hr
            JOIN record_access_permissions rap ON hr.id = rap.record_id
            WHERE hr.patient_user_id = u.id AND rap.doctor_user_id = :doctor_id AND rap.status = 'granted'
        )
        OR
        EXISTS (
            SELECT 1
            FROM appointments app
            WHERE app.patient_user_id = u.id AND app.doctor_user_id = :doctor_id
            -- You might want to consider appointment status here too, e.g., AND app.status != 'cancelled'
        )
      )
    ORDER BY u.full_name;
    """
    cursor = conn.execute(query, {"doctor_id": doctor_user_id})
    patients_rows = cursor.fetchall()
    patients_list_of_dicts = [dict(row) for row in patients_rows]
    return patients_list_of_dicts

# --- Health Record Specific Functions ---
def add_health_record(patient_user_id, record_type, original_filename, encrypted_file_relative_path, metadata_summary, file_hash=None):
    # ... (ensure this function stores encrypted_file_relative_path in 'encrypted_file_path' column)
    conn = get_db_connection()
    cursor = conn.cursor()

    encrypted_original_filename = encrypt_data(original_filename).decode('utf-8') # Stored as string
    encrypted_metadata = encrypt_data(json.dumps({"summary": metadata_summary})).decode('utf-8') # Stored as string

    cursor.execute('''
        INSERT INTO health_records (patient_user_id, record_type, original_file_name, encrypted_file_path, metadata, file_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (patient_user_id, record_type, encrypted_original_filename, encrypted_file_relative_path, encrypted_metadata, file_hash))
    record_id = cursor.lastrowid
    conn.commit()
    conn.close()
    log_access(patient_user_id, "record_uploaded", target_type="record", target_id=record_id, details={"filename": original_filename, "type": record_type})
    return record_id

# Call init_db and key loading at the end of utils.py
if __name__ == '__main__': # If running utils.py directly for setup/testing
    print("Initializing DB and loading key from utils.py direct execution...")
    init_db()
    try:
        load_or_generate_key()
        print(f"Encryption key loaded/generated. Current key (first 10 bytes): {_key[:10] if _key else 'None'}")
    except ValueError as e:
        print(f"CRITICAL ERROR during key loading in utils direct exec: {e}")
else: # When imported by app.py or api.py
    # init_db() is called in app.py's main().
    # Key should be loaded when get_fernet() is first called.
    # You can force a load here if you want it earlier, but get_fernet will handle it.
    pass

def get_patient_records(patient_user_id):
    conn = get_db_connection()
    records = conn.execute("SELECT * FROM health_records WHERE patient_user_id = ?", (patient_user_id,)).fetchall()
    conn.close()
    # Decrypt necessary fields before returning
    decrypted_records = []
    for rec in records:
        rec_dict = dict(rec)
        rec_dict['original_file_name'] = decrypt_data(rec_dict['original_file_name'])
        metadata_json = decrypt_data(rec_dict['metadata'])
        rec_dict['metadata'] = json.loads(metadata_json) if metadata_json else {"summary": "N/A"}
        decrypted_records.append(rec_dict)
    return decrypted_records

def get_record_by_id(record_id):
    conn = get_db_connection()
    record = conn.execute("SELECT * FROM health_records WHERE id = ?", (record_id,)).fetchone()
    conn.close()
    if record:
        rec_dict = dict(record)
        rec_dict['original_file_name'] = decrypt_data(rec_dict['original_file_name'])
        metadata_json = decrypt_data(rec_dict['metadata'])
        rec_dict['metadata'] = json.loads(metadata_json) if metadata_json else {"summary": "N/A"}
        return rec_dict
    return None

def grant_record_access(record_id, doctor_user_id, granter_user_id):
    conn = get_db_connection()
    try:
        # Upsert: Update status if exists, else insert
        conn.execute('''
            INSERT INTO record_access_permissions (record_id, doctor_user_id, status)
            VALUES (?, ?, 'granted')
            ON CONFLICT(record_id, doctor_user_id) DO UPDATE SET status = 'granted', granted_date = CURRENT_TIMESTAMP
        ''', (record_id, doctor_user_id))
        conn.commit()
        log_access(granter_user_id, "access_granted", target_type="record", target_id=record_id, details={"doctor_id": doctor_user_id})
        return True
    except Exception as e:
        logger.error(f"Error granting access: {e}")
        return False
    finally:
        conn.close()

def revoke_record_access(record_id, doctor_user_id, revoker_user_id):
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE record_access_permissions SET status = 'revoked'
            WHERE record_id = ? AND doctor_user_id = ?
        ''', (record_id, doctor_user_id))
        conn.commit()
        log_access(revoker_user_id, "access_revoked", target_type="record", target_id=record_id, details={"doctor_id": doctor_user_id})
        return True
    except Exception as e:
        logger.error(f"Error revoking access: {e}")
        return False
    finally:
        conn.close()

def get_doctors_with_access(record_id):
    conn = get_db_connection()
    doctors = conn.execute('''
        SELECT u.id, u.full_name, u.email, rap.status
        FROM users u
        JOIN record_access_permissions rap ON u.id = rap.doctor_user_id
        WHERE rap.record_id = ? AND rap.status = 'granted'
    ''', (record_id,)).fetchall()
    conn.close()
    return doctors

def check_doctor_access_to_record(doctor_user_id, record_id):
    conn = get_db_connection()
    permission = conn.execute('''
        SELECT 1 FROM record_access_permissions
        WHERE record_id = ? AND doctor_user_id = ? AND status = 'granted'
    ''', (record_id, doctor_user_id)).fetchone()
    conn.close()
    return permission is not None

def get_records_accessible_by_doctor(patient_user_id, doctor_user_id):
    conn = get_db_connection()
    # Records owned by patient_user_id AND doctor_user_id has 'granted' access
    records = conn.execute('''
        SELECT hr.*
        FROM health_records hr
        JOIN record_access_permissions rap ON hr.id = rap.record_id
        WHERE hr.patient_user_id = ? AND rap.doctor_user_id = ? AND rap.status = 'granted'
    ''', (patient_user_id, doctor_user_id)).fetchall()
    conn.close()
    
    decrypted_records = []
    for rec in records:
        rec_dict = dict(rec)
        rec_dict['original_file_name'] = decrypt_data(rec_dict['original_file_name'])
        metadata_json = decrypt_data(rec_dict['metadata'])
        rec_dict['metadata'] = json.loads(metadata_json) if metadata_json else {"summary": "N/A"}
        decrypted_records.append(rec_dict)
    return decrypted_records


# --- Appointment Specific Functions ---
def book_appointment(patient_user_id, doctor_user_id, appt_datetime, notes=""):
    conn = get_db_connection()
    encrypted_notes = encrypt_data(notes).decode('utf-8') if notes else None
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO appointments (patient_user_id, doctor_user_id, appointment_datetime, notes, status)
            VALUES (?, ?, ?, ?, 'pending')
        ''', (patient_user_id, doctor_user_id, appt_datetime, encrypted_notes))
        appt_id = cursor.lastrowid
        conn.commit()
        log_access(doctor_user_id, "appointment_booked", target_type="appointment", target_id=appt_id, details={"patient_id": patient_user_id, "datetime": appt_datetime})
        # TODO: Send notification
        return appt_id
    except Exception as e:
        logger.error(f"Error booking appointment: {e}")
        return None
    finally:
        conn.close()

def get_user_appointments(user_id, role):
    conn = get_db_connection()
    if role == 'patient':
        query = """
        SELECT app.*, doc.full_name as doctor_name, pat.full_name as patient_name
        FROM appointments app
        JOIN users doc ON app.doctor_user_id = doc.id
        JOIN users pat ON app.patient_user_id = pat.id
        WHERE app.patient_user_id = ? ORDER BY app.appointment_datetime DESC
        """
    elif role == 'doctor':
        query = """
        SELECT app.*, doc.full_name as doctor_name, pat.full_name as patient_name
        FROM appointments app
        JOIN users doc ON app.doctor_user_id = doc.id
        JOIN users pat ON app.patient_user_id = pat.id
        WHERE app.doctor_user_id = ? ORDER BY app.appointment_datetime DESC
        """
    else: # admin or invalid role for this query
        conn.close()
        return []
        
    appts = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    
    decrypted_appts = []
    for appt in appts:
        appt_dict = dict(appt)
        if appt_dict['notes']:
            appt_dict['notes'] = decrypt_data(appt_dict['notes'])
        else:
            appt_dict['notes'] = ""
        decrypted_appts.append(appt_dict)
    return decrypted_appts


def update_appointment_status(appointment_id, status, user_id):
    conn = get_db_connection()
    try:
        conn.execute("UPDATE appointments SET status = ? WHERE id = ?", (status, appointment_id))
        conn.commit()
        log_access(user_id, "appointment_status_updated", target_type="appointment", target_id=appointment_id, details={"new_status": status})
        return True
    except Exception as e:
        logger.error(f"Error updating appointment status: {e}")
        return False
    finally:
        conn.close()

# --- Health Trend Analysis (Placeholder) ---
def get_patient_trends_data(patient_user_id):
    # This is a placeholder. In a real app, this would involve:
    # - Parsing structured data from records (e.g., lab values from PDFs/structured entries)
    # - Storing these structured values in separate tables (e.g., blood_pressure, cholesterol_levels)
    # - Querying these tables to get time-series data
    # For now, let's simulate some data if any "Lab Report" exists.
    records = get_patient_records(patient_user_id)
    bp_data = []
    cholesterol_data = []
    
    for i, record in enumerate(r for r in records if r['record_type'] == 'Lab Report'):
        # Simulate some data based on record upload date
        upload_dt = datetime.strptime(record['upload_date'].split('.')[0], '%Y-%m-%d %H:%M:%S') # Handle potential microseconds
        
        # Simulate BP: systolic decreasing, diastolic increasing slightly
        systolic = 140 - i*5 
        diastolic = 75 + i*2
        bp_data.append({'date': upload_dt, 'systolic': systolic, 'diastolic': diastolic})
        
        # Simulate Cholesterol: LDL decreasing
        ldl = 150 - i*10
        hdl = 40 + i*3
        cholesterol_data.append({'date': upload_dt, 'ldl': ldl, 'hdl': hdl})

    trends = {
        "blood_pressure": pd.DataFrame(bp_data) if bp_data else pd.DataFrame(columns=['date', 'systolic', 'diastolic']),
        "cholesterol": pd.DataFrame(cholesterol_data) if cholesterol_data else pd.DataFrame(columns=['date', 'ldl', 'hdl'])
    }
    return trends

# --- Example JSON Output Generation ---
def generate_patient_json_summary(patient_user_id):
    patient_user = get_user_by_id(patient_user_id)
    if not patient_user:
        return {"error": "Patient not found"}

    records = get_patient_records(patient_user_id)
    appointments = get_user_appointments(patient_user_id, 'patient')
    
    # For access logs, we'd need a more specific query, this is illustrative
    conn = get_db_connection()
    logs_cursor = conn.execute("""
        SELECT action, timestamp, details FROM access_logs 
        WHERE (target_type = 'record' AND target_id IN (SELECT id FROM health_records WHERE patient_user_id = ?))
           OR (user_id = ?)
        ORDER BY timestamp DESC LIMIT 10
    """, (patient_user_id, patient_user_id))
    access_logs_raw = logs_cursor.fetchall()
    conn.close()

    formatted_records = []
    for r in records:
        doctors_with_access = get_doctors_with_access(r['id'])
        formatted_records.append({
            "RecordID": r['id'],
            "Type": r['record_type'],
            "Date": r['upload_date'],
            "Summary": r['metadata'].get('summary', 'N/A'),
            "AccessGrantedTo": [doc['full_name'] for doc in doctors_with_access]
        })

    formatted_appointments = []
    for a in appointments:
        formatted_appointments.append({
            "AppointmentID": a['id'],
            "Doctor": a['doctor_name'], # Assuming doctor_name is fetched in get_user_appointments
            "Date": a['appointment_datetime'],
            "Status": a['status']
        })
    
    formatted_logs = [f"{log['action']} on {log['timestamp']}" + (f" Details: {log['details']}" if log['details'] else "") for log in access_logs_raw]

    # Simplified health trends for JSON output
    trends_data = get_patient_trends_data(patient_user_id)
    bp_summary = "N/A"
    if not trends_data["blood_pressure"].empty:
        avg_sys = trends_data["blood_pressure"]["systolic"].mean()
        avg_dia = trends_data["blood_pressure"]["diastolic"].mean()
        bp_summary = f"{avg_sys:.0f}/{avg_dia:.0f} mmHg (Avg)"

    output = {
        "PatientProfile": {
            "ID": f"P{patient_user_id}", # Example ID prefix
            "Name": patient_user['full_name'],
            "Records": formatted_records,
            "Appointments": formatted_appointments
        },
        "AccessLogs": formatted_logs,
        "HealthTrends": {
            "BloodPressure": bp_summary
            # Add more trends here
        }
    }
    return output

# Call init_db when this module is loaded for the first time if DB doesn't exist
if not os.path.exists(DATABASE_PATH):
    print(f"Database not found at {DATABASE_PATH}, initializing...")
    init_db()
else: # Ensure key is loaded on module import if already set
    load_or_generate_key()