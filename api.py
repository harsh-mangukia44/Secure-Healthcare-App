from fastapi import FastAPI, HTTPException, File, UploadFile, Depends, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm # For future auth
from pydantic import BaseModel
import utils
import json

app = FastAPI(title="Patient Health App API")

# For future JWT token authentication
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserCreate(BaseModel):
    username: str
    password: str
    role: str # 'patient' or 'doctor'
    full_name: str
    email: str
    dob: str = None # Optional, for patients

class RecordMetadata(BaseModel):
    record_type: str
    summary: str = None

@app.on_event("startup")
async def startup_event():
    utils.init_db() # Ensure DB is initialized
    utils.load_or_generate_key() # Ensure key is loaded/generated

@app.post("/users/", status_code=201)
async def create_user_api(user: UserCreate):
    user_id = utils.create_user(
        username=user.username,
        password=user.password,
        role=user.role,
        full_name=user.full_name,
        email=user.email,
        dob=user.dob if user.role == 'patient' else None
    )
    if not user_id:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    utils.log_access(None, "api_user_created", target_type="user", target_id=user_id, details={"username": user.username})
    return {"id": user_id, "username": user.username, "role": user.role}

# Example: API endpoint for uploading a record (could be used by other clients)
@app.post("/records/upload/{patient_user_id}")
async def api_upload_record(
    patient_user_id: int,
    record_type: str = Form(...),
    file: UploadFile = File(...)
):
    # Check if patient_user_id is valid (simplified check)
    patient = utils.get_user_by_id(patient_user_id)
    if not patient or patient['role'] != 'patient':
        raise HTTPException(status_code=404, detail="Patient not found or invalid ID")

    # Save and encrypt file
    original_filename, encrypted_path = utils.save_uploaded_file(file.file, patient_user_id) # file.file is the SpooledTemporaryFile

    # Parse document for metadata (can be slow, consider background task for production)
    file.file.seek(0) # Reset file pointer after save_uploaded_file might have read it
    file_bytes = await file.read() # Read again for parsing
    
    parsed_info = utils.parse_document(file_bytes, original_filename)
    summary = parsed_info.get("summary", "Summary not available.")

    record_id = utils.add_health_record(
        patient_user_id=patient_user_id,
        record_type=record_type,
        original_filename=original_filename,
        encrypted_file_path=encrypted_path,
        metadata_summary=summary
    )
    utils.log_access(patient_user_id, "api_record_uploaded", target_type="record", target_id=record_id)
    return {"record_id": record_id, "filename": original_filename, "summary": summary}

@app.get("/patients/{patient_user_id}/summary_json")
async def get_patient_summary_json_api(patient_user_id: int):
    # In a real app, add authentication to ensure only authorized users (patient themselves or authorized doctor) can access
    summary = utils.generate_patient_json_summary(patient_user_id)
    if "error" in summary:
        raise HTTPException(status_code=404, detail=summary["error"])
    utils.log_access(None, "api_patient_summary_requested", target_type="patient", target_id=patient_user_id) # user_id should be the requester
    return summary

# To run FastAPI (e.g., locally for testing API):
# uvicorn api:app --reload