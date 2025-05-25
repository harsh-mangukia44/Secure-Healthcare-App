# Secure-Healthcare-App
Patient Health Records Management and Consultation Booking Application


## Tech Stack

*   **Frontend:** Streamlit
*   **Backend API (Minimal):** FastAPI
*   **Data Storage:** SQLite
*   **File Handling:** PyMuPDF (Fitz), Pillow (PIL)
*   **Security:** Fernet (Encryption), bcrypt (Password Hashing)
*   **Access Logging:** Python `logging` module & custom DB logging
*   **Plots & Reports:** Matplotlib, Pandas
*   **Deployment:** Hugging Face Spaces

## Setup and Running Locally

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd Secure-Healthcare-App
    ```

2.  **Create a virtual environment and activate it:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set the Encryption Key:**
    The application uses Fernet encryption. You **MUST** set an encryption key as an environment variable.
    *   Run `python utils.py` once. If no key is set, it will generate and print a demo key.
    *   Copy this key.
    *   Set the environment variable `APP_ENCRYPTION_KEY`:
        ```bash
        export APP_ENCRYPTION_KEY='your_copied_fernet_key_here' 
        # On Windows (PowerShell): $env:APP_ENCRYPTION_KEY='your_key_here'
        # Or add to a .env file if you modify the app to use python-dotenv for local dev.
        ```
    **IMPORTANT:** For any real deployment, use a strong, securely managed key. The auto-generated key is for demo convenience only. Data encrypted with one key cannot be decrypted with another.

5.  **Initialize the database (if not already done by `utils.py` on import):**
    The `utils.py` script attempts to initialize the database on import if it doesn't exist. You can also run `python utils.py` directly to ensure tables are created. The Streamlit app (`app.py`) also calls `utils.init_db()`.

6.  **Run the Streamlit application:**
    ```bash
    streamlit run app.py
    ```
    The application should open in your web browser.

7.  **Demo Users (created on first run if DB is empty):**
    *   admin / admin123
    *   drsmith / doctor123
    *   johnp / patient123

8.  **(Optional) Run the FastAPI server (for API testing, not strictly needed for Streamlit app):**
    ```bash
    uvicorn api:app --reload --port 8001
    ```
    The API will be available at `http://127.0.0.1:8001/docs`.

## Deployment on Hugging Face Spaces

1.  **Create a new Space on Hugging Face.**
    *   Choose "Streamlit" as the SDK.
    *   Connect to your GitHub repository.
    *   The main application file should be `app.py`.
2.  **Configure Secrets:**
    *   In your Hugging Face Space settings, go to "Secrets".
    *   Add a new secret:
        *   Name: `APP_ENCRYPTION_KEY`
        *   Value: `your_strong_fernet_key_here` (Generate a new one for HF Spaces, don't reuse a local demo key if it was exposed).
3.  **Ensure `requirements.txt` is up-to-date.**
4.  The Space should build and deploy your application. The SQLite database and uploads will be stored within the Space's persistent storage (if configured, otherwise they might be ephemeral depending on Space type and settings).

## Security & Compliance Considerations (HIPAA/GDPR)

This application implements foundational security measures:
*   **Encryption at Rest:** Uploaded files and sensitive database fields are encrypted using Fernet.
*   **Encryption in Transit:** Assumed via HTTPS (provided by Hugging Face Spaces).
*   **Access Controls:** Role-based access and patient-controlled sharing of records.
*   **Authentication:** Usernames and hashed passwords (bcrypt).
*   **Audit Trails:** Basic logging of key actions.

**However, full HIPAA/GDPR compliance is a complex, ongoing process involving technical, administrative, and physical safeguards.** This demo provides a technical starting point but would require:
*   Formal risk assessments.
*   Robust Identity and Access Management (IAM) policies.
*   Detailed audit logging and monitoring.
*   Data backup and disaster recovery plans.
*   Secure key management practices (not just an environment variable for production).
*   Secure development lifecycle.
*   Business Associate Agreements (BAAs) with hosting providers (if applicable).
*   User consent mechanisms for data processing.
*   Data subject rights fulfillment (e.g., right to access, erasure).
*   Breach notification procedures.
*   And much more.

This demo is **NOT** to be used for actual patient data without significant further development and compliance efforts.

## Future Enhancements

*   More robust API endpoints for all functionalities.
*   Advanced search and filtering for doctors.
*   Real-time notifications (e.g., using WebSockets or a messaging queue).
*   Integration with external services (e.g., labs, pharmacies).
*   Advanced NLP for record summarization and data extraction.
*   Two-Factor Authentication (2FA).
*   More granular permissions.
*   Containerization with Docker for easier deployment.
*   Use of a production-grade database (e.g., PostgreSQL, MySQL) instead of SQLite for scalability and robustness.
*   Automated testing.
