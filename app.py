import streamlit as st
from streamlit_option_menu import option_menu
import utils
from datetime import datetime, date
import pandas as pd
import matplotlib.pyplot as plt
import os # For file download

# --- Page Configuration ---
st.set_page_config(page_title="HealthApp", layout="wide")

# --- Initialize Session State ---
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.full_name = None

# --- Helper Functions for UI ---
def display_login_form():
    st.subheader("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login_button = st.form_submit_button("Login")

        if login_button:
            user = utils.get_user_by_username(username)
            if user and utils.verify_password(password, user['password_hash']):
                st.session_state.logged_in = True
                st.session_state.user_id = user['id']
                st.session_state.username = user['username']
                st.session_state.role = user['role']
                st.session_state.full_name = user['full_name']
                utils.log_access(user['id'], "login_successful")
                st.rerun()
            else:
                st.error("Invalid username or password")
                utils.log_access(None, "login_failed", details={"username": username})

def display_registration_form():
    st.subheader("Register New User")
    with st.form("registration_form"):
        reg_username = st.text_input("Username*", key="reg_user")
        reg_password = st.text_input("Password*", type="password", key="reg_pass")
        reg_full_name = st.text_input("Full Name*", key="reg_fname")
        reg_email = st.text_input("Email*", key="reg_email")
        reg_role = st.selectbox("Role*", ["patient", "doctor"], key="reg_role")
        reg_dob_str = None
        if reg_role == "patient":
            reg_dob = st.date_input("Date of Birth (for Patients)", min_value=date(1900,1,1), max_value=date.today(), key="reg_dob")
            reg_dob_str = reg_dob.strftime('%Y-%m-%d') if reg_dob else None

        register_button = st.form_submit_button("Register")

        if register_button:
            if not (reg_username and reg_password and reg_full_name and reg_email):
                st.error("Please fill in all required fields (*).")
            elif reg_role == "patient" and not reg_dob_str:
                 st.error("Date of Birth is required for patients.")
            else:
                user_id = utils.create_user(reg_username, reg_password, reg_role, reg_full_name, reg_email, reg_dob_str)
                if user_id:
                    st.success(f"User {reg_username} ({reg_role}) registered successfully! Please login.")
                else:
                    st.error("Username or email already exists, or another error occurred.")

# --- Patient Dashboard Functions ---
def patient_dashboard():
    st.header(f"Welcome Patient: {st.session_state.full_name}")
    
    patient_menu = ["View My Records", "Upload Record", "Manage Record Access", "My Appointments", "View JSON Summary"]
    patient_choice = st.sidebar.radio("Patient Menu", patient_menu)

    if patient_choice == "View My Records":
        view_my_records()
    elif patient_choice == "Upload Record":
        upload_health_record()
    elif patient_choice == "Manage Record Access":
        manage_record_access()
    elif patient_choice == "My Appointments":
        view_my_appointments()
    elif patient_choice == "View JSON Summary":
        display_patient_json_summary(st.session_state.user_id)


def upload_health_record():
    st.subheader("Upload New Health Record")
    with st.form("upload_form", clear_on_submit=True):
        record_type = st.selectbox("Record Type", ["Lab Report", "Imaging", "Prescription", "Doctor's Note", "Other"])
        uploaded_file = st.file_uploader("Choose a file (PDF, JPG, PNG, TXT)", type=["pdf", "jpg", "jpeg", "png", "txt"])
        submit_button = st.form_submit_button("Upload Record")

        if submit_button and uploaded_file is not None:
            if uploaded_file.size > 25 * 1024 * 1024: # Max 25MB
                st.error("File is too large. Maximum 25MB.")
                return

            progress_bar = st.progress(0)
            st.info(f"Uploading {uploaded_file.name}...")

            # Save and encrypt
            original_filename, encrypted_path = utils.save_uploaded_file(uploaded_file, st.session_state.user_id)
            progress_bar.progress(30)

            # Parse for summary (this can be slow for large files)
            uploaded_file.seek(0) # Reset file pointer as save_uploaded_file read it
            file_bytes_for_parsing = uploaded_file.read()
            parsed_info = utils.parse_document(file_bytes_for_parsing, original_filename)
            summary = parsed_info.get("summary", "Summary could not be generated.")
            progress_bar.progress(70)

            # Add to database
            record_id = utils.add_health_record(
                st.session_state.user_id,
                record_type,
                original_filename,
                encrypted_path,
                summary
            )
            progress_bar.progress(100)
            st.success(f"Record '{original_filename}' uploaded successfully with ID {record_id}!")
            utils.log_access(st.session_state.user_id, "record_upload_ui", target_type="record", target_id=record_id, details={"filename": original_filename})
            st.balloons()

def view_my_records(selected_patient_id=None, doctor_view=False):
    # If selected_patient_id is provided, it's a doctor viewing a patient's records
    # Otherwise, it's a patient viewing their own records.
    patient_id_to_view = selected_patient_id if selected_patient_id else st.session_state.user_id
    
    if doctor_view and selected_patient_id:
        st.subheader(f"Viewing Records for Patient ID: {selected_patient_id}")
        records = utils.get_records_accessible_by_doctor(patient_id_to_view, st.session_state.user_id)
        if not records:
            st.info("No records found or you do not have access to this patient's records.")
            return
    else: # Patient viewing their own
        st.subheader("My Health Records")
        records = utils.get_patient_records(patient_id_to_view)
        if not records:
            st.info("You have not uploaded any records yet.")
            return

    df_records = pd.DataFrame(records)
    if not df_records.empty:
        df_display = df_records[["id", "original_file_name", "record_type", "upload_date"]].copy()
        df_display.rename(columns={"id":"Record ID", "original_file_name": "File Name", "record_type": "Type", "upload_date": "Uploaded"}, inplace=True)
        st.dataframe(df_display, use_container_width=True)

        selected_record_id = st.selectbox("Select Record ID to view details/download:", options=df_records["id"].tolist(), format_func=lambda x: f"{x} - {df_records[df_records['id']==x]['original_file_name'].iloc[0]}")
        
        if selected_record_id:
            record_details = next((r for r in records if r['id'] == selected_record_id), None)
            if record_details:
                st.write(f"**Details for Record ID: {record_details['id']}**")
                st.write(f"**File Name:** {record_details['original_file_name']}")
                st.write(f"**Type:** {record_details['record_type']}")
                st.write(f"**Uploaded:** {record_details['upload_date']}")
                st.write(f"**Summary:** {record_details['metadata'].get('summary', 'N/A')}")

                # Download button
                decrypted_content = utils.read_encrypted_file(record_details['encrypted_file_path'])
                if decrypted_content:
                    st.download_button(
                        label=f"Download {record_details['original_file_name']}",
                        data=decrypted_content,
                        file_name=record_details['original_file_name'], # Original filename for download
                        mime="application/octet-stream" # Generic
                    )
                    utils.log_access(st.session_state.user_id, "record_download_attempt", target_type="record", target_id=record_details['id'])
                else:
                    st.error("Could not retrieve file for download.")
                
                # If doctor is viewing, log access
                if doctor_view:
                    utils.log_access(st.session_state.user_id, "doctor_viewed_record", target_type="record", target_id=record_details['id'], details={"patient_id": patient_id_to_view})
            else:
                st.error("Selected record not found.")
    else:
        st.info("No records available to display.")


def manage_record_access():
    st.subheader("Manage Access to My Records")
    records = utils.get_patient_records(st.session_state.user_id)
    if not records:
        st.info("You have no records to manage access for.")
        return

    record_options = {r['id']: f"{r['id']} - {r['original_file_name']} ({r['record_type']})" for r in records}
    selected_record_id = st.selectbox("Select Record:", options=list(record_options.keys()), format_func=lambda x: record_options[x])

    if selected_record_id:
        st.write(f"**Managing access for: {record_options[selected_record_id]}**")
        
        # Show doctors with current access
        doctors_with_access = utils.get_doctors_with_access(selected_record_id)
        if doctors_with_access:
            st.write("**Currently Granted Access To:**")
            for doc in doctors_with_access:
                col1, col2 = st.columns([3,1])
                with col1:
                    st.write(f"- Dr. {doc['full_name']} ({doc['email']})")
                with col2:
                    if st.button(f"Revoke for Dr. {doc['full_name']}", key=f"revoke_{selected_record_id}_{doc['id']}"):
                        if utils.revoke_record_access(selected_record_id, doc['id'], st.session_state.user_id):
                            st.success(f"Access revoked for Dr. {doc['full_name']}.")
                            st.rerun() # To refresh the list
                        else:
                            st.error("Failed to revoke access.")
        else:
            st.info("No doctors currently have access to this specific record.")

        # Grant access to a new doctor
        st.write("**Grant Access To Doctor:**")
        all_doctors = utils.get_all_doctors()
        if not all_doctors:
            st.warning("No doctors found in the system to grant access to.")
            return
            
        # Filter out doctors who already have access to this record
        accessible_doctor_ids = [doc['id'] for doc in doctors_with_access]
        available_doctors = [doc for doc in all_doctors if doc['id'] not in accessible_doctor_ids]

        if not available_doctors:
            st.info("All doctors already have access or there are no other doctors.")
        else:
            doctor_options = {doc['id']: f"Dr. {doc['full_name']} ({doc['email']})" for doc in available_doctors}
            selected_doctor_id = st.selectbox("Select Doctor to Grant Access:", options=list(doctor_options.keys()), format_func=lambda x: doctor_options[x], key=f"grant_doc_select_{selected_record_id}")
            
            if st.button("Grant Access", key=f"grant_btn_{selected_record_id}"):
                if utils.grant_record_access(selected_record_id, selected_doctor_id, st.session_state.user_id):
                    st.success(f"Access granted to {doctor_options[selected_doctor_id]} for record {record_options[selected_record_id]}.")
                    st.rerun()
                else:
                    st.error("Failed to grant access.")

def view_my_appointments():
    st.subheader("My Appointments")
    appointments = utils.get_user_appointments(st.session_state.user_id, st.session_state.role)
    
    if not appointments:
        st.info("You have no upcoming or past appointments.")
        return

    df_appts = pd.DataFrame(appointments)
    # st.dataframe(df_appts) # For debugging
    
    if not df_appts.empty:
        df_display = df_appts[["id", "doctor_name" if st.session_state.role == 'patient' else "patient_name", "appointment_datetime", "status", "notes"]].copy()
        df_display.rename(columns={
            "id": "Appt ID",
            "doctor_name": "Doctor",
            "patient_name": "Patient",
            "appointment_datetime": "Date & Time",
            "status": "Status",
            "notes": "Notes"
        }, inplace=True)
        st.dataframe(df_display, use_container_width=True)

        # Option for doctors to update status
        if st.session_state.role == 'doctor':
            st.markdown("---")
            st.write("**Update Appointment Status**")
            app_ids = df_appts["id"].tolist()
            if app_ids:
                selected_appt_id_status = st.selectbox("Select Appointment ID to update status:", options=app_ids)
                new_status = st.selectbox("New Status:", ["confirmed", "completed", "cancelled"], key=f"status_update_{selected_appt_id_status}")
                if st.button("Update Status", key=f"btn_status_update_{selected_appt_id_status}"):
                    if utils.update_appointment_status(selected_appt_id_status, new_status, st.session_state.user_id):
                        st.success(f"Appointment {selected_appt_id_status} status updated to {new_status}.")
                        st.rerun()
                    else:
                        st.error("Failed to update status.")
            else:
                st.info("No appointments to update.")
    else:
        st.info("No appointments to display.")


# --- Doctor Dashboard Functions ---
def doctor_dashboard():
    st.header(f"Welcome Doctor: {st.session_state.full_name}")
    doctor_menu = ["Search Patients", "My Appointments", "View Patient Records", "Book Appointment", "Analyze Patient History"]
    doctor_choice = st.sidebar.radio("Doctor Menu", doctor_menu)

    # Store selected patient ID in session state for persistence across doctor menu choices
    if 'doctor_selected_patient_id' not in st.session_state:
        st.session_state.doctor_selected_patient_id = None

    if doctor_choice == "Search Patients":
        search_patients() # This will set doctor_selected_patient_id
    
    # Actions requiring a selected patient
    if doctor_choice in ["View Patient Records", "Book Appointment", "Analyze Patient History"]:
        if st.session_state.doctor_selected_patient_id:
            patient_info = utils.get_user_by_id(st.session_state.doctor_selected_patient_id)
            st.info(f"Currently selected patient: **{patient_info['full_name']} (ID: {st.session_state.doctor_selected_patient_id})**")
            if doctor_choice == "View Patient Records":
                view_my_records(selected_patient_id=st.session_state.doctor_selected_patient_id, doctor_view=True)
            elif doctor_choice == "Book Appointment":
                book_appointment_for_patient(st.session_state.doctor_selected_patient_id)
            elif doctor_choice == "Analyze Patient History":
                analyze_patient_history(st.session_state.doctor_selected_patient_id)
        else:
            st.warning("Please search and select a patient first from the 'Search Patients' menu.")
    
    elif doctor_choice == "My Appointments": # This does not require a patient selection from search
        view_my_appointments()


def search_patients():
    st.subheader("Search Patients")
    # For simplicity, list all patients doctor has some interaction with (access or appointment)
    # In a real system, search would be by ID, name, condition etc.
    patients_list_of_dicts = utils.get_all_patients_for_doctor(st.session_state.user_id)

    if not patients_list_of_dicts:
        st.info("No patients found that you have access to or appointments with. Patients need to grant you access to their records first, or you need to book an appointment.")
        st.session_state.doctor_selected_patient_id = None # Clear selection
        return
    
    df_patients = pd.DataFrame(patients_list_of_dicts) 
    
    st.write("Patients you have interactions with (record access or appointments):")
    
    if not df_patients.empty:
        required_cols_for_display = ["id", "full_name", "email", "dob"]
        missing_cols = [col for col in required_cols_for_display if col not in df_patients.columns]
        if missing_cols:
            st.error(f"The patient data is missing the following expected columns: {', '.join(missing_cols)}. Please check the 'utils.get_all_patients_for_doctor' function in utils.py.")
            st.session_state.doctor_selected_patient_id = None
            return
        
        df_display = df_patients[required_cols_for_display].copy()
        df_display.rename(columns={
            "id": "Patient ID",
            "full_name": "Full Name",
            "email": "Email",
            "dob": "Date of Birth"
        }, inplace=True)
        st.dataframe(df_display, use_container_width=True)

        patient_options = {p['id']: f"{p['full_name']} (ID: {p['id']})" for p in patients_list_of_dicts}
        
        if patient_options: # Only show selectbox if there are patients
            selected_id = st.selectbox(
                "Select Patient to manage:", 
                options=list(patient_options.keys()), 
                format_func=lambda x: patient_options[x],
                key="doctor_search_patient_select" # Added a unique key
            )
            
            if selected_id:
                st.session_state.doctor_selected_patient_id = selected_id
                # Get full_name from the selected patient for the success message
                selected_patient_details = next((p for p in patients_list_of_dicts if p['id'] == selected_id), None)
                selected_patient_name = selected_patient_details['full_name'] if selected_patient_details else "Unknown"

                st.success(f"Selected patient: {selected_patient_name} (ID: {selected_id}). You can now use other menu options for this patient.")
                
                accessible_records = utils.get_records_accessible_by_doctor(selected_id, st.session_state.user_id)
                st.write(f"You have access to {len(accessible_records)} records for this patient.")
            else:
                # This case implies patient_options was not empty, but selectbox returned None (e.g. if no default selection and nothing chosen)
                st.session_state.doctor_selected_patient_id = None
        else: # Should not happen if patients_list_of_dicts was not empty, but a safeguard.
            st.info("No patients available to select after processing.")
            st.session_state.doctor_selected_patient_id = None
            
    else:
        # This case means patients_list_of_dicts was not empty, but pd.DataFrame() resulted in an empty df. Unlikely.
        st.info("No patient data available to display after DataFrame conversion.")
        st.session_state.doctor_selected_patient_id = None


def book_appointment_for_patient(patient_id):
    st.subheader(f"Book Appointment for Patient ID: {patient_id}")
    patient_info = utils.get_user_by_id(patient_id)
    st.write(f"Patient Name: {patient_info['full_name']}")

    with st.form("book_appointment_form"):
        appt_date = st.date_input("Appointment Date", min_value=date.today())
        appt_time = st.time_input("Appointment Time")
        notes = st.text_area("Notes (optional)")
        submit_button = st.form_submit_button("Book Appointment")

        if submit_button:
            appt_datetime = datetime.combine(appt_date, appt_time)
            if appt_datetime < datetime.now():
                st.error("Cannot book an appointment in the past.")
            else:
                appt_id = utils.book_appointment(patient_id, st.session_state.user_id, appt_datetime.strftime('%Y-%m-%d %H:%M:%S'), notes)
                if appt_id:
                    st.success(f"Appointment booked successfully for {patient_info['full_name']} on {appt_datetime.strftime('%Y-%m-%d %I:%M %p')}. Appointment ID: {appt_id}")
                    # TODO: Implement actual notification to patient
                    st.info("Patient notification feature is a TODO.")
                else:
                    st.error("Failed to book appointment.")

def analyze_patient_history(patient_id):
    st.subheader(f"Health Trends for Patient ID: {patient_id}")
    patient_info = utils.get_user_by_id(patient_id)
    st.write(f"Patient Name: {patient_info['full_name']}")

    trends = utils.get_patient_trends_data(patient_id)

    # Blood Pressure
    bp_df = trends['blood_pressure']
    if not bp_df.empty and 'date' in bp_df.columns and 'systolic' in bp_df.columns and 'diastolic' in bp_df.columns:
        st.write("**Blood Pressure Trend (Simulated)**")
        # Ensure 'date' is datetime
        bp_df['date'] = pd.to_datetime(bp_df['date'])
        bp_df = bp_df.sort_values(by='date')

        fig, ax = plt.subplots()
        ax.plot(bp_df['date'], bp_df['systolic'], marker='o', linestyle='-', label='Systolic')
        ax.plot(bp_df['date'], bp_df['diastolic'], marker='x', linestyle='--', label='Diastolic')
        ax.set_xlabel("Date")
        ax.set_ylabel("Blood Pressure (mmHg)")
        ax.set_title("Blood Pressure Over Time")
        ax.legend()
        plt.xticks(rotation=45)
        st.pyplot(fig)

        # Critical Value Alert (Example)
        if not bp_df.empty:
            latest_bp = bp_df.iloc[-1]
            if latest_bp['systolic'] > 180 or latest_bp['diastolic'] > 120: # Hypertensive crisis example
                st.error(f"**Critical Alert:** Latest BP is {latest_bp['systolic']}/{latest_bp['diastolic']} mmHg on {latest_bp['date'].strftime('%Y-%m-%d')}!")
            elif latest_bp['systolic'] > 140 or latest_bp['diastolic'] > 90:
                st.warning(f"**High BP Alert:** Latest BP is {latest_bp['systolic']}/{latest_bp['diastolic']} mmHg on {latest_bp['date'].strftime('%Y-%m-%d')}.")

    else:
        st.info("No Blood Pressure data available for plotting.")

    # Cholesterol (similar plotting can be added)
    chol_df = trends['cholesterol']
    if not chol_df.empty and 'date' in chol_df.columns and 'ldl' in chol_df.columns:
        st.write("**Cholesterol Trend (Simulated)**")
        chol_df['date'] = pd.to_datetime(chol_df['date'])
        chol_df = chol_df.sort_values(by='date')
        
        fig_chol, ax_chol = plt.subplots()
        ax_chol.plot(chol_df['date'], chol_df['ldl'], marker='o', label='LDL')
        if 'hdl' in chol_df.columns:
             ax_chol.plot(chol_df['date'], chol_df['hdl'], marker='x', label='HDL')
        ax_chol.set_xlabel("Date")
        ax_chol.set_ylabel("Cholesterol (mg/dL)")
        ax_chol.set_title("Cholesterol Levels Over Time")
        ax_chol.legend()
        plt.xticks(rotation=45)
        st.pyplot(fig_chol)
    else:
        st.info("No Cholesterol data available for plotting.")

    # Downloadable Report (simple text report for now)
    report_content = f"Health Trend Report for Patient: {patient_info['full_name']} (ID: {patient_id})\n"
    report_content += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    if not bp_df.empty:
        report_content += "Blood Pressure Data:\n" + bp_df.to_string(index=False) + "\n\n"
    if not chol_df.empty:
        report_content += "Cholesterol Data:\n" + chol_df.to_string(index=False) + "\n\n"
    
    if len(report_content) > 150: # if some data was added
        st.download_button(
            label="Download Patient Trend Report (TXT)",
            data=report_content.encode('utf-8'),
            file_name=f"patient_{patient_id}_trend_report.txt",
            mime="text/plain"
        )
    else:
        st.info("Not enough data for a downloadable report.")


# --- Admin Dashboard (Simplified) ---
def admin_dashboard():
    st.header("Admin Dashboard")
    admin_menu = ["View Users", "View System Logs"]
    admin_choice = st.sidebar.radio("Admin Menu", admin_menu)

    if admin_choice == "View Users":
        st.subheader("All Users")
        conn = utils.get_db_connection()
        users = conn.execute("SELECT id, username, role, full_name, email, created_at FROM users").fetchall()
        conn.close()
        if users:
            df_users = pd.DataFrame(users)
            st.dataframe(df_users, use_container_width=True)
        else:
            st.info("No users in the system.")

    elif admin_choice == "View System Logs":
        st.subheader("System Access Logs (Last 50)")
        conn = utils.get_db_connection()
        logs = conn.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 50").fetchall()
        conn.close()
        if logs:
            df_logs = pd.DataFrame(logs)
            st.dataframe(df_logs, use_container_width=True)
        else:
            st.info("No logs found.")

# --- JSON Summary Display ---
def display_patient_json_summary(patient_user_id):
    st.subheader(f"JSON Summary for Patient ID: {patient_user_id}")
    summary_data = utils.generate_patient_json_summary(patient_user_id)
    if "error" in summary_data:
        st.error(summary_data["error"])
    else:
        st.json(summary_data)


# --- Main App Logic ---
def main():
    # Initialize DB and Key on first run or if module is reloaded
    # This might run multiple times in Streamlit's execution model, but utils.init_db is idempotent
    utils.init_db() 
    utils.load_or_generate_key()

    if not st.session_state.logged_in:
        st.title("Healthcare Portal Login")
        
        login_tab, register_tab = st.tabs(["Login", "Register"])
        with login_tab:
            display_login_form()
        with register_tab:
            display_registration_form()
        
        # For demo: Add initial admin/doctor/patient if DB is empty
        conn = utils.get_db_connection()
        user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        if user_count == 0:
            st.sidebar.info("No users found. Creating demo users...")
            utils.create_user("admin", "admin123", "admin", "Admin User", "admin@health.app")
            utils.create_user("drsmith", "doctor123", "doctor", "Alice Smith", "dr.smith@health.app")
            utils.create_user("johnp", "patient123", "patient", "John Patient", "john.p@mail.com", "1985-05-15")
            st.sidebar.success("Demo users (admin/admin123, drsmith/doctor123, johnp/patient123) created. Please login.")
            st.rerun()

    else:
        st.sidebar.subheader(f"Logged in as: {st.session_state.full_name} ({st.session_state.role})")
        if st.sidebar.button("Logout"):
            utils.log_access(st.session_state.user_id, "logout")
            for key in list(st.session_state.keys()):
                del st.session_state[key] # Clear all session state
            st.session_state.logged_in = False # Explicitly set logged_in to False
            st.rerun()
        
        st.sidebar.markdown("---")

        if st.session_state.role == 'patient':
            patient_dashboard()
        elif st.session_state.role == 'doctor':
            doctor_dashboard()
        elif st.session_state.role == 'admin':
            admin_dashboard()

if __name__ == "__main__":
    main()