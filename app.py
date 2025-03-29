from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import mysql.connector # type: ignore
from datetime import date, datetime
import regex as re
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import session, jsonify, render_template
from flask_socketio import join_room, leave_room, emit      
import google.generativeai as genai
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'shridharbhat',  # Replace with your actual password
    'database': 'therapy'    # Database name updated
}

# Database connection function
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Home route
@app.route('/')
def home():
    if 'user' in session:
        # Fetch the user details to display their name
        user = get_user_by_username(session['user'])
        if user:
            user_name = user.get('Name', 'User')
            print("User is logged in:", session['user']) # Log the username
        else:
            user_name = 'Unknown User'

        return render_template('home.html', show_appointment_options=True, user_name=user_name)
    return render_template('home.html')

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)  # Ensure results are in dictionary form
    cursor.execute("SELECT UserID, Username, Password, Role, PatientID, TherapistID FROM Users WHERE Username = %s", (username,))
    user = cursor.fetchone()

    if user:
        # If the user is a patient, fetch the patient's name
        if user['Role'] == 'Patient' and user['PatientID']:
            cursor.execute("SELECT Name FROM Patients WHERE PatientID = %s", (user['PatientID'],))
            patient_name = cursor.fetchone()
            if patient_name:
                user['Name'] = patient_name['Name']

        # If the user is a therapist, fetch the therapist's name
        elif user['Role'] == 'Therapist' and user['TherapistID']:
            cursor.execute("SELECT Name FROM Therapists WHERE TherapistID = %s", (user['TherapistID'],))
            therapist_name = cursor.fetchone()
            if therapist_name:
                user['Name'] = therapist_name['Name']

    cursor.close()
    conn.close()
    print(user)  # This will show the user object fetched from the database
    return user

@app.route('/view_resources')
def view_resources():
    return render_template('view_resources.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            return jsonify({"success": False, "error": "Database connection failed."})

        cursor = conn.cursor(dictionary=True)

        # Fetch user details based on username
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
        user = cursor.fetchone()
        
        cursor.close()
        conn.close()

        if user and check_password_hash(user['Password'], password):
            session['user'] = username
            session['role'] = user['Role']
            session['user_id'] = user['PatientID'] if user['Role'] == 'Patient' else user['TherapistID']
            
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Fetch user's name based on their role
            if user['Role'] == 'Patient':
                cursor.execute("SELECT Name FROM Patients WHERE PatientID = %s", (session['user_id'],))
                patient = cursor.fetchone()
                if patient:
                    session['user_name'] = patient['Name']
                    cursor.close()
                    conn.close()
                    return jsonify({"success": True})
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({"success": False, "error": "Patient name not found."}) 

            elif user['Role'] == 'Therapist':
                cursor.execute("SELECT Name FROM Therapists WHERE TherapistID = %s", (session['user_id'],))
                therapist = cursor.fetchone()
                if therapist:
                    session['user_name'] = therapist['Name']
                    cursor.close()
                    conn.close()
                    return jsonify({"success": True})
                else:
                    cursor.close()
                    conn.close()
                    return jsonify({"success": False, "error": "Therapist name not found."})

        return jsonify({"success": False, "error": "Invalid credentials."}) 

    return render_template('login.html')

@app.route('/reset_password_page', methods=['GET'])
def reset_password_page():
    return render_template('reset_password.html')  # Ensure 'reset_password.html' exists

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    if "otp_verified" not in session or not session["otp_verified"]:
        return jsonify({"success": False, "error": "OTP verification required before resetting password."}), 403

    if new_password != confirm_password:
        return jsonify({"success": False, "error": "Passwords do not match."}), 400

    username = session.get("reset_username")
    if not username:
        return jsonify({"success": False, "error": "Session expired. Please try again."}), 400

    # Hash and update the new password in DB (use your hashing method)
    hashed_password = generate_password_hash(new_password)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE Users SET Password = %s WHERE Username = %s", (hashed_password, username))
    conn.commit()
    
    cursor.close()
    conn.close()

    # Clear session after successful reset
    session.pop("otp", None)
    session.pop("otp_verified", None)
    session.pop("reset_username", None)

    return jsonify({"success": True, "message": "Password reset successfully. Redirecting to login..."})

# Route to send OTP
@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.json
    username = data.get("username")

    # Connect to DB
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch user role
        cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "error": "User not found."}), 404

        role = user["Role"]
        ID = user["PatientID"] if role == "Patient" else user["TherapistID"]
        # Retrieve ContactInfo based on role
        if role == "Therapist":
            cursor.execute("SELECT ContactInfo FROM Therapists WHERE TherapistID = %s", (ID,))
        elif role == "Patient":
            cursor.execute("SELECT ContactInfo FROM Patients WHERE PatientID = %s", (ID,))
        else:
            return jsonify({"success": False, "error": "Invalid user role."}), 400

        contact_info = cursor.fetchone()
        if not contact_info:
            return jsonify({"success": False, "error": "Contact information not found."}), 404

        email = contact_info["ContactInfo"]
        otp = str(random.randint(1000, 9999))  # Generate 4-digit OTP

        # Store OTP in session with expiry
        session["otp"] = otp
        session["otp_expiry"] = time.time() + 300  # OTP valid for 5 minutes
        session["reset_username"] = username  # Store username for reset process

        # Email body with OTP
        email_body = f"""
        <html>
            <body>
                <h2>Password Reset OTP</h2>
                <p>Your OTP for password reset is: <strong>{otp}</strong></p>
                <p>This OTP is valid for 5 minutes.</p>
            </body>
        </html>
        """

        send_email(email, "Password Reset OTP", email_body)
        return jsonify({"success": True, "message": "OTP sent to your email."})

    finally:
        cursor.close()
        conn.close()

import time
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    entered_otp = data.get("otp")

    # Check if OTP is in session and hasn't expired
    if "otp" not in session or "otp_expiry" not in session:
        return jsonify({"success": False, "error": "Session expired. Request OTP again."}), 400

    if time.time() > session["otp_expiry"]:
        session.pop("otp", None)
        session.pop("otp_expiry", None)
        return jsonify({"success": False, "error": "OTP expired. Request a new one."}), 400

    if session["otp"] != entered_otp:
        return jsonify({"success": False, "error": "Invalid OTP."}), 400
    session["otp_verified"] = True # Mark OTP as verified
    return jsonify({"success": True, "message": "OTP verified successfully."})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        contact_info = request.form['contact_info']
        role = request.form['role']  # Either 'patient', 'therapist', or 'admin'

        '''if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", contact_info):
            flash("Invalid email address format. Please enter a valid email.", "warning")
            return render_template('register.html')'''


        # Validation: Check username length and characters
        if len(username) < 4 or not re.match(r"^[A-Za-z0-9_]+$", username):
            flash("Username must be at least 4 characters long and contain only letters, numbers, and underscores.", "warning")
            return render_template('register.html')

        '''# Validation: Check password complexity
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[0-9]", password):
            flash("Password must be at least 8 characters long, with at least one uppercase letter and one digit.", "warning")
            return render_template('register.html')'''

        # Hash the password
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            if role == 'admin':
                admin_notes = request.form.get('admin_notes', '')  # Optional field

                # Check if username already exists in Admins table
                cursor.execute("SELECT * FROM Admins WHERE username = %s", (username,))
                if cursor.fetchone():
                    flash("Username already exists. Please choose a different one.", "warning")
                else:
                    cursor.execute('''
                        INSERT INTO Admins (Username, Password, FullName, ContactInfo, AdminNotes) 
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (username, hashed_password, name, contact_info, admin_notes))
                    conn.commit()

                    # Send confirmation email
                    subject = "Registration Successful"
                    body = f"Dear {name},\n\nYour Admin account has been successfully registered.\n\nThank you for joining us!"
                    send_email(contact_info, subject, body)

                    flash("Admin registration successful! Please log in.", "success")
                    return redirect(url_for('register'))

            elif role == 'patient':
                age = request.form['age']
                diagnosis = request.form.get('diagnosis', '')
                therapy_goals = request.form.get('therapy_goals', '')

                # Check if username already exists
                cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
                if cursor.fetchone():
                    flash("Username already exists. Please choose a different one.", "warning")
                else:
                    cursor.execute('''
                        INSERT INTO Patients (Name, Age, ContactInfo, Diagnosis, TherapyGoals) 
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (name, age, contact_info, diagnosis, therapy_goals))
                    patient_id = cursor.lastrowid
                    cursor.execute('''
                        INSERT INTO Users (Username, Password, Role, PatientID) 
                        VALUES (%s, %s, 'Patient', %s)
                    ''', (username, hashed_password, patient_id))
                    conn.commit()

                    # Send confirmation email
                    subject = "Registration Successful"
                    body = f"<p>Dear<strong> {name}</strong>,</p><p>Your Patient account has been successfully registered.</p><p>Thank you for joining us!</p>"
                    send_email(contact_info, subject, body)

                    flash("Patient registration successful! Please log in.", "success")
                    return redirect(url_for('register'))

            elif role == 'therapist':
                specialization = request.form['specialization']
                address = request.form['address']
                amount = request.form['amount']  # Define the amount variable
                # Check if username already exists
                cursor.execute("SELECT * FROM Users WHERE Username = %s", (username,))
                if cursor.fetchone():
                    flash("Username already exists. Please choose a different one.", "warning")
                else:
                    cursor.execute('''
                        INSERT INTO Therapists (Name, Specialization, ContactInfo, Address, Amount) 
                        VALUES (%s, %s, %s,%s,%s)
                    ''', (name, specialization, contact_info,address,amount))
                    therapist_id = cursor.lastrowid
                    cursor.execute('''
                        INSERT INTO Users (Username, Password, Role, TherapistID) 
                        VALUES (%s, %s, 'Therapist', %s)
                    ''', (username, hashed_password, therapist_id))
                    conn.commit()

                    # Send confirmation email
                    subject = "Registration Successful"
                    body = f"<p>Dear <strong>{name}</strong>,</p><p>Your Therapist account has been successfully registered.</p><p>Thank you for joining us!</p>"
                    send_email(contact_info, subject, body)

                    flash("Therapist registration successful! Please log in.", "success")
                    return redirect(url_for('register'))

            else:
                flash("Invalid role selected. Please choose Patient, Therapist, or Admin.", "danger")

        except mysql.connector.Error as err:
            conn.rollback()
            flash(f"Database error: {err}", "danger")

        finally:
            cursor.close()
            conn.close()

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('user_name', None)
    print(session)  # Log the session data
    return redirect(url_for('login', logout_success=True))

def send_email(receiver_email, subject, body):
    """Send confirmation email."""
    sender_email = "kiranraithal2004@gmail.com"
    password = "yjov fede skss grol"  # Replace with your app password
    # Create a multipart message and set headers
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = receiver_email

    # Attach the plain text and HTML versions of the email
    message.attach(MIMEText(body, "html"))
    #email_message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
            print("Email sent successfully!")
    except smtplib.SMTPAuthenticationError:
        print("Failed to authenticate with the SMTP server. Check email/password.")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

@app.route('/book_appointment', methods=['GET', 'POST'])
def book_appointment():
    if 'role' in session and session['role'] == 'Patient':  # Only allow patients to book appointments
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Fetch therapists with optional search/filter
            search_query = request.args.get('search', '')
            if search_query:
                cursor.execute('''
                    SELECT TherapistID, Name, Address, Specialization, Amount, ContactInfo
                    FROM Therapists 
                    WHERE (Name LIKE %s OR Address LIKE %s OR Specialization LIKE %s) 
                    AND IsVerified = 1
                ''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
            else:
                cursor.execute('''
                    SELECT TherapistID, Name, Address, Specialization, Amount, ContactInfo
                    FROM Therapists 
                    WHERE IsVerified = 1
                ''')
            therapists = cursor.fetchall()

        except mysql.connector.Error as e:
            flash(f"Database error: {e}", "danger")
            return redirect(url_for('home'))
        finally:
            cursor.close()
            conn.close()

        if request.method == 'POST':
            patient_id = session['user_id']  # Patient ID from session
            therapist_id = request.form.get('therapist_id')
            appointment_date = request.form.get('date')
            appointment_time = request.form.get('time')
            payment_method = request.form.get('payment_method')  # New payment method field

            # Validate form inputs
            if not therapist_id:
                flash('Please select a therapist.', 'danger')
                return render_template('book_appointment.html', therapists=therapists)

            try:
                # Validate date and time
                current_datetime = datetime.now()
                selected_datetime = datetime.strptime(f"{appointment_date} {appointment_time}", '%Y-%m-%d %H:%M')

                if selected_datetime <= current_datetime:
                    flash("Appointments must be booked for future dates and times.", "danger")
                    return render_template('book_appointment.html', therapists=therapists)
            except ValueError:
                flash("Invalid date or time format.", "danger")
                return render_template('book_appointment.html', therapists=therapists)

            try:
                conn = get_db_connection()
                cursor = conn.cursor(dictionary=True)

                # Fetch therapist details
                cursor.execute('SELECT * FROM Therapists WHERE TherapistID = %s', (therapist_id,))
                therapist = cursor.fetchone()

                if not therapist:
                    flash('Selected therapist not found.', 'danger')
                    return render_template('book_appointment.html', therapists=therapists)

                # Insert appointment into the database
                cursor.execute('''
                    INSERT INTO Appointments (PatientID, TherapistID, Date, Time)
                    VALUES (%s, %s, %s, %s)
                ''', (patient_id, therapist_id, appointment_date, appointment_time))
                conn.commit()

                # Get the last inserted appointment ID
                appointment_id = cursor.lastrowid

                # Insert payment record
                amount = therapist['Amount']
                cursor.execute('''
                    INSERT INTO PaymentRecords (PatientID, AppointmentID, Amount, PaymentDate, PaymentMethod)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (patient_id, appointment_id, amount, datetime.now().date(), payment_method))
                conn.commit()

                # Fetch patient email
                cursor.execute('SELECT * FROM Patients WHERE PatientID = %s', (patient_id,))
                patient = cursor.fetchone()

                # Send confirmation email
                if patient:
                    receiver_email = patient['ContactInfo']
                    subject = "Appointment Scheduled"

                    # Therapist details in HTML format for email
                    therapist_details = f"""
                    <strong>Therapist Name:</strong> {therapist['Name']}<br>
                    <strong>Specialization:</strong> {therapist['Specialization']}<br>
                    <strong>Address:</strong> {therapist['Address']}<br>
                    <strong>Contact:</strong> {therapist['ContactInfo']}<br>
                    <strong>Session Fee:</strong> Rs{amount}<br>
                    <strong>Payment Method:</strong> {payment_method}<br><br>
                    """

    # Email body with HTML formatting
                    body = f"""
                    Dear <strong>{patient['Name']}</strong>,<br><br>
                    Your appointment has been successfully booked with the following details:<br><br>
                    <strong>Appointment Date:</strong> {appointment_date}<br>
                    <strong>Appointment Time:</strong> {appointment_time}<br><br>
                    <strong>Therapist Details:</strong><br>
                    {therapist_details}
                    Thank you for choosing us!<br><br>
                    <strong>Visit our website:</strong> <a href="http://127.0.0.1:5000/">Mental Health Platform</a>
                    """
                    send_email(receiver_email, subject, body)
                    receiver_email_therapist = therapist['ContactInfo']
                    subject_therapist = "New Appointment Request"

                    patient_details_html = f"""
                    <strong>Patient Name:</strong> {patient['Name']}<br>
                    <strong>Contact:</strong> {patient['ContactInfo']}<br>
                    <strong>Appointment Date:</strong> {appointment_date}<br>
                    <strong>Appointment Time:</strong> {appointment_time}<br>
                    """

                    body_therapist = f"""
                    Dear <strong>{therapist['Name']}</strong>,<br><br>
                    A new appointment has been requested with the following details:<br><br>
                    {patient_details_html}
                    Please confirm the appointment at your earliest convenience.<br><br>
                    <strong>Visit our portal:</strong> <a href="http://127.0.0.1:5000/">Mental Health Platform</a>
                    """
                    send_email(receiver_email_therapist, subject_therapist, body_therapist)


                flash("Appointment scheduled successfully! A confirmation email has been sent.", "success")
                return redirect(url_for('book_appointment'))
            except mysql.connector.Error as e:
                flash(f"Database error during booking: {e}", "danger")
            finally:
                cursor.close()
                conn.close()

        return render_template('book_appointment.html', therapists=therapists)

    flash("Only patients can book appointments.", "danger")
    return redirect(url_for('book_appointment'))

from datetime import datetime, timedelta

@app.route('/appointment_history', methods=['GET'])
def appointment_history():
    if 'role' in session and session['role'] == 'Patient':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        now = datetime.now()

        # Fetch past and cancelled appointments, excluding 'Scheduled'
        cursor.execute(''' 
            SELECT 
                A.AppointmentID AS AppointmentID, 
                P.Name AS PatientName, 
                T.Name AS TherapistName, 
                A.TherapistID AS TherapistID,
                A.Date, 
                A.Time, 
                A.Status, 
                F.Comments,
                PR.Amount,
                PR.PaymentMethod,
                A.can_leave_feedback
            FROM Appointments A
            JOIN Patients P ON A.PatientID = P.PatientID
            JOIN Therapists T ON A.TherapistID = T.TherapistID
            LEFT JOIN Feedback F ON A.AppointmentID = F.AppointmentID
            LEFT JOIN PaymentRecords PR ON A.AppointmentID = PR.AppointmentID
            WHERE A.PatientID = %s 
            AND (CONCAT(A.Date, ' ', A.Time) < %s OR A.Status = 'Cancelled') 
            AND A.Status != 'Scheduled'
            ORDER BY A.Date DESC, A.Time DESC
        ''', (session['user_id'], now))
        
        appointments = cursor.fetchall()

        for appointment in appointments:
            # Convert Date and Time to datetime
            appointment_date = datetime.strptime(appointment['Date'], '%Y-%m-%d').date() if isinstance(appointment['Date'], str) else appointment['Date']
            if isinstance(appointment['Time'], str):
                appointment_time = datetime.strptime(appointment['Time'], '%H:%M').time()
            elif isinstance(appointment['Time'], timedelta):
                appointment_time = (datetime.min + appointment['Time']).time()
            else:
                appointment_time = appointment['Time']

            full_appointment_time = datetime.combine(appointment_date, appointment_time)

            # Check if feedback can be left (now >= appointment time)
            can_leave_feedback = now >= full_appointment_time

            # Update can_leave_feedback in DB if conditions are met
            if can_leave_feedback and appointment['Status'] in ['Confirmed', 'Completed']:
                cursor.execute('''
                    UPDATE Appointments 
                    SET can_leave_feedback = 1 
                    WHERE AppointmentID = %s
                ''', (appointment['AppointmentID'],))
                conn.commit()
                appointment['can_leave_feedback'] = 1  # Reflect in fetched data

            # Update status to 'Completed' if past and was 'Confirmed'
            if appointment['Status'] == 'Confirmed' and now >= full_appointment_time:
                cursor.execute('''
                    UPDATE Appointments 
                    SET Status = 'Completed' 
                    WHERE AppointmentID = %s
                ''', (appointment['AppointmentID'],))
                conn.commit()
                appointment['Status'] = 'Completed'

        cursor.close()
        conn.close()

        return render_template('appointment_history.html', appointments=appointments)

@app.route('/update_feedback', methods=['POST'])
def update_feedback():
    # Ensure the user is logged in and is a patient
    if 'user_id' not in session or session.get('role') != 'Patient':
        return jsonify({"success": False, "error": "Unauthorized access."}), 403

    appointment_id = request.form.get('appointment_id')
    new_comments = request.form.get('comments')

    if not appointment_id or not new_comments:
        return jsonify({"success": False, "error": "Missing appointment ID or feedback."})

    # Connect to the database
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Verify that the appointment belongs to the logged-in patient
    cursor.execute(
        "SELECT * FROM Appointments WHERE AppointmentID = %s AND PatientID = %s",
        (appointment_id, session['user_id'])
    )
    appointment = cursor.fetchone()
    if not appointment:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "Appointment not found or access denied."})

    # Check if feedback already exists for this appointment
    cursor.execute("SELECT * FROM Feedback WHERE AppointmentID = %s", (appointment_id,))
    feedback = cursor.fetchone()
    
    if feedback:
        # Update the existing feedback
        cursor.execute(
            "UPDATE Feedback SET Comments = %s WHERE AppointmentID = %s",
            (new_comments, appointment_id)
        )
    else:
        # Insert new feedback if none exists
        cursor.execute(
            "INSERT INTO Feedback (AppointmentID, Comments) VALUES (%s, %s)",
            (appointment_id, new_comments)
        )
    
    # Update the FeedbackGiven status in Appointments table
    cursor.execute(
        "UPDATE Appointments SET feedback_given = TRUE WHERE AppointmentID = %s",
        (appointment_id,)
    )
    
    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({"success": True, "message": "Feedback updated successfully."})

@app.route('/delete_feedback', methods=['POST'])
def delete_feedback():
    if 'user_id' not in session or session.get('role') != 'Patient':
        return jsonify({"success": False, "error": "Unauthorized access."}), 403

    appointment_id = request.form.get('appointment_id')
    if not appointment_id:
        return jsonify({"success": False, "error": "Missing appointment ID."})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Verify that the appointment belongs to the logged-in patient
    cursor.execute("SELECT * FROM Appointments WHERE AppointmentID = %s AND PatientID = %s",
                   (appointment_id, session['user_id']))
    appointment = cursor.fetchone()
    if not appointment:
        cursor.close()
        conn.close()
        return jsonify({"success": False, "error": "Appointment not found or access denied."})

    # Delete feedback from the Feedback table
    cursor.execute("DELETE FROM Feedback WHERE AppointmentID = %s", (appointment_id,))
    
    # Update the FeedbackGiven status in Appointments table
    cursor.execute(
        "UPDATE Appointments SET feedback_given = FALSE WHERE AppointmentID = %s",
        (appointment_id,)
    )

    conn.commit()
    cursor.close()
    conn.close()
    
    return jsonify({"success": True, "message": "Feedback deleted successfully."})


@app.route('/appointments')
def view_appointments():
    if 'role' in session and session['role'] == 'Patient':  # Only allow patients to view their appointments
        patient_id = session['user_id']
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        now = datetime.now()  # You might want to use `datetime.utcnow()` if you're using UTC

        # Fetch all upcoming appointments (excluding past and cancelled appointments)
        cursor.execute(''' 
            SELECT Appointments.AppointmentID, Patients.Name as PatientName, Therapists.Name as TherapistName,
                   Appointments.Date, Appointments.Time, Appointments.Status,PR.Amount,PR.PaymentMethod
            FROM Appointments
            JOIN Patients ON Appointments.PatientID = Patients.PatientID
            JOIN Therapists ON Appointments.TherapistID = Therapists.TherapistID
            LEFT JOIN PaymentRecords PR ON Appointments.AppointmentID = PR.AppointmentID
            WHERE Appointments.PatientID = %s AND Appointments.Status != 'Cancelled'
            AND CONCAT(Appointments.Date, ' ', Appointments.Time) > %s
            ORDER BY Appointments.Date, Appointments.Time
        ''', (patient_id, now))  # Filters out past appointments by comparing the appointment date and time with the current datetime
        
        appointments = cursor.fetchall()
        cursor.close()
        
        # Open a new cursor for updating the database
        cursor = conn.cursor()

        for appointment in appointments:
            # Ensure 'Date' is in datetime format (if needed)
            if isinstance(appointment['Date'], str):
                appointment_date = datetime.strptime(appointment['Date'], '%Y-%m-%d').date()
            else:
                appointment_date = appointment['Date']
            
            # Handle the 'Time' field
            if isinstance(appointment['Time'], str):
                appointment_time = datetime.strptime(appointment['Time'], '%H:%M').time()
            elif isinstance(appointment['Time'], timedelta):
                # Handle case where Time is stored as a timedelta
                appointment_time = (datetime.min + appointment['Time']).time()
            else:
                # If 'Time' is already a time object, use it directly
                appointment_time = appointment['Time']

            # Combine Date and Time into a full datetime object
            full_appointment_time = datetime.combine(appointment_date, appointment_time)
            
            # Check if feedback can be left (1 hour after the appointment time)
            can_leave_feedback = now >= full_appointment_time + timedelta(hours=1)
            
            # Update the database with the new flag
            cursor.execute(''' 
                UPDATE Appointments
                SET can_leave_feedback = %s
                WHERE AppointmentID = %s
            ''', (can_leave_feedback, appointment['AppointmentID']))
        
        # Commit the changes to the database
        conn.commit()
        conn.close()
        
        return render_template('appointments.html', appointments=appointments)
    else:
        return redirect(url_for('home'))

    
@app.route('/upcoming_appointments', methods=['GET'])
def upcoming_appointments():
    if 'role' in session and session['role'] == 'Patient':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the current date and time
        now = datetime.now()

        # Fetch upcoming appointments for the logged-in patient, excluding cancelled ones
        cursor.execute('''
            SELECT A.AppointmentID, P.Name AS PatientName,T.TherapistID, T.Name AS TherapistName, A.Date, A.Time, A.Status,T.ContactInfo,T.Address
            FROM Appointments A
            JOIN Patients P ON A.PatientID = P.PatientID
            JOIN Therapists T ON A.TherapistID = T.TherapistID
            WHERE A.PatientID = %s AND CONCAT(A.Date, ' ', A.Time) > %s AND A.Status != 'Cancelled'
            ORDER BY A.Date ASC, A.Time ASC
        ''', (session['user_id'], now))  # Use session to get the patient’s ID
        
        appointments = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template('upcoming_appointments.html', appointments=appointments)
    else:
        flash("You must be logged in as a Patient to view upcoming appointments.", "danger")
        return redirect(url_for('home'))



# Cancel appointment route (for patients)
@app.route('/cancel_appointment/<int:appointment_id>', methods=['POST'])
def cancel_appointment(appointment_id):
    if 'role' in session and session['role'] == 'Patient':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Check if the appointment exists and if it belongs to the current user
        cursor.execute('''SELECT AppointmentID, PatientID, TherapistID, Date, Time FROM Appointments WHERE AppointmentID = %s''', (appointment_id,))
        appointment = cursor.fetchone()
        
        if appointment:
            appointment_id_from_db = appointment['AppointmentID']
            patient_id_from_db = appointment['PatientID']
            therapist_id = appointment['TherapistID']
            date = appointment['Date']
            time = appointment['Time']

            # Retrieve the therapist's name
            cursor.execute('SELECT * FROM Therapists WHERE TherapistID = %s', (therapist_id,))
            therapist = cursor.fetchone()
            therapist_name = therapist['Name'] if therapist else "Unknown"

        if appointment is None:
            flash("Appointment not found.", "danger")
            conn.close()
            return redirect(url_for('view_appointments'))

        # Ensure that the patient is canceling their own appointment
        if patient_id_from_db != session['user_id']:
            flash("You are not authorized to cancel this appointment.", "danger")
            conn.close()
            return redirect(url_for('view_appointments'))
        
        # Retrieve the patient's contact information
        cursor.execute('SELECT * FROM Patients WHERE PatientID = %s', (patient_id_from_db,))
        patient = cursor.fetchone()

        receiver_email = patient['ContactInfo']
        subject = "Appointment Cancellation"
        body = f"""
            Dear <strong> {patient['Name']} </strong>,<br><br>
            Your appointment with Therapist: <strong>{therapist_name}</strong> Therapist ID {therapist_id} scheduled for {date} at {time} has been cancelled.<br><br>
            We apologize for any inconvenience caused. If you have any questions, please contact us.<br><br>
            Thank you!
            """
        send_email(receiver_email, subject, body)

            # Email to therapist
        subject_therapist = "Appointment Cancellation"
        body_therapist = f"""
        Dear  <strong>{therapist_name} </strong>,<br><br>
        The appointment with Patient: <strong>{patient['Name']}</strong> scheduled for {date} at {time} has been cancelled.<br><br>
        We apologize for any inconvenience caused. If you have any questions, please contact us.<br><br>
        Thank you!
        """
        send_email(therapist['ContactInfo'], subject_therapist, body_therapist)
        # Update the status of the appointment to "Cancelled"
        cursor.execute('''UPDATE Appointments SET Status = 'Cancelled' WHERE AppointmentID = %s AND PatientID = %s''', 
                       (appointment_id, session['user_id']))
        conn.commit()

        cursor.close()
        conn.close()

        flash("Appointment cancelled successfully.", "success")
        return redirect(url_for('view_appointments'))
    else:
        flash("You are not authorized to cancel this appointment.", "danger")
        return redirect(url_for('home'))

@app.route('/feedback/<int:appointment_id>', methods=['GET', 'POST'])
def feedback(appointment_id):
    # Check if the user is logged in and is a Patient
    if 'role' in session and session['role'] == 'Patient':
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the appointment exists and fetch feedback status and patient ID
        cursor.execute('''SELECT feedback_given, PatientID FROM Appointments WHERE AppointmentID = %s''', (appointment_id,))
        appointment = cursor.fetchone()

        if appointment is None:
            flash("Appointment not found.", "danger")
            conn.close()
            return redirect(url_for('view_appointments'))

        feedback_given, patient_id = appointment

        # Ensure that the logged-in patient is the one who booked this appointment
        if patient_id != session['user_id']:
            flash("You cannot submit feedback for this appointment.", "danger")
            conn.close()
            return redirect(url_for('view_appointments'))

        # Prevent the patient from submitting feedback if it's already been submitted
        if feedback_given:
            flash("Feedback has already been submitted for this appointment.", "warning")
            conn.close()
            return redirect(url_for('view_appointments'))

        if request.method == 'POST':
            # Ensure both rating and comments are provided
            if 'rating' not in request.form or 'comments' not in request.form:
                return render_template('feedback.html', appointment_id=appointment_id)

            rating = request.form['rating']
            comments = request.form['comments']

            try:
                # Insert feedback into the Feedback table
                cursor.execute('''INSERT INTO Feedback (AppointmentID, Rating, Comments, Date)
                                VALUES (%s, %s, %s, %s)''', (appointment_id, rating, comments, date.today()))

                # Update the appointment to mark feedback as given
                cursor.execute('''UPDATE Appointments SET feedback_given = TRUE WHERE AppointmentID = %s''', (appointment_id,))
                conn.commit()

                flash("Feedback submitted successfully!", "success")
            except mysql.connector.Error as err:
                flash(f"Error: {err}", "danger")
                conn.rollback()
            finally:
                conn.close()
                return redirect(url_for('appointment_history'))

        return render_template('feedback.html', appointment_id=appointment_id)
    
    else:
        flash("Only patients can submit feedback.", "danger")
        return redirect(url_for('home'))

@app.route('/view_all_appointments', methods=['GET'])
def view_all_appointments():
    if 'role' in session and session['role'] == 'Therapist':
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the current date and time
        now = datetime.now()

        # Fetch only upcoming appointments that are not canceled
        cursor.execute('''
            SELECT A.AppointmentID, P.Name AS PatientName, A.Date, A.Time, A.Status, P.Diagnosis, P.Age, P.TherapyGoals,A.PatientID
            FROM Appointments A
            JOIN Patients P ON A.PatientID = P.PatientID
            WHERE A.TherapistID = %s 
                  AND CONCAT(A.Date, ' ', A.Time) > %s 
                  AND A.Status != 'Cancelled'
            ORDER BY A.Date, A.Time
        ''', (session['user_id'], now))  # session['user_id'] stores the therapist's ID

        appointments = cursor.fetchall()

        cursor.close()
        conn.close()

        # Combine Date and Time into a datetime string for easier display
        for appointment in appointments:
            appointment['AppointmentDateTime'] = f"{appointment['Date']} {appointment['Time']}"

        return render_template('view_all_appointments.html', appointments=appointments)
    else:
        flash("You are not authorized to view appointments.", "danger")
        return redirect(url_for('home'))


@app.route('/manage_appointments', methods=['GET'])
def manage_appointments():
    if 'role' in session and session['role'] == 'Therapist':
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Get the current date and time
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            # Fetch all upcoming (future) appointments for the therapist with payment details
            query = '''
                SELECT 
                    A.AppointmentID, 
                    P.Name AS PatientName, 
                    A.Date, 
                    A.Time, 
                    A.Status, 
                    P.Diagnosis, 
                    P.TherapyGoals, 
                    P.Age, 
                    PR.PaymentMethod, 
                    PR.Amount 
                FROM Appointments A
                JOIN Patients P ON A.PatientID = P.PatientID
                LEFT JOIN PaymentRecords PR ON A.AppointmentID = PR.AppointmentID
                WHERE A.TherapistID = %s 
                  AND CONCAT(A.Date, ' ', A.Time) > %s 
                  AND A.Status != 'Completed'
                ORDER BY A.Date, A.Time
            '''

            cursor.execute(query, (session['user_id'], now))
            appointments = cursor.fetchall()

        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            appointments = []
        finally:
            cursor.close()
            conn.close()

        return render_template('manage_appointments.html', appointments=appointments)

    else:
        flash("You are not authorized to manage appointments.", "danger")
        return redirect(url_for('home'))

    
@app.route('/confirm_appointment/<int:appointment_id>', methods=['POST'])
def confirm_appointment(appointment_id):
    if 'role' in session and session['role'] == 'Therapist':
        therapist_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the appointment exists and is assigned to the current therapist
        cursor.execute('''
            SELECT AppointmentID, TherapistID, PatientID, Date, Time FROM Appointments 
            WHERE AppointmentID = %s AND TherapistID = %s
        ''', (appointment_id, therapist_id))
        appointment = cursor.fetchone()

        if not appointment:
            flash("Appointment not found or unauthorized action.", "danger")
        else:
            try:
                appointment_id_from_db, therapist_id_from_db, patient_id_from_db, date, time = appointment

                # Update the appointment status to 'Confirmed'
                cursor.execute('''
                    UPDATE Appointments SET Status = 'Confirmed' WHERE AppointmentID = %s
                ''', (appointment_id,))
                conn.commit()

                # Fetch patient email
                cursor.execute('SELECT ContactInfo FROM Patients WHERE PatientID = %s', (patient_id_from_db,))
                patient = cursor.fetchone()

                # Fetch therapist email
                cursor.execute('SELECT ContactInfo FROM Therapists WHERE TherapistID = %s', (therapist_id_from_db,))
                therapist = cursor.fetchone()

                # Send confirmation email to the patient
                if patient:
                    receiver_email = patient[0]  # Access tuple element directly
                    subject = "Appointment Confirmation"
                    body = (
                        f"Dear Patient,\n\nYour appointment with Therapist ID {therapist_id_from_db} "
                        f"scheduled for {date} at {time} has been confirmed by the Therapist.\n\nThank you!"
                    )
                    send_email(receiver_email, subject, body)

                # Send confirmation email to the therapist
                if therapist:
                    receiver_email = therapist[0]
                    subject = "Appointment Confirmation"
                    body = (
                        f"Dear Therapist,\n\nThe appointment with Patient ID {patient_id_from_db} "
                        f"scheduled for {date} at {time} has been confirmed.\n\nThank you!"
                    )
                    send_email(receiver_email, subject, body)

                flash("Appointment confirmed successfully. Both you and the patient have been notified via email.", "success")
            except Exception as e:
                flash(f"Error confirming appointment: {e}", "danger")
            finally:
                cursor.close()
                conn.close()

        return redirect(url_for('manage_appointments'))
    else:
        flash("You are not authorized to confirm appointments.", "danger")
        return redirect(url_for('home'))


@app.route('/cancel_appointment_therapist/<int:appointment_id>', methods=['POST'])
def cancel_appointment_therapist(appointment_id):
    if 'role' in session and session['role'] == 'Therapist':
        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the appointment exists and if it belongs to the current therapist
        cursor.execute('''SELECT AppointmentID, TherapistID, PatientID, Date, Time FROM Appointments WHERE AppointmentID = %s''', (appointment_id,))
        appointment = cursor.fetchone()

        if appointment is None:
            flash("Appointment not found.", "danger")
            conn.close()
            return redirect(url_for('view_all_appointments'))

        appointment_id_from_db, therapist_id_from_db, patient_id_from_db, date, time = appointment

        # Ensure that the therapist is canceling their own appointment
        if therapist_id_from_db != session['user_id']:
            flash("You are not authorized to cancel this appointment.", "danger")
            conn.close()
            return redirect(url_for('view_all_appointments'))

        try:
            # Fetch patient email
            cursor.execute('SELECT ContactInfo FROM Patients WHERE PatientID = %s', (patient_id_from_db,))
            patient = cursor.fetchone()

            # Fetch therapist email
            cursor.execute('SELECT ContactInfo FROM Therapists WHERE TherapistID = %s', (therapist_id_from_db,))
            therapist = cursor.fetchone()

            # Send cancellation email to the patient
            if patient:
                receiver_email = patient[0]
                subject = "Appointment Cancellation"
                body = (
                    f"Dear Patient,\n\nYour appointment with Therapist ID {therapist_id_from_db} "
                    f"scheduled for {date} at {time} has been cancelled.\n\nWe apologize for any inconvenience caused."
                )
                send_email(receiver_email, subject, body)

            # Send cancellation email to the therapist
            if therapist:
                receiver_email = therapist[0]
                subject = "Appointment Cancellation"
                body = (
                    f"Dear Therapist,\n\nThe appointment with Patient ID {patient_id_from_db} "
                    f"scheduled for {date} at {time} has been cancelled.\n\nPlease update your schedule accordingly."
                )
                send_email(receiver_email, subject, body)

            # Delete any associated feedback first
            cursor.execute('''DELETE FROM Feedback WHERE AppointmentID = %s''', (appointment_id,))
            conn.commit()

            cursor.execute('''DELETE FROM paymentrecords WHERE AppointmentID = %s''', (appointment_id,))
            conn.commit() 

            # Now delete the appointment
            cursor.execute('''UPDATE Appointments SET Status = 'Cancelled' WHERE AppointmentID = %s AND PatientID = %s''', 
                           (appointment_id, session['user_id']))
            conn.commit()

            flash("Appointment cancelled successfully. Both you and the patient have been notified via email.", "success")
        except Exception as e:
            flash(f"Error cancelling appointment: {e}", "danger")
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('view_all_appointments'))
    else:
        flash("You are not authorized to cancel this appointment.", "danger")
        return redirect(url_for('home'))
    
from datetime import datetime

@app.route('/therapist_past_appointments', methods=['GET'])
def therapist_past_appointments():
    if 'role' in session and session['role'] == 'Therapist':
        therapist_id = session['user_id']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  # Ensure results are returned as dictionaries

        try:
            # Fetch past appointments for the logged-in therapist, including canceled appointments
            cursor.execute('''
                SELECT A.AppointmentID, P.Name, P.Age, P.TherapyGoals,P.PatientID, P.Diagnosis, A.Date, A.Time, A.Status, F.Comments,PR.Amount,PR.PaymentMethod
                FROM Appointments AS A
                JOIN Patients AS P ON A.PatientID = P.PatientID
                LEFT JOIN PaymentRecords PR ON A.AppointmentID = PR.AppointmentID
                LEFT JOIN Feedback AS F ON A.AppointmentID = F.AppointmentID
                WHERE A.TherapistID = %s AND (A.Date < CURDATE() OR A.Status = 'Cancelled') AND A.Status != 'Scheduled'
                ORDER BY A.Date DESC, A.Time DESC
            ''', (therapist_id,))

            past_appointments = cursor.fetchall()

            # Check each appointment to update the status if needed
            now = datetime.now()

            for appointment in past_appointments:
                # Combine the appointment date and time into a single datetime object
                appointment_time = datetime.strptime(f"{appointment['Date']} {appointment['Time']}", '%Y-%m-%d %H:%M:%S')

                # If the status is 'Confirmed' and the appointment time has passed, update the status to 'Completed'
                if appointment['Status'] == 'Confirmed' and now >= appointment_time:
                    cursor.execute(''' 
                        UPDATE Appointments
                        SET Status = 'Completed'
                        WHERE AppointmentID = %s
                    ''', (appointment['AppointmentID'],))
                    conn.commit()

                    # Update the appointment status in the list
                    appointment['Status'] = 'Completed'
        finally:
            cursor.close()
            conn.close()

        return render_template('therapist_past_appointments.html', appointments=past_appointments)
    else:
        flash("You are not authorized to view this page.", "danger")
        return redirect(url_for('home'))


@app.route('/add_note_page', methods=['GET', 'POST'])
def add_note_page():
    # Check if the user is logged in and is a therapist
    if 'role' not in session or session['role'] != 'Therapist':
        flash("Unauthorized access. Please log in as a therapist.", "danger")
        return redirect(url_for('login'))

    therapist_id = session.get('user_id')  # TherapistID is stored in session

    if request.method == 'POST':
        # Get appointment ID and note text from the form
        appointment_id = request.form.get('appointment_id')
        note_text = request.form.get('note_text')

        if not appointment_id or not note_text:
            flash("Both Appointment ID and Note Text are required.", "warning")
            return render_template('add_note_page.html')

        # Validate and insert the note into the database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Validate if the appointment belongs to the therapist
            cursor.execute('''
                SELECT * FROM Appointments 
                WHERE AppointmentID = %s AND TherapistID = %s
            ''', (appointment_id, therapist_id))
            appointment = cursor.fetchone()

            if not appointment:
                flash("Invalid Appointment ID or you are not the assigned therapist.", "danger")
                return render_template('add_note_page.html')

            # Insert the note into TherapistNotes table
            cursor.execute('''
                INSERT INTO TherapistNotes (AppointmentID, TherapistID, NoteText)
                VALUES (%s, %s, %s)
            ''', (appointment_id, therapist_id, note_text))
            conn.commit()

            flash("Note successfully added!", "success")
            return redirect(url_for('add_note_page'))

        except Exception as e:
            flash("An error occurred while adding the note. Please try again.", "danger")
            print(f"Error: {e}")  # Log the error for debugging
        finally:
            # Ensure the database connection is closed
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template('add_note_page.html')

@app.route('/view_notes', methods=['GET', 'POST'])
def view_notes():
    # Check if the user is logged in and is a therapist
    if 'role' not in session or session['role'] != 'Therapist':
        flash("Unauthorized access. Please log in as a therapist.", "danger")
        return redirect(url_for('login'))

    therapist_id = session.get('user_id')  # TherapistID is stored in session

    if request.method == 'POST':
        # Get the patient ID input by the therapist
        patient_id = request.form.get('patient_id')

        # Ensure the patient_id is provided
        if patient_id:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            # Validate that the patient has appointments with this therapist
            cursor.execute('''
                SELECT COUNT(*) AS AppointmentCount
                FROM Appointments
                WHERE PatientID = %s AND TherapistID = %s
            ''', (patient_id, therapist_id))
            appointment_check = cursor.fetchone()

            if appointment_check and appointment_check['AppointmentCount'] > 0:
                # Fetch all notes for the given patient
                cursor.execute('''
                    SELECT N.NoteID, N.NoteText, N.DateCreated, A.Date, A.Time, P.Name AS PatientName
                    FROM TherapistNotes N
                    JOIN Appointments A ON N.AppointmentID = A.AppointmentID
                    JOIN Patients P ON A.PatientID = P.PatientID
                    WHERE A.PatientID = %s AND A.TherapistID = %s
                    ORDER BY A.Date, A.Time
                ''', (patient_id, therapist_id))
                notes = cursor.fetchall()

                cursor.close()
                conn.close()

                if notes:
                    return render_template('view_notes.html', notes=notes, patient_id=patient_id)
                else:
                    flash("No notes found for this patient.", "info")
            else:
                flash(f"You do not have permission to access notes for Patient ID: {patient_id}", "danger")
                cursor.close()
                conn.close()
        else:
            flash("Please enter a valid Patient ID.", "warning")

    return render_template('view_notes.html', notes=[], patient_id=None)


@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    if 'role' not in session or session['role'] != 'Therapist':
        flash("Unauthorized access. Please log in as a therapist.", "danger")
        return redirect(url_for('login'))

    therapist_id = session.get('user_id')  # TherapistID is stored in session

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch the note to be edited
    cursor.execute('''
        SELECT NoteID, NoteText
        FROM TherapistNotes
        WHERE NoteID = %s AND TherapistID = %s
    ''', (note_id, therapist_id))
    note = cursor.fetchone()

    if not note:
        flash("Note not found or you are not authorized to edit this note.", "danger")
        return redirect(url_for('view_notes'))

    if request.method == 'POST':
        # Get the updated note text from the form
        updated_note = request.form['note_text']

        # Update the note in the database
        cursor.execute('''
            UPDATE TherapistNotes
            SET NoteText = %s
            WHERE NoteID = %s
        ''', (updated_note, note_id))
        conn.commit()

        cursor.close()
        conn.close()

        flash("Note updated successfully.", "success")
        return redirect(url_for('view_notes'))

    cursor.close()
    conn.close()

    return render_template('edit_note.html', note=note)


@app.route('/delete_note/<int:note_id>', methods=['POST'])
def delete_note(note_id):
    if 'role' not in session or session['role'] != 'Therapist':
        return jsonify({"status": "error", "message": "Unauthorized access. Please log in as a therapist."}), 403

    therapist_id = session.get('user_id')  # TherapistID is stored in session

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete the note from the database
        cursor.execute('''
            DELETE FROM TherapistNotes
            WHERE NoteID = %s AND TherapistID = %s
        ''', (note_id, therapist_id))
        conn.commit()

        return jsonify({"status": "success", "message": "Note deleted successfully."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error deleting note: {e}"}), 500
    finally:
        cursor.close()
        conn.close()

# Configure the Gemini API
genai.configure(api_key="AIzaSyArfbShGCsh2JqfUbiuoLAWfb4RLh85RdY")
model = genai.GenerativeModel("gemini-1.5-flash")

# Function to generate a response based on user input
def generate_response(user_input):
    response = model.generate_content(user_input)
    return response.text

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')  # Get the message from the client
    if not user_message:
        return jsonify({"response": "Sorry, I didn't understand that. Can you please try again?"})

    # Generate a response using the Gemini model
    bot_response = generate_response(user_message)

    # Replace newlines with <br> for formatting
    bot_response = bot_response.replace("\n", "<br>")

    # Use regex to bold the point names (headers)
    bot_response = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', bot_response)

    # Return the response in a format that the frontend can render as HTML
    return jsonify({"response": bot_response})


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM Admins WHERE Username = %s AND Password = %s", (username, password))
        admin = cursor.fetchone()
        cursor.close()
        conn.close()

        if admin:
            session['admin_logged_in'] = True
            return jsonify(success=True)
        else:
            flash('Invalid credentials', 'danger')
            return jsonify(success=False, error="Invalid username or password")

    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT COUNT(*) AS user_count FROM Users")
    user_count = cursor.fetchone()['user_count']

    cursor.execute("SELECT COUNT(*) AS therapist_count FROM Therapists")
    therapist_count = cursor.fetchone()['therapist_count']

    cursor.execute("SELECT COUNT(*) AS appointment_count FROM Appointments")
    appointment_count = cursor.fetchone()['appointment_count']
    cursor.close()
    conn.close()

    return render_template('admin_dashboard.html', user_count=user_count, therapist_count=therapist_count, appointment_count=appointment_count)

@app.route('/admin/therapist')
def manage_therapist():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM Therapists")
    therapists = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('manage_therapist.html', therapists=therapists)

@app.route('/admin/verify_therapist/<int:therapist_id>', methods=['POST'])
def verify_therapist(therapist_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Update the therapist's verification status in the database
        cursor.execute("UPDATE Therapists SET IsVerified = 1 WHERE TherapistID = %s", (therapist_id,))
        conn.commit()

        # Fetch therapist's email
        cursor.execute("SELECT ContactInfo FROM Therapists WHERE TherapistID = %s", (therapist_id,))
        therapist = cursor.fetchone()

        if therapist and therapist[0]:
            # Send an email notification
            sender_email = "kiranraithal2004@gmail.com"  # Replace with your email
            password = "yjov fede skss grol"  # Replace with your app password
            receiver_email = therapist[0]  # Therapist's email
            subject = "Verification Successful"
            body = "Congratulations! Your account has been successfully verified. You can now access all features."

            # Combine subject and body
            email_message = f"Subject: {subject}\n\n{body}"

            try:
                with smtplib.SMTP("smtp.gmail.com", 587) as server:
                    server.starttls()
                    server.login(sender_email, password)
                    server.sendmail(sender_email, receiver_email, email_message)
                print("Verification email sent successfully!")
            except Exception as email_error:
                print(f"Failed to send verification email: {email_error}")

        cursor.close()
        conn.close()
        return jsonify({ "success": True, "message": "Therapist verified successfully" }), 200

    except Exception as e:
        print(f"Error verifying therapist: {e}")
        return jsonify({"success": False, "error": "Failed to verify therapist"}), 500

# Manage Users
@app.route('/admin/manage_users', methods=['GET'])
def manage_users():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch user details (ID, Name, Email, Role)
    cursor.execute("SELECT * FROM Users")
    users = cursor.fetchall()
    cursor.execute("SELECT * FROM Patients")
    patients = cursor.fetchall()
    cursor.execute("SELECT * FROM Therapists")
    therapists = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template("manage_users.html", users=users,patients=patients, therapists=therapists)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    try:
        # Get database connection
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Fetch the user's role and corresponding IDs
        cursor.execute("SELECT Username,Role, PatientID, TherapistID FROM Users WHERE UserID = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            print(f"User with ID {user_id} not found in Users table.")
            return jsonify({"error": "User not found"}), 404

        # Debug: Print the fetched user data
        print(f"User data fetched: {user}")

        # Extract email for notification
        if user['Role'] == "Patient":
            cursor.execute("SELECT ContactInfo AS email FROM Patients WHERE PatientID = %s", (user['PatientID'],))
        else:
            cursor.execute("SELECT ContactInfo AS email FROM Therapists WHERE TherapistID = %s", (user['TherapistID'],))
        
        email_data = cursor.fetchone()
        if not email_data or 'email' not in email_data:
            print("Email not found for the user.")
            return jsonify({"error": "Email not found"}), 500

        email = email_data['email']

        # Delete the user from the Users table first
        cursor.execute("DELETE FROM Users WHERE UserID = %s", (user_id,))

        # Delete from Patients or Therapists table based on the Role
        if user["Role"] == "Patient" and user["PatientID"]:
            print(f"Deleting Patient with PatientID: {user['PatientID']}")
            cursor.execute("DELETE FROM Patients WHERE PatientID = %s", (user["PatientID"],))
        elif user["Role"] == "Therapist" and user["TherapistID"]:
            print(f"Deleting Therapist with TherapistID: {user['TherapistID']}")
            cursor.execute("DELETE FROM Therapists WHERE TherapistID = %s", (user["TherapistID"],))

        # Commit changes to the database
        conn.commit()

        # Debug: Confirm that deletion is complete
        print("User deleted successfully.")

        # Send email notification
        subject = "Account Deletion Notification"
        body = f"<p>Dear <strong> {user['Username']} </strong>,</p><p>Your account has been successfully deleted from the system.</p><p>If you have any questions, please contact the admin team.</p>"
        send_email(email, subject, body)

        # Close the cursor and connection
        cursor.close()
        conn.close()

        return jsonify({"success": True}), 200

    except Exception as e:
        print(f"Error deleting user: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

# Manage Appointments - View and Delete
@app.route('/admin/manage_admin_appointments', methods=['GET', 'POST'])
def manage_admin_appointments():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch all appointments with patient and therapist details
    cursor.execute("""
        SELECT A.AppointmentID, A.Date AS date, A.Time AS time,A.Status AS status,
               P.Name AS patient_name, P.ContactInfo AS patient_contact,
               T.Name AS therapist_name, T.Specialization, T.ContactInfo AS therapist_contact
        FROM Appointments A
        JOIN Patients P ON A.PatientID = P.PatientID
        JOIN Therapists T ON A.TherapistID = T.TherapistID
        ORDER BY A.AppointmentID ASC
    """)
    appointments = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_appointment.html', appointments=appointments)

@app.route('/admin/delete_appointment/<int:appointment_id>', methods=['POST'])
def delete_appointment(appointment_id):
    if 'admin_logged_in' not in session:
        return jsonify({'message': 'You are not authorized to delete appointments.', 'status': 'error'})

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Fetch the appointment details
        cursor.execute(''' 
            SELECT P.ContactInfo AS PatientEmail, T.ContactInfo AS TherapistEmail,
                   P.Name AS PatientName, T.Name AS TherapistName, A.Date, A.Time
            FROM Appointments A
            JOIN Patients P ON A.PatientID = P.PatientID
            JOIN Therapists T ON A.TherapistID = T.TherapistID
            WHERE A.AppointmentID = %s
        ''', (appointment_id,))
        appointment = cursor.fetchone()
    
        if not appointment:
            return jsonify({'message': 'Appointment not found.', 'status': 'error'})
    
        # Step 1: Delete dependent records from child tables
        tables_to_clean = ['paymentrecords', 'feedback', 'therapistnotes']
        for table in tables_to_clean:
            cursor.execute(f"DELETE FROM {table} WHERE AppointmentID = %s", (appointment_id,))
    
        # Step 2: Delete the appointment from the Appointments table
        cursor.execute("DELETE FROM Appointments WHERE AppointmentID = %s", (appointment_id,))
        
        # Commit the changes after all deletions
        conn.commit()

        # Step 3: Send email notifications with separate bodies for Patient and Therapist

        # Email body for the patient
        patient_subject = "Appointment Deleted Notification"
        patient_body = f"""
        <p>Dear <strong>{appointment['PatientName']}</strong>,</p>
        <p>We regret to inform you that your appointment scheduled for {appointment['Date']} at {appointment['Time']} with {appointment['TherapistName']} has been deleted from the system.</p>
        <p>If you have any questions or wish to reschedule, please feel free to contact the admin team.</p>
        <p>Best regards,<br>Admin Team</p>
        """
        
        # Email body for the therapist
        therapist_subject = "Appointment Deleted Notification"
        therapist_body = f"""
        <p>Dear <strong>{appointment['TherapistName']}</strong>,</p>
        <p>This is to inform you that the appointment scheduled with {appointment['PatientName']} for {appointment['Date']} at {appointment['Time']} has been deleted from the system.</p>
        <p>If you have any questions or need further assistance, please feel free to contact the admin team.</p>
        <p>Best regards,<br>Admin Team</p>
        """

        # Send separate emails
        send_email(appointment['PatientEmail'], patient_subject, patient_body)
        send_email(appointment['TherapistEmail'], therapist_subject, therapist_body)

        return jsonify({
            'message': 'Appointment deleted successfully.',
            'status': 'success',
            'redirect': url_for('manage_admin_appointments')  # Send the redirect URL
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()

        return jsonify({'message': f"Error deleting appointment: {str(e)}", 'status': 'error'})
    
    finally:
        cursor.close()
        conn.close()

# Initialize Flask-SocketIO
socketio = SocketIO(app)

# Define a route for the chat page
@app.route('/chat_with_patient')
def chat_with_patient():
    # Ensure the user is logged in and is a therapist
    if 'user' not in session or session.get('role') != 'Therapist':
        return jsonify({"error": "Therapist not logged in"}), 403

    return render_template('chat_with_patient.html')  # HTML should handle WebSocket connections

@app.route('/chat_with_therapist', methods=['GET'])
def chat_with_therapist():
    # Ensure the user is logged in and is a patient
    if 'user' not in session or session.get('role') != 'Patient':
        return jsonify({"error": "Patient not logged in"}), 403

    return render_template('chat_with_therapist.html')

@socketio.on('join')
def on_join(data):
    # Validate room and join
    room = data.get('room')
    if not room:
        emit('error', {'message': 'Room ID is required'})
        return

    user_name = session.get('user_name', 'Anonymous')
    join_room(room)
    emit('message', {'sender': 'System', 'message': f"{user_name} has joined the room."}, room=room)

@socketio.on('send_message')
def handle_message(data):
    # Validate room and message
    room = data.get('room')
    message = data.get('message')
    if not room or not message:
        emit('error', {'message': 'Room and message are required'})
        return

    user_name = session.get('user_name', 'Anonymous')
    emit('message', {'sender': user_name, 'message': message}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data.get('room')
    if not room:
        emit('error', {'message': 'Room ID is required'})
        return

    user_name = session.get('user_name', 'Anonymous')
    leave_room(room)
    emit('message', {'sender': 'System', 'message': f"{user_name} has left the room."}, room=room)

@app.route('/get_therapists')
def get_therapists():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT TherapistID, Name FROM Therapists WHERE status = 'Available'")  # Assuming you want only available therapists
    therapists = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(therapists)

@app.route('/')
def index():
    return render_template('chat_with_therapist.html')

@app.route('/chatbot')
def chatbot():
    return render_template('dialogflow.html')

if __name__ == '__main__':
    app.run(debug=True)