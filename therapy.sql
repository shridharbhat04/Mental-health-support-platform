CREATE DATABASE therapy;

USE therapy;

CREATE TABLE Admins (
    admin_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    contact_info VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Patients (
    PatientID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    Age INT NOT NULL,
    ContactInfo VARCHAR(255) NOT NULL,
    Diagnosis TEXT,
    TherapyGoals TEXT
);

CREATE TABLE Therapists (
    TherapistID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(255) NOT NULL,
    Specialization VARCHAR(255) NOT NULL,
    ContactInfo VARCHAR(255) NOT NULL,
    Address VARCHAR(255) NOT NULL,
    IsVerified BOOLEAN DEFAULT FALSE,
    Amount DECIMAL(10, 2) DEFAULT 0,
    status VARCHAR(50) DEFAULT 'Available'
);

CREATE TABLE Appointments (
    AppointmentID INT AUTO_INCREMENT PRIMARY KEY,
    PatientID INT,
    TherapistID INT,
    Date DATE,
    Time TIME,
    feedback_given BOOLEAN DEFAULT FALSE,
    status VARCHAR(50) DEFAULT 'scheduled',
    can_leave_feedback BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (PatientID) REFERENCES Patients(PatientID),
    FOREIGN KEY (TherapistID) REFERENCES Therapists(TherapistID)
);

CREATE TABLE Feedback (
    FeedbackID INT AUTO_INCREMENT PRIMARY KEY,
    AppointmentID INT,
    Rating INT CHECK (Rating BETWEEN 1 AND 5),
    Comments TEXT,
    Date DATE,
    FOREIGN KEY (AppointmentID) REFERENCES Appointments(AppointmentID)
);

CREATE TABLE PaymentRecords (
    PaymentID INT AUTO_INCREMENT PRIMARY KEY,
    PatientID INT,
    AppointmentID INT,
    Amount DECIMAL(10, 2),
    PaymentDate DATE,
    PaymentMethod VARCHAR(50),
    FOREIGN KEY (PatientID) REFERENCES Patients(PatientID),
    FOREIGN KEY (AppointmentID) REFERENCES Appointments(AppointmentID)
);

CREATE TABLE users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    PaymentID INT NULL,
    TherapistID INT NULL,
    UserName VARCHAR(255) NOT NULL,
    Password VARCHAR(255) NOT NULL,
    role ENUM('patient', 'therapist') NOT NULL,
    FOREIGN KEY (PaymentID) REFERENCES patients(PatientID),
    FOREIGN KEY (therapist_id) REFERENCES therapists(TherapistID)
);

CREATE TABLE therapistnotes (
    NoteID INT AUTO_INCREMENT PRIMARY KEY,
    TherapistID INT,
    PaymentID INT,
    AppointmentID INT,
    NoteText TEXT,
    datecreated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (TherapistID) REFERENCES therapists(TherapistID),
    FOREIGN KEY (PaymentID) REFERENCES PaymentRecords(PaymentID)
);
