-- SecureDB Sample CollegeDB Database Schema & Seed Data
-- CSE Final Year Project Evaluation Dataset

DROP TABLE IF EXISTS enrollments CASCADE;
DROP TABLE IF EXISTS courses CASCADE;
DROP TABLE IF EXISTS faculty CASCADE;
DROP TABLE IF EXISTS students CASCADE;
DROP TABLE IF EXISTS audit_security_log CASCADE;

-- 1. Students Table
CREATE TABLE students (
    student_id SERIAL PRIMARY KEY,
    roll_number VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    department VARCHAR(50) NOT NULL,
    cgpa NUMERIC(3, 2) NOT NULL CHECK (cgpa >= 0.00 AND cgpa <= 10.00),
    admission_year INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Faculty Table
CREATE TABLE faculty (
    faculty_id SERIAL PRIMARY KEY,
    emp_code VARCHAR(20) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    designation VARCHAR(50) NOT NULL,
    department VARCHAR(50) NOT NULL,
    specialization VARCHAR(100) NOT NULL
);

-- 3. Courses Table
CREATE TABLE courses (
    course_code VARCHAR(10) PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    credits INT NOT NULL,
    faculty_id INT REFERENCES faculty(faculty_id)
);

-- 4. Enrollments Table
CREATE TABLE enrollments (
    enrollment_id SERIAL PRIMARY KEY,
    student_id INT REFERENCES students(student_id) ON DELETE CASCADE,
    course_code VARCHAR(10) REFERENCES courses(course_code),
    grade VARCHAR(2),
    semester INT NOT NULL
);

-- 5. Audit Security Log Table (Simulating target DB activity)
CREATE TABLE audit_security_log (
    log_id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    performed_by VARCHAR(50) NOT NULL,
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- --- SEED DATA ---
INSERT INTO faculty (emp_code, name, designation, department, specialization) VALUES
('FAC001', 'Dr. Arvind Swaminathan', 'Professor & HOD', 'Computer Science', 'Cryptography & Network Security'),
('FAC002', 'Dr. Meenakshi Sundaram', 'Associate Professor', 'Computer Science', 'Distributed Database Systems'),
('FAC003', 'Prof. Rajesh Kulkarni', 'Assistant Professor', 'Cyber Security', 'Cloud Security & Digital Forensics');

INSERT INTO courses (course_code, title, credits, faculty_id) VALUES
('CS401', 'Advanced Cryptography & Information Security', 4, 1),
('CS402', 'Distributed Database Architectures', 4, 2),
('CS403', 'Cloud Infrastructure & Incident Response', 3, 3);

INSERT INTO students (roll_number, full_name, email, department, cgpa, admission_year) VALUES
('2023CS101', 'Aditya Sharma', 'aditya.sharma@college.edu', 'Computer Science', 9.42, 2023),
('2023CS102', 'Priya Patel', 'priya.patel@college.edu', 'Computer Science', 9.15, 2023),
('2023CS103', 'Rahul Verma', 'rahul.verma@college.edu', 'Computer Science', 8.78, 2023),
('2023CY201', 'Sneha Deshmukh', 'sneha.d@college.edu', 'Cyber Security', 9.60, 2023),
('2023CY202', 'Vikramaditya Roy', 'vikram.roy@college.edu', 'Cyber Security', 8.92, 2023);

INSERT INTO enrollments (student_id, course_code, grade, semester) VALUES
(1, 'CS401', 'A+', 7),
(1, 'CS402', 'A', 7),
(2, 'CS401', 'A', 7),
(3, 'CS402', 'B+', 7),
(4, 'CS401', 'O', 7),
(4, 'CS403', 'A+', 7),
(5, 'CS403', 'A', 7);

INSERT INTO audit_security_log (event_type, performed_by) VALUES
('DATABASE_INITIALIZED', 'system_dba'),
('ACCESS_POLICY_APPLIED', 'security_officer'),
('STUDENT_ENROLLMENT_BATCH_COMMITTED', 'registrar');
