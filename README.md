# Flask Job Portal Project

## Description
A web application built using the Flask framework for Python. It allows job seekers to find and apply for jobs (including resume upload and application details), employers to post job listings and manage applications (including status updates and rejections), and administrators to oversee the platform (user management, job approvals). Developed as an intern project.

## Features
* **User Roles:** Job Seeker, Employer, Administrator.
* **Authentication:** User Registration, Login, Logout, Email Verification, Password Complexity Checks, Forgot/Reset Password.
* **Job Seekers:** Profile creation (basic via registration), Job search/viewing, Apply for jobs (with form for Current CTC, Expected CTC, Notice Period, Join Date, Resume Upload - PDF <5MB), View "My Applications" dashboard with status tracking.
* **Employers:** Company profile creation (basic via registration), Post new job listings, Manage own job listings (Edit - pending re-approval, Delete), View applications for their jobs, Download applicant resumes, Update application status (Viewed, Shortlisted, Interviewing, Offer Made, Hired, Offer Declined), Reject applications with reason.
* **Administrators:** Manage users (View, Edit verification, Delete), Manage all job listings (Approve, Unapprove, Delete).
* **Email Notifications:** For Admins (New Job Pending), Employers (Job Approved, New Application), Job Seekers (Verification, Reset Link, Application Confirmation, Rejection, Offer Made).
* **Resume Handling:** PDF uploads (<5MB), secure storage using unique filenames, download link restricted to relevant employers/admins.

## Technology Stack
* **Backend:** Python 3, Flask
* **Database:** SQLite
* **ORM:** Flask-SQLAlchemy
* **Frontend:** HTML5, CSS3, Bootstrap 5
* **Templating:** Jinja2
* **Forms:** Flask-WTF
* **Authentication:** Flask-Login
* **Email:** Flask-Mail
* **Migrations:** None (DB created via `db.create_all()`)
* **Other Libraries:** Werkzeug, itsdangerous, python-dotenv, email-validator, uuid

## Project Structure
job_portal/
├── app/                  # Main application package
│   ├── init.py       # App factory, extensions
│   ├── models.py         # Database models
│   ├── forms.py          # WTForms definitions
│   ├── views.py          # Routes and view logic
│   └── templates/        # Jinja2 HTML templates
│       ├── auth/
│       ├── jobs/
│       ├── employers/
│       ├── admin/
│       ├── email/        # Email templates
│       └── base.html     # Base layout template
├── instance/             # Instance data (NOT COMMITTED TO GIT)
│   ├── site.db           # SQLite database (created automatically)
│   └── uploads/          # Uploads folder (created automatically)
│       └── resumes/      # Uploaded resumes folder
├── static/               # Static files (CSS)
│   └── css/
│       └── style.css
├── venv/                 # Virtual environment (NOT COMMITTED TO GIT)
├── .env                  # Local environment variables (REQUIRED LOCALLY, NOT COMMITTED)
├── .gitignore            # Files/folders ignored by Git
├── requirements.txt      # Python dependencies
├── run.py                # App execution script
└── create_admin.py       # Admin user creation script

## Setup and Installation

Follow these steps to set up and run the project locally:

1.  **Prerequisites:**
    * Python 3.8 or newer ([Download Python](https://www.python.org/))
    * pip (Python package installer) installed.
    * Git installed ([Download Git](https://git-scm.com/)).

2.  **Clone the Repository:**
    * Open your terminal or command prompt.
    * Navigate to the directory where you want to store the project.
    * Run:
        ```bash
        git clone [https://github.com/RKghub2025/Job_Portal.git](https://github.com/RKghub2025/Job_Portal.git)
        cd Job_Portal
        ```

3.  **Create and Activate Virtual Environment:**
    * Using a virtual environment is strongly recommended to manage dependencies.
    * From the project root (`Job_Portal/`), run:
        ```bash
        # Create the virtual environment folder named 'venv'
        python -m venv venv

        # Activate the virtual environment:
        # On Windows (Command Prompt):
        venv\Scripts\activate
        # On Windows (PowerShell - you might need to adjust execution policy):
        # .\venv\Scripts\Activate.ps1
        # On macOS / Linux (bash/zsh):
        source venv/bin/activate
        ```
    * Your terminal prompt should now start with `(venv)`.

4.  **Install Dependencies:**
    * Make sure your virtual environment is active.
    * Run:
        ```bash
        pip install -r requirements.txt
        ```

5.  **Configure Environment Variables:**
    * Create a file named `.env` in the project root directory (`Job_Portal/.env`).
    * **Important:** This file stores sensitive configuration and is **not** tracked by Git (it's listed in `.gitignore`). You **must** create this file locally.
    * Copy the following structure into your `.env` file and replace the placeholder values with your actual secrets or test credentials:

        ```dotenv
        # --- .env file content ---

        # Flask Secret Key - REQUIRED: Generate a long, random, secret string!
        # Example generation (run in python terminal): import secrets; secrets.token_hex(24)
        SECRET_KEY='PASTE_YOUR_GENERATED_SECRET_KEY_HERE'

        # Salt for generating secure tokens (e.g., password reset, email verify) - REQUIRED
        # Example generation: import secrets; secrets.token_hex(16)
        SECURITY_PASSWORD_SALT='PASTE_YOUR_GENERATED_SECURITY_SALT_HERE'

        # Email Configuration (Replace with REAL values for emails to work)
        MAIL_SERVER='smtp.example.com'   # e.g., smtp.gmail.com for Gmail
        MAIL_PORT=587                    # e.g., 587 (for TLS) or 465 (for SSL)
        MAIL_USE_TLS=True                # Usually True if port is 587
        MAIL_USE_SSL=False               # Usually False if using TLS
        MAIL_USERNAME='your_email@example.com' # Your full email address
        MAIL_PASSWORD='your_email_or_app_password' # **Use an App Password for Gmail if 2FA is enabled**
        MAIL_DEFAULT_SENDER='Job Portal App <your_email@example.com>' # How the 'From' field appears
        ```

6.  **Database Setup:**
    * The application uses SQLite.
    * The database file (`instance/site.db`) and the necessary folders (`instance/`, `instance/uploads/resumes/`) will be **created automatically** by the application the first time it runs if they don't already exist. No manual commands are needed to create the database structure.

7.  **Create Initial Admin User:**
    * Make sure your virtual environment is still active (`(venv)` should be visible).
    * Run the following script from the project root directory:
        ```bash
        python create_admin.py
        ```
    * Follow the prompts in the terminal to enter a username, email address, and password for the administrator account.

8.  **Run the Application:**
    * Make sure your virtual environment is still active.
    * Run the main application script:
        ```bash
        python run.py
        ```

9.  **Access the Application:**
    * Open your web browser.
    * Navigate to `http://127.0.0.1:5000` (or the URL provided in the terminal, usually this one for local development).

## Usage
* Navigate to the application URL in your browser.
* Use the "Register" link to create accounts (select Role: Job Seeker or Employer).
* Verify your email address by clicking the link sent upon registration.
* Log in using appropriate credentials.
* **Job Seekers:** Use "Find Jobs", click on a job title for details, click "Apply Now", fill the application form (CTC, Notice Period, Join Date, Resume PDF) and submit. Use "My Applications" in the user dropdown to track application status.
* **Employers:** Use "Post New Job", view their current postings on the "Employer Dashboard", click "View" applications for a specific job, download resumes using the button, use action buttons (Mark Viewed, Shortlist, Interviewing, Make Offer, Reject via modal, Mark Hired, Mark Offer Declined) to manage candidates.
* **Admin:** Log in using the account created via `create_admin.py`. Use the "Admin Dashboard", navigate to "Manage Jobs" to Approve/Unapprove/Delete postings, navigate to "Manage Users" to View/Edit Verification Status/Delete users.

## Author
* Kowshi
