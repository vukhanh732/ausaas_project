# AUSAAS: Secure User Authentication and Authorization System

## Project Overview

The **AUSAAS (Secure User Authentication and Authorization System)** is a Flask-based web application designed to demonstrate and implement robust user authentication and Role-Based Access Control (RBAC). It serves as a reusable, secure login portal module for other Flask projects, integrating modern cybersecurity best practices from the ground up.

This project showcases secure password handling, session management, comprehensive input validation, flexible authorization, and includes a full suite of automated tests to verify its security and functionality.

## Features

### Authentication & Core Functionality
* **User Registration:** Allows new users to create accounts.
* **User Login/Logout:** Secure user authentication with session management.
* **Password Hashing & Salting:** Passwords are securely stored using the `bcrypt` adaptive hashing algorithm.
* **NIST-Aligned Password Policy:**
    * Enforces a minimum password length (e.g., 12 characters).
    * Checks against a list of commonly used/banned passwords.
    * Provides real-time, client-side visual feedback during password entry (length, complexity checks) for improved user experience.
* **"Show Password" Toggle:** Enhances usability and accessibility for password fields.
![image](https://github.com/user-attachments/assets/b8f9709c-cae0-4c42-8a07-669a8987530d)
![image](https://github.com/user-attachments/assets/3bc8da77-ea18-4920-9906-cdcf3d662227)
![image](https://github.com/user-attachments/assets/3850f702-7f58-4070-aa54-a9b836732e16)




### Authorization (Role-Based Access Control - RBAC)
* **Multi-Role Support:** Supports multiple predefined roles (e.g., `admin`, `user`, `developer`, `it`).
* **Granular Access Control:** Protects specific web routes/pages based on a user's assigned roles using custom Flask decorators (`@login_required`, `@roles_required`).
* **Admin Role Management:**
    * A dedicated administrative interface (`/auth/manage_users`) allows admin users to view all registered users.
    * Admins can assign and unassign roles to any user via a web form.
    * *(Note: There is a known, minor issue where updating to only a single role might require a slight retry/re-check - to be refined.)*
* **Role Management:**
    * A dedicated administrative interface (`/auth/roles_management`) allows admin users to add new roles to the system.
    * Admins can delete custom roles (core 'admin'/'user' roles are protected from deletion).

### Security & Best Practices
* **Defense in Depth:** Multiple layers of security controls (hashing, sessions, validation, RBAC).
* **CSRF Protection:** Integrated via Flask-WTF to prevent Cross-Site Request Forgery attacks.
* **Generic Error Messages:** Login failures provide generic messages to prevent username enumeration.
* **Custom Error Pages:** User-friendly and secure custom pages for 404 Not Found, 403 Forbidden, and 500 Internal Server errors.
* **Environment Variable for Secrets:** Uses `SECRET_KEY` from environment variables for secure secret management.

### Automated Testing
* **Comprehensive Test Suite:** Includes `test_auth_system.py` with automated integration tests covering:
    * Successful and failed user registration (including policy adherence).
    * Successful and failed user login.
    * Secure logout functionality.
    * Correct access control for protected routes (dashboard, admin panel) based on user roles and login status.
    * Verification of custom error pages.
    * Verification of admin role assignment functionality.

## Getting Started

### Prerequisites

* Python 3.8+
* Git

### Setup

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/vukhanh732/ausaas_project.git
    cd AUSAAS
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python3 -m venv venv
    # On macOS/Linux (WSL):
    source venv/bin/activate
    # On Windows (Command Prompt):
    .\venv\Scripts\activate.bat
    # On Windows (PowerShell):
    .\venv\Scripts\Activate.ps1
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Initialize the database and create an admin user:**
    This command will create all necessary database tables (`users`, `roles`, `user_roles`), populate default roles (`admin`, `user`, `developer`, `it`), and guide you through creating an initial administrator account.

    ```bash
    # Ensure FLASK_APP and SECRET_KEY are set in your terminal:
    export FLASK_APP=app.py
    export SECRET_KEY='YOUR_VERY_LONG_AND_RANDOM_SECRET_KEY' # REPLACE WITH A REAL RANDOM STRING!

    flask init-app-data
    ```
    *Follow the prompts:* Enter `admin` for username, choose a strong password (e.g., `adminpass`), and select roles (e.g., `1,3` for admin and developer roles).

### Running the Application

1.  **Ensure your virtual environment is active** (the `(venv)` prefix in your terminal).
2.  **Set environment variables** (if not already set in the current terminal session):
    ```bash
    export FLASK_APP=app.py
    export SECRET_KEY='YOUR_VERY_LONG_AND_RANDOM_SECRET_KEY' # IMPORTANT: Use the same key as init-app-data
    export FLASK_DEBUG=1 # Recommended for development (enables auto-reload and debugger)
    ```
3.  **Start the Flask development server:**
    ```bash
    flask run
    ```
    The application will typically run on `http://127.0.0.1:5000/`.

### Usage

Once the application is running:

* **Homepage:** `http://127.0.0.1:5000/`
* **Register:** `http://127.0.0.1:5000/auth/register` (Observe real-time password validation here!)
* **Login:** `http://127.0.0.1:5000/auth/login`
* **Dashboard (Logged-in users):** `http://127.0.0.1:5000/auth/dashboard`
* **Admin Panel (Admin role required):** `http://127.0.0.1:5000/auth/admin_panel`
* **Manage Users (Admin role required):** `http://127.0.0.1:5000/auth/manage_users`
* **Manage Roles (Admin role required):** `http://127.0.0.1:5000/auth/roles_management`

## Running Automated Tests

To verify the functionality and security of the system:

1.  **Ensure the Flask application is running** (`flask run` in a separate terminal).
2.  **Open a new terminal window.**
3.  **Activate your virtual environment** in this new terminal.
4.  **Run the test script:**
    ```bash
    python3 test_auth_system.py
    ```
    The output will show `[PASS]`, `[FAIL]`, or `[SKIP]` for each test case. Ideally, all tests should pass.

## Project Structure
