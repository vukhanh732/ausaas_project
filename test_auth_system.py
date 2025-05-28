import requests
import json
import time
from bs4 import BeautifulSoup # Ensure BeautifulSoup is imported

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000"

# Test Users (ensure these are either new or match what you've set up via flask init-app-data)
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "adminpass" # IMPORTANT: CHANGE THIS TO YOUR ACTUAL ADMIN PASSWORD YOU USED IN 'flask init-app-data'

REGULAR_USERNAME = "testuser"
REGULAR_PASSWORD = "testpassword123" # IMPORTANT: This is the password the test script will use to register/login testuser

INVALID_USERNAME = "nonexistent"
INVALID_PASSWORD = "wrongpassword"

# --- Helper Function for Test Reporting ---
def print_test_result(test_name, status, message=""):
    color = "\033[92m" if status == "PASS" else "\033[91m"
    reset_color = "\033[0m"
    print(f"{color}[{status}]{reset_color} {test_name}: {message}")

# --- Helper: Extract Flash Messages ---
def get_flash_messages(html_content, category=None):
    """Parses HTML content and extracts flash messages."""
    soup = BeautifulSoup(html_content, 'html.parser')
    messages = []
    flashes_ul = soup.find('ul', class_='flashes')
    if flashes_ul:
        for li in flashes_ul.find_all('li'):
            if category is None or category in li.get('class', []):
                messages.append(li.get_text(strip=True))
    return messages

# --- Test Functions ---

def test_registration(session):
    print("\n--- Running Registration Tests ---")

    # Test Case 1: Successful Registration
    test_name = "Test Case 1: Successful Registration"
    reg_data = {"username": REGULAR_USERNAME, "password": REGULAR_PASSWORD, "confirm_password": REGULAR_PASSWORD, "csrf_token": ""}
    
    # Get registration form to extract CSRF token
    response_get_form = session.get(f"{BASE_URL}/auth/register")
    if response_get_form.status_code != 200:
        print_test_result(test_name, "FAIL", f"Could not get registration form: {response_get_form.status_code}")
        return False

    soup = BeautifulSoup(response_get_form.text, 'html.parser')
    csrf_token_field = soup.find('input', {'name': 'csrf_token'})
    if csrf_token_field:
        reg_data["csrf_token"] = csrf_token_field['value']
    else:
        print_test_result(test_name, "FAIL", "CSRF token not found on registration form.")
        return False

    # Perform POST registration, allow_redirects=False to check the 302 redirect directly
    response_post_reg = session.post(f"{BASE_URL}/auth/register", data=reg_data, allow_redirects=False)

    if response_post_reg.status_code == 302 and "/auth/login" in response_post_reg.headers.get("Location", ""):
        # Now, follow the redirect to confirm content of the final page
        final_response = session.get(response_post_reg.headers["Location"])
        flash_messages = get_flash_messages(final_response.text, 'success')
        if final_response.status_code == 200 and "Registration successful!" in "".join(flash_messages) and "Login" in final_response.text:
            print_test_result(test_name, "PASS", "New user registered successfully and redirected to login.")
            return True
        else:
             print_test_result(test_name, "FAIL", f"Redirected but unexpected final content/flash: {final_response.status_code}, {final_response.text}")
             return False
    elif response_post_reg.status_code == 200 and "That username is taken" in response_post_reg.text:
        print_test_result(test_name, "SKIP", "User already registered, skipping successful registration test.")
        return True # Treat as success for test flow if user already exists
    else:
        print_test_result(test_name, "FAIL", f"Failed registration unexpectedly: {response_post_reg.status_code}, {response_post_reg.text}")
        return False
        
    
def test_duplicate_registration(session):
    print("\n--- Running Duplicate Registration Test ---")
    test_name = "Test Case 2: Duplicate Username Registration"
    reg_data = {"username": REGULAR_USERNAME, "password": REGULAR_PASSWORD, "confirm_password": REGULAR_PASSWORD, "csrf_token": ""}

    response_get_form = session.get(f"{BASE_URL}/auth/register") # Get new CSRF token
    if response_get_form.status_code != 200:
        print_test_result(test_name, "FAIL", f"Could not get registration form: {response_get_form.status_code}")
        return False

    soup = BeautifulSoup(response_get_form.text, 'html.parser')
    csrf_token_field = soup.find('input', {'name': 'csrf_token'})
    if csrf_token_field:
        reg_data["csrf_token"] = csrf_token_field['value']
    else:
        print_test_result(test_name, "FAIL", "CSRF token not found for duplicate test.")
        return False

    response = session.post(f"{BASE_URL}/auth/register", data=reg_data)
    if response.status_code == 200 and "That username is taken" in response.text:
        print_test_result(test_name, "PASS", "Duplicate username correctly rejected.")
        return True
    else:
        print_test_result(test_name, "FAIL", f"Duplicate username not rejected: {response.status_code}, {response.text}")
        return False

def test_password_mismatch(session):
    print("\n--- Running Passwords Mismatch Test ---")
    test_name = "Test Case 3: Passwords Mismatch"
    mismatch_data = {"username": "mismatchuser", "password": "pass1", "confirm_password": "pass2", "csrf_token": ""}
    
    response_get_form = session.get(f"{BASE_URL}/auth/register") # Get new CSRF token
    if response_get_form.status_code != 200:
        print_test_result(test_name, "FAIL", f"Could not get registration form: {response_get_form.status_code}")
        return False

    soup = BeautifulSoup(response_get_form.text, 'html.parser')
    csrf_token_field = soup.find('input', {'name': 'csrf_token'})
    if csrf_token_field:
        mismatch_data["csrf_token"] = csrf_token_field['value']
    else:
        print_test_result(test_name, "FAIL", "CSRF token not found for mismatch test.")
        return False

    response = session.post(f"{BASE_URL}/auth/register", data=mismatch_data)
    if response.status_code == 200 and "Passwords must match" in response.text:
        print_test_result(test_name, "PASS", "Password mismatch correctly rejected.")
        return True
    else:
        print_test_result(test_name, "FAIL", f"Password mismatch not rejected: {response.status_code}, {response.text}")
        return False


def test_login(session, username, password, expected_outcome="success"):
    print(f"\n--- Running Login Test for {username} (Expected: {expected_outcome}) ---")
    login_data = {"username": username, "password": password, "csrf_token": "", "remember_me": "y"}
    
    # Get login form to extract CSRF token
    response_get_form = session.get(f"{BASE_URL}/auth/login")
    if response_get_form.status_code != 200:
        print_test_result(f"Login setup for {username}", "FAIL", f"Could not get login form: {response_get_form.status_code}")
        return False
    
    soup = BeautifulSoup(response_get_form.text, 'html.parser')
    csrf_token_field = soup.find('input', {'name': 'csrf_token'})
    if csrf_token_field:
        login_data["csrf_token"] = csrf_token_field['value']
    else:
        print_test_result(f"Login setup for {username}", "FAIL", "CSRF token not found on login form.")
        return False

    # Perform POST login. Allow redirects (default behavior).
    # The final response should be the home page.
    response_post_login = session.post(f"{BASE_URL}/auth/login", data=login_data)
    
    if expected_outcome == "success":
        # Check if final redirect leads to home page (status 200) and contains expected content
        if response_post_login.status_code == 200 and response_post_login.url == f"{BASE_URL}/":
            flash_messages = get_flash_messages(response_post_login.text, 'success')
            if f"Hello, {username}!" in response_post_login.text and "You have been logged in successfully!" in "".join(flash_messages):
                print_test_result(f"Login as {username}", "PASS", "Logged in successfully and redirected to home.")
                return True
            else:
                print_test_result(f"Login as {username}", "FAIL", f"Redirected to home but unexpected content/flash: {response_post_login.status_code}, {response_post_login.text}")
                return False
        else:
            print_test_result(f"Login as {username}", "FAIL", f"Login failed unexpectedly (not redirected to home): {response_post_login.status_code}, {response_post_login.text}")
            return False
    else: # Expected to fail (expected_outcome == "fail")
        # For failed login, Flask renders the login page again with a flash message (status 200)
        flash_messages = get_flash_messages(response_post_login.text, 'danger')
        if response_post_login.status_code == 200 and "Invalid username or password" in "".join(flash_messages):
            print_test_result(f"Login as {username}", "PASS", "Login failed as expected (invalid credentials).")
            return False # Return False because login technically failed
        else:
            print_test_result(f"Login as {username}", "FAIL", f"Login succeeded unexpectedly or failed differently: {response_post_login.status_code}, {response_post_login.text}")
            return False


def test_access_protected_pages(session):
    print("\n--- Running Protected Page Access Tests ---")

    # Test Case 1: Access Dashboard (login_required) when not logged in
    test_name = "Test Case 1: Access Dashboard (logged out)"
    # Ensure fully logged out before this test
    test_logout_func(session) # Clears cookies
    response = session.get(f"{BASE_URL}/auth/dashboard") # Allow redirects (default)
    
    # Expected: redirected to login page (status 200 from login page)
    if response.status_code == 200 and "/auth/login" in response.url:
        flash_messages = get_flash_messages(response.text, 'danger')
        if "Please log in to access this page." in "".join(flash_messages):
            print_test_result(test_name, "PASS", "Redirected to login as expected (logged out).")
        else:
            print_test_result(test_name, "FAIL", f"Redirected but missing flash message: {response.text}")
    else:
        print_test_result(test_name, "FAIL", f"Unexpected access to Dashboard when logged out: {response.status_code}, {response.text}")

    # Test Case 2: Access Admin Panel (roles_required) when not logged in
    test_name = "Test Case 2: Access Admin Panel (logged out)"
    # Ensure fully logged out before this test
    test_logout_func(session) # Clears cookies
    response = session.get(f"{BASE_URL}/auth/admin_panel") # Allow redirects (default)
    
    # Expected: redirected to login page (status 200 from login page)
    if response.status_code == 200 and "/auth/login" in response.url:
        flash_messages = get_flash_messages(response.text, 'danger')
        if "Please log in to access this page." in "".join(flash_messages):
            print_test_result(test_name, "PASS", "Redirected to login as expected (logged out).")
        else:
            print_test_result(test_name, "FAIL", f"Redirected but missing flash message: {response.text}")
    else:
        print_test_result(test_name, "FAIL", f"Unexpected access to Admin Panel when logged out: {response.status_code}, {response.text}")

    # Test Case 3: Access Dashboard (login_required) as REGULAR USER
    test_name = "Test Case 3: Access Dashboard (regular user)"
    # Ensure regular user is logged in for this test
    if test_login(session, REGULAR_USERNAME, REGULAR_PASSWORD, expected_outcome="success"):
        response = session.get(f"{BASE_URL}/auth/dashboard")
        if response.status_code == 200 and "Welcome to your dashboard" in response.text:
            print_test_result(test_name, "PASS", "Dashboard accessible by regular user.")
        else:
            print_test_result(test_name, "FAIL", f"Dashboard inaccessible by regular user: {response.status_code}, {response.text}")
    else:
        print_test_result(test_name, "SKIP", "Could not log in as regular user, skipping dashboard test.")

    # Test Case 4: Access Admin Panel (roles_required) as REGULAR USER
    test_name = "Test Case 4: Access Admin Panel (regular user)"
    # Ensure regular user is logged in before this test
    if test_login(session, REGULAR_USERNAME, REGULAR_PASSWORD, expected_outcome="success"): # Re-login if previous test logged out
        response = session.get(f"{BASE_URL}/auth/admin_panel") # Allow redirects
        # Expected: redirected to home page (status 200 from home page)
        if response.status_code == 200 and response.url == f"{BASE_URL}/":
            flash_messages = get_flash_messages(response.text, 'danger')
            if "You do not have permission to access this page." in "".join(flash_messages):
                print_test_result(test_name, "PASS", "Redirected to home as expected (no admin role).")
            else:
                print_test_result(test_name, "FAIL", f"Redirected but missing flash message: {response.text}")
        else:
            print_test_result(test_name, "FAIL", f"Unexpected access to Admin Panel for regular user: {response.status_code}, {response.text}")
    else:
        print_test_result(test_name, "SKIP", "Could not log in as regular user, skipping admin panel test.")
    
    # Test Case 5: Access Admin Panel (roles_required) as ADMIN USER
    test_name = "Test Case 5: Access Admin Panel (admin user)"
    test_logout_func(session) # Log out previous user first
    if test_login(session, ADMIN_USERNAME, ADMIN_PASSWORD, expected_outcome="success"):
        response = session.get(f"{BASE_URL}/auth/admin_panel")
        if response.status_code == 200 and "Welcome, Administrator" in response.text:
            print_test_result(test_name, "PASS", "Admin Panel accessible by admin user.")
        else:
            print_test_result(test_name, "FAIL", f"Admin Panel inaccessible by admin user: {response.status_code}, {response.text}")
    else:
        print_test_result(test_name, "SKIP", "Could not log in as admin user, skipping admin panel test.")

def test_logout_func(session):
    print("\n--- Running Logout Test ---")
    test_name = "Test Case: Successful Logout"
    # Ensure cookies are cleared to simulate a fresh state for logout check
    session.cookies.clear() 
    # Log in first to ensure there's a session to log out from for this test
    if not test_login(session, REGULAR_USERNAME, REGULAR_PASSWORD, expected_outcome="success"):
        print_test_result(test_name, "SKIP", "Could not log in to perform logout test.")
        return False

    response = session.get(f"{BASE_URL}/auth/logout") # Allow redirects (default)
    
    # Expected: redirected to home and shows logout flash message
    if response.status_code == 200 and response.url == f"{BASE_URL}/":
        flash_messages = get_flash_messages(response.text, 'info') # Logout message is 'info' category
        if "You have been logged out." in "".join(flash_messages):
            print_test_result(test_name, "PASS", "Logged out successfully.")
            return True
        else:
            print_test_result(test_name, "FAIL", f"Redirected but missing flash message: {response.text}")
            return False
    else:
        print_test_result(test_name, "FAIL", f"Logout failed unexpectedly: {response.status_code}, {response.text}")
        return False

def test_error_pages(session):
    print("\n--- Running Error Page Tests ---")

    # Test Case 1: 404 Not Found
    test_name = "Test Case 1: 404 Not Found Page"
    response = session.get(f"{BASE_URL}/non_existent_page_123abc")
    
    # Check if the text contains expected elements robustly
    response_text_lower = response.text.lower()
    expected_title_part = "error - 404"
    expected_h1_part = "error 404"
    expected_p_part = "the page you requested could not be found." # Exact phrase

    if (response.status_code == 404 and
        expected_title_part in response_text_lower and
        expected_h1_part in response_text_lower and
        expected_p_part in response_text_lower):
        print_test_result(test_name, "PASS", "404 page displayed correctly.")
    else:
        print_test_result(test_name, "FAIL", 
                          f"404 page not displayed as expected. "
                          f"Status: {response.status_code}. "
                          f"Expected title: '{expected_title_part}', found: '{expected_title_part in response_text_lower}'. "
                          f"Expected h1: '{expected_h1_part}', found: '{expected_h1_part in response_text_lower}'. "
                          f"Expected p: '{expected_p_part}', found: '{expected_p_part in response_text_lower}'. "
                          f"Response Text (first 200 chars): {response.text[:200]}") # Show part of response for debug

    # Test Case 2: 403 Forbidden (Conceptual, as decorators redirect)
    # To test a direct 403, you'd need a route that explicitly calls abort(403)
    # and doesn't redirect. Our current decorator redirects to home on 403.
    print_test_result("Test Case 2: 403 Forbidden Page (Conceptual)", "INFO", "Skipped as current decorators redirect on 403, not directly render 403.")

def test_access_protected_pages_admin_only(session):
    print("\n--- Running Admin-Only Protected Page Access Tests ---")

    # Test Case 1: Access Admin Panel (roles_required) as ADMIN USER
    test_name = "Test Case 1: Access Admin Panel (admin user)"
    # Assumes admin user is already logged in by the calling test sequence
    response = session.get(f"{BASE_URL}/auth/admin_panel")
    if response.status_code == 200 and "Welcome, Administrator" in response.text:
        print_test_result(test_name, "PASS", "Admin Panel accessible by admin user.")
    else:
        print_test_result(test_name, "FAIL", f"Admin Panel inaccessible by admin user: {response.status_code}, {response.text}")

# --- Main Test Execution ---
if __name__ == "__main__":
    # Ensure BeautifulSoup4 is installed (auto-install if not)
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("BeautifulSoup4 not found. Installing now...")
        try:
            import subprocess
            subprocess.check_call(['pip', 'install', 'beautifulsoup4'])
            from bs4 import BeautifulSoup
            print("BeautifulSoup4 installed successfully.")
        except Exception as e:
            print(f"Failed to install BeautifulSoup4: {e}. Please install it manually (`pip install beautifulsoup4`) and retry.")
            exit(1)

    print("--- Starting AUSAAS Automated Tests ---")

    # Use a requests.Session to maintain cookies across tests
    with requests.Session() as s:
        # Step 1: Ensure database and admin user are setup
        # It's assumed 'flask init-app-data' has been run successfully once.
        # If running tests repeatedly, you might need to reset database for clean state.
        # Example: Call flask init-app-data before running this script for fresh test.

        # Ensure we start with a clean session state for the test runner
        s.cookies.clear() # Clear cookies at the very beginning of the test run

        # Step 2: Test Registration Flow
        # For simplicity, we assume testuser might already exist and skip if so.
        registration_successful = test_registration(s)
        test_duplicate_registration(s)
        test_password_mismatch(s)
        
        # Ensure we are logged out before next sequence of login tests
        # We need a user to be logged in to test logout.
        # This will be handled inside test_logout_func itself.
        # For the very first logout test at the beginning of login tests, we ensure clear state.
        test_logout_func(s) 

        # Step 3: Test Login Flow (Regular User)
        login_success_regular = test_login(s, REGULAR_USERNAME, REGULAR_PASSWORD, expected_outcome="success")
        
        # Step 4: Test Login Flow (Invalid Credentials)
        test_login(s, INVALID_USERNAME, INVALID_PASSWORD, expected_outcome="fail")
        
        # Step 5: Test Protected Page Access (as various users/states)
        # These tests will handle their own login/logout as needed
        test_access_protected_pages(s)

        # Step 6: Test Logout (after all other tests that might leave user logged in)
        test_logout_func(s)

        # Step 7: Test Admin User Login and Access (this sequence handles its own login/logout)
        test_logout_func(s) # Ensure logged out before admin login attempt
        login_success_admin = test_login(s, ADMIN_USERNAME, ADMIN_PASSWORD, expected_outcome="success")
        if login_success_admin:
            # Re-run admin access test if admin login was successful
            test_access_protected_pages_admin_only(s) # NEW: dedicated admin access test
        else:
            print_test_result("Test Case 5: Access Admin Panel (admin user)", "SKIP", "Could not log in as admin user, skipping admin access test.")


        # Step 8: Final Logout after Admin tests
        test_logout_func(s)

        # Step 9: Test Error Pages
        test_error_pages(s)

    print("\n--- AUSAAS Automated Tests Complete ---")