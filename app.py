import os
import requests
import subprocess
import json
import logging
import re
import yaml
from datetime import datetime, timezone
from flask import Flask, request, render_template, redirect, url_for

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define paths relative to the application root
APP_ROOT = os.path.dirname(os.path.abspath(__file__))
RUNNER_REGISTRY_FILE = os.path.join(APP_ROOT, "runner_registry.yaml")
INVENTORY_FILE = os.path.join(APP_ROOT, "ansible", "inventory.ini")
LOG_FILE = os.path.join(APP_ROOT, "ansible-registration.log")
RUNNER_REGISTRATION_PLAYBOOK = os.path.join(APP_ROOT, "ansible", "register-runner.yml")

# Define the path for the dynamic inventory group
DYNAMIC_INVENTORY_GROUP = "dynamic_boards"

# --- Utility Functions (Adapted from your Odoo Python file) ---

def check_gitlab_server(url):
    """
    Checks if a given URL is a valid and reachable GitLab instance.
    This version is more robust against Cloudflare and similar protections.
    """
    # Normalize URL (remove trailing slash)
    url = url.rstrip("/")
    # Validate basic URL structure
    URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
    if not URL_REGEX.match(url):
        logger.info(f"'{url}' does not appear to be a valid URL format.")
        return False
    logger.info(f"\n--- Checking URL: {url} ---")
    try:
        # --- Method 1: Check for 'X-Gitlab-Instance' header ---
        # This header is often present on GitLab-served pages and is a strong indicator.
        # We'll make a HEAD request to be efficient, or a GET if HEAD is insufficient.
        try:
            head_resp = requests.head(url, timeout=5, allow_redirects=True)
            if 'X-Gitlab-Instance' in head_resp.headers:
                logger.info(f"'{url}' is a GitLab URL (X-Gitlab-Instance header confirmed).")
                return True
        except requests.exceptions.RequestException:
            pass # Continue to GET request if HEAD fails
        # Try a GET request to the base URL to catch the header and potentially content
        try:
            base_resp = requests.get(url, timeout=5, allow_redirects=True)
            if 'X-Gitlab-Instance' in base_resp.headers:
                logger.info(f"'{url}' is a GitLab URL (Homepage content 'GitLab' confirmed).")
                return True
        except requests.exceptions.RequestException:
            pass # Continue to API checks if base URL GET fails
        # --- Method 2: Check GitLab API endpoint /api/v4/version ---
        # Even if it returns 403, we'll check the content and headers for clues.
        api_version_url = f"{url}/api/v4/version"
        logger.info(f"Attempting to reach GitLab API at: {api_version_url}")
        api_resp = requests.get(api_version_url, timeout=5)
        if api_resp.status_code == 200:
            if 'application/json' in api_resp.headers.get('Content-Type', ''):
                try:
                    data = api_resp.json()
                    if 'version' in data and 'revision' in data:
                        logger.info(f"'{url}' is a GitLab URL (API /version confirmed, version: {data['version']}).")
                        return True
                except requests.exceptions.JSONDecodeError:
                    pass # Not valid JSON, continue to next check
        # Even if 403 or other status, check headers/content if it's GitLab's response
        if 'X-Gitlab-Instance' in api_resp.headers:
            logger.info(f"'{url}' is a GitLab URL (API /version header confirmed, even with status {api_resp.status_code}).")
            return True
        if "GitLab" in api_resp.text: # Could be a GitLab error page
            logger.info(f"'{url}' is a GitLab URL (API /version content 'GitLab' confirmed, even with status {api_resp.status_code}).")
            return True
        # --- Method 3: Check /-/health endpoint (often accessible) ---
        health_url = f"{url}/-/health"
        logger.info(f"Attempting to reach GitLab health endpoint at: {health_url}")
        health_resp = requests.get(health_url, timeout=5)
        if health_resp.status_code == 200:
            if 'application/json' in health_resp.headers.get('Content-Type', ''):
                try:
                    data = health_resp.json()
                    if 'status' in data and data['status'] == 'ok':
                        logger.info(f"'{url}' is a GitLab URL (/-/health endpoint confirmed).")
                        return True
                except requests.exceptions.JSONDecodeError:
                    pass
        if 'X-Gitlab-Instance' in health_resp.headers:
            logger.info(f"'{url}' is a GitLab URL (/-/health header confirmed, even with status {health_resp.status_code}).")
            return True
        if "GitLab" in health_resp.text:
            logger.info(f"'{url}' is a GitLab URL (/-/health content 'GitLab' confirmed, even with status {health_resp.status_code}).")
            return True
        # --- Method 4: Check for login page and specific headers/content (less reliable with Cloudflare) ---
        # This is the least reliable due to Cloudflare, but kept as a very last resort.
        login_page_url = f"{url}/users/sign_in"
        logger.info(f"All API checks failed/undetermined. Falling back to login page check at: {login_page_url}")
        login_resp = requests.get(login_page_url, timeout=5, allow_redirects=True)
        # Check for cookies, headers or specific text on the page
        if "_gitlab_session" in login_resp.headers.get("Set-Cookie", ""):
            logger.info(f"'{url}' is a GitLab URL (login page cookie confirmed).")
            return True
        if "GitLab" in login_resp.text:
            # Be careful with this, as "GitLab" could be in a Cloudflare challenge page too.
            # But combined with other checks, it adds value.
            logger.info(f"'{url}' is a GitLab URL (login page content 'GitLab' confirmed).")
            return True
        logger.info(f"'{url}' is not a GitLab URL (no conclusive evidence found after all checks).")
        return False
    except requests.exceptions.RequestException as e:
        logger.info(f"Could not reach '{url}' or an error occurred: {e}")
        return False
    except Exception as e: # Catch any other unexpected errors
        logger.info(f"An unexpected error occurred while checking '{url}': {e}")
        return False


def is_online(target_node):
    """
    Runs an Ansible playbook to check if a target node is alive.
    Returns True if alive, False otherwise.
    """
    logger.info(f"--- Checking if {target_node} is online via Ansible...")
    
    try:
        # We limit the check to the specific target_node
        result = subprocess.run(
            [
                "ansible",
                "-i", INVENTORY_FILE,
                "-m", "ping",
                target_node
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True # Decode stdout/stderr automatically
        )

        output = result.stdout
        logger.info(f"--- Ansible Output for {target_node}:\n{output[:500]}...") # logger.info snippet

        # Check for 'ok=1' and 'failed=0' and 'unreachable=0' for better accuracy
        if f"SUCCESS" in output and "ping" in output and "pong" in output:
            logger.info(f"--- ✅ {target_node} is online.")
            return True
        else:
            logger.info(f"--- ❌ {target_node} is not responding or check failed.")
            return False
    except FileNotFoundError:
        logger.info("Error: 'ansible' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.info(f"Error running Ansible playbook for {target_node}: {e}")
        return False


def get_healthy_targets(registry, runner_type):
    """
    Gets a list of healthy nodes for a specific type,
    sorted by the number of runners (least first).
    """
    # Use .get("nodes", {}) to safely access the "nodes" key.
    # If "nodes" is missing or None, it defaults to an empty dictionary,
    # preventing the AttributeError.
    healthy_nodes = {
        name: data for name, data in registry.get("nodes", {}).items()
        if data.get("health") == "good" and data.get("type") == runner_type
    }

    if not healthy_nodes:
        return [] # Return an empty list if no healthy nodes

    # Sort by the number of runners (length of the 'runners' list)
    sorted_nodes = sorted(
        healthy_nodes.items(),
        key=lambda x: len(x[1].get("runners", [])) # Use .get for safety
    )

    # Return just the names in sorted order
    return [name for name, data in sorted_nodes]  
        
        
def find_and_select_online_target(registry, runner_type):
    """
    Finds the first healthy and online target for the given type.
    """
    logger.info(f"Searching for an online '{runner_type}' target...")
    potential_targets = get_healthy_targets(registry, runner_type)

    if not potential_targets:
        logger.info(f"No healthy nodes found for type '{runner_type}'.")
        return None

    logger.info(f"Found {len(potential_targets)} healthy candidates, checking online status...")

    for target in potential_targets:
        if is_online(target):
            logger.info(f"🎉 Selected target: {target}")
            return target # Found one, return its name

    logger.info(f"❌ No healthy *and* online nodes found for type '{runner_type}'.")
    return None # Didn't find any online target


def load_registry(registry_path):
    """
    This function loads the runners_registry.yaml YAML file.
    If any such file does not exist, it creates the file
    with a default structure. If the file exists but is empty or malformed,
    it also initializes it with the default structure.
    """
    default_registry_structure = {
        "nodes": {
            "visionfive2": {"health": "good", "type": "visionfive2", "runner_count": 0, "runners": []},
            "qemu": {"health": "good", "type": "qemu", "runner_count": 0, "runners": []},
            "banana-pi-f3": {"health": "good", "type": "banana-pi-f3", "runner_count": 0, "runners": []}
        }
    }

    if not os.path.exists(registry_path):
        logger.info(f"Registry file not found at {registry_path}. Creating with default structure.")
        with open(registry_path, "w") as f:
            yaml.dump(default_registry_structure, f, default_flow_style=False)
        return default_registry_structure
    else:
        try:
            with open(registry_path, "r") as f:
                registry = yaml.safe_load(f)
                
                # If the file is empty or contains invalid YAML resulting in None
                if registry is None:
                    logger.warning(f"Registry file at {registry_path} is empty or invalid. Initializing with default structure.")
                    registry = default_registry_structure
                    # Overwrite the empty/invalid file with the default structure
                    with open(registry_path, "w") as wf:
                        yaml.dump(registry, wf, default_flow_style=False)
                
                # Ensure 'nodes' key exists and is a dictionary
                if "nodes" not in registry or not isinstance(registry["nodes"], dict):
                    logger.warning(f"Registry file at {registry_path} has missing or malformed 'nodes' section. Reinitializing with default structure.")
                    registry = default_registry_structure
                    with open(registry_path, "w") as wf:
                        yaml.dump(registry, wf, default_flow_style=False)
                else:
                    # Ensure all default nodes are present and have correct structure
                    for node_name, node_data in default_registry_structure["nodes"].items():
                        if node_name not in registry["nodes"]:
                            registry["nodes"][node_name] = node_data
                        else:
                            # Ensure 'runner_count' and 'runners' exist for existing nodes
                            if "runner_count" not in registry["nodes"][node_name]:
                                registry["nodes"][node_name]["runner_count"] = 0
                            if "runners" not in registry["nodes"][node_name] or not isinstance(registry["nodes"][node_name]["runners"], list):
                                registry["nodes"][node_name]["runners"] = []

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML from {registry_path}: {e}. Initializing with default structure.")
            registry = default_registry_structure
            # Overwrite the malformed file with the default structure
            with open(registry_path, "w") as wf:
                yaml.dump(registry, wf, default_flow_style=False)
        
        return registry


def register_runner_attempt(target, gitlab_server_url, runner_reg_token, log_file, inventory_file, runner_name, runner_registeration_playbook):
    """
    This function runs the ansible script and tries to register the gitlab runner on the requested machine. 
    It returns True if the return code was zero (success) and False otherwise.
    """
    cmd = [
        "ansible-playbook", runner_registeration_playbook,
        "-i", inventory_file,
        "-e", f"target_node={target}",
        "-e", f"registration_token={runner_reg_token}",
        "-e", f"gitlab_url={gitlab_server_url}",
        "-e", f"runner_name={runner_name}"
    ]
    
    logger.info(f"Executing Ansible command: {' '.join(cmd)}")
    
    try:
        with open(log_file, "a") as f:
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
        
        logger.info(f"The return code of the register_runner_attempt_function is {process.returncode}")
        
        # Ansible playbooks usually return 0 on success.
        return process.returncode == 0
    except FileNotFoundError:
        logger.error("Error: 'ansible-playbook' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.error(f"Error running Ansible playbook: {e}")
        return False


def save_registry(registry, runner_registry_file_path):
    """
    This function saves the newer registry data passed as argument to the registry yaml file
    """
    with open(runner_registry_file_path, "w") as f:
        yaml.dump(registry, f, default_flow_style=False)

def check_latest_failed_attempt(log_file):
    """
    Analyzes the ansible log file for specific failure messages.
    Returns:
        0: No specific failure pattern found or success.
        1: Invalid GitLab Registration Token (specific error message).
        2: Invalid GitLab Registration Token or GitLab server URL (status 422).
        3: GitLab Runner binary not found on the target machine.
    """
    if not os.path.exists(log_file):
        logger.info(f"Log file not found: {log_file}")
        return 0

    with open(log_file, 'r') as f:
        lines = f.readlines()

    # Find the last occurrence of a "TASK [Fail |" line
    latest_fail_index = -1
    for i, line in reversed(list(enumerate(lines))):
        if re.match(r'^TASK \[Fail \|', line):
            latest_fail_index = i
            break
    
    if latest_fail_index == -1:
        logger.info("No specific 'Fail |' tasks found in log.")
        return 0 # No specific failure task found

    # Get the content from the latest fail task to the end of the log
    latest_attempt_text = ''.join(lines[latest_fail_index:])

    if "Invalid Gitlab Registration Token or GitLab server URL" in latest_attempt_text:
        logger.info("Latest attempt failed due to invalid runner token or invalid gitlab server url (422 error).")
        return 2
    elif "Invalid Gitlab Registration Token" in latest_attempt_text:
        logger.info("Latest attempt failed due to invalid runner token.")
        return 1
    elif "not found" in latest_attempt_text and "/home/gitlab-runner-user/gitlab-runner/out/binaries/gitlab-runner-linux-riscv64" in latest_attempt_text:
        logger.info("Latest attempt failed because GitLab Runner binary was not found.")
        return 3 # New error code for "not found"
    else:
        logger.info("Latest attempt did not fail due to a recognized runner token/URL issue.")
        return 0


# --- Flask Routes ---

@app.route('/', methods=['GET'])
def render_index_page():
    """
    Renders the main landing page with options to add a board or register a runner.
    """
    return render_template('index.html')

@app.route('/add-board', methods=['GET'])
def render_add_board_page():
    """
    Renders the form to add a new RISC-V board.
    """
    return render_template('add_board.html')

@app.route('/add-board', methods=['POST'])
def handle_add_board_post():
    """
    Handles the submission of the form to add a new RISC-V board.
    This function writes the new board details to the ansible/inventory.ini file.
    """
    board_name = request.form.get('board_name')
    ip_address = request.form.get('ip_address')
    ssh_port = request.form.get('ssh_port') # Get the SSH port
    ssh_password = request.form.get('ssh_password')

    if not board_name or not ip_address:
        return render_template('add_board.html', message="Board Name and IP Address are required.", is_error=True)

    # Basic IP address validation (can be enhanced)
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address) and \
       not re.match(r"^[a-zA-Z0-9.-]+$", ip_address): # Allow hostnames too
        return render_template('add_board.html', message="Invalid IP Address or Hostname format.", is_error=True)

    # Prepare the line to add to inventory.ini
    inventory_line = f"{board_name} ansible_host={ip_address} ansible_user=gitlab-runner-user"
    
    # Add SSH port if provided and valid
    if ssh_port and ssh_port.isdigit() and 1 <= int(ssh_port) <= 65535:
        inventory_line += f" ansible_port={ssh_port}"
    else:
        # If not provided or invalid, default to 22 (Ansible's default)
        inventory_line += f" ansible_port=22" # Explicitly set default for clarity

    if ssh_password:
        # WARNING: Storing SSH passwords in plain text in inventory.ini is NOT secure.
        # For production, consider using Ansible Vault or SSH keys without passwords.
        inventory_line += f" ansible_password='{ssh_password}'" # Use ansible_password for modern Ansible
    
    inventory_line += "\n"

    try:
        with open(INVENTORY_FILE, 'a+') as f: # Use 'a+' to read and append
            f.seek(0) # Go to the beginning of the file to read
            content = f.read()
            
            # Check if the dynamic group header already exists
            if f"[{DYNAMIC_INVENTORY_GROUP}]" not in content:
                f.write(f"\n[{DYNAMIC_INVENTORY_GROUP}]\n") # Add group header if not present
            
            f.write(inventory_line)
        
        logger.info(f"Successfully added board '{board_name}' with IP '{ip_address}' to inventory.")
        return render_template('add_board.html', message=f"Board '{board_name}' successfully added to inventory!", is_error=False)
    except IOError as e:
        logger.error(f"Error writing to inventory file {INVENTORY_FILE}: {e}")
        return render_template('add_board.html', message=f"Failed to add board: {e}", is_error=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred while adding board: {e}")
        return render_template('add_board.html', message=f"An unexpected error occurred: {e}", is_error=True)


@app.route('/gitlab-riscv-runner', methods=['GET'])
def render_runner_registration_page():
    """
    Renders the GitLab Runner registration form.
    """
    return render_template('runner_token_ask.html')

@app.route('/gitlab-runner-result-page', methods=['POST'])
def handle_runner_registration_post():
    """
    Handles the submission of the GitLab Runner registration form.
    """
    logger.info('Starting handle_runner_registration_post function')
    
    runner_creation_token = request.form.get('runner_token')
    gitlab_server_url = request.form.get('gitlab_server_url')
    target_platform = request.form.get('target_platform')
    user_email = request.form.get('user_email')
    gitlab_project_link = request.form.get('gitlab_project_link')        
    
    # This check ensures that the response was not visited without first filling the fields
    if not all([runner_creation_token, gitlab_server_url, target_platform, user_email, gitlab_project_link]):
        logger.warning("Missing form fields in POST request.")
        return render_template('no_registration_token.html',
            error_message="It looks like you've landed here directly or submitted an incomplete form! To get started, please visit our registration page to provide the necessary details."
        )
    
    # Validate the GitLab Server URL
    if not check_gitlab_server(gitlab_server_url):
        logger.warning(f"Invalid GitLab Server URL provided: {gitlab_server_url}")
        return render_template('no_registration_token.html',
            error_message="The GitLab URL you entered appears to be invalid. Please check the URL and try again."
        )
    
    # Load the YAML registry file for runners
    runner_registry = load_registry(RUNNER_REGISTRY_FILE)
    
    # Select a healthy online target from runners_registry.yaml
    runner = find_and_select_online_target(runner_registry, target_platform)
    
    if runner is None: # Means either runner not healthy (number of registered gitlab runners >=15) OR no runner online
        logger.warning(f"No healthy and online runner found for platform: {target_platform}")
        return render_template('no_registration_token.html',
            error_message="We are sorry. Due to current limitations, the requested machine cannot be allocated at this time. Kindly try again briefly, or contact support at cloud-v@10xengineers.ai for further help."
        )

    # Create a unique runner id (example: "sf2-2-runner-<count+1>")
    # Ensure 'runner' exists as a key in 'nodes' and 'runners' is a list
    if runner not in runner_registry["nodes"] or "runners" not in runner_registry["nodes"][runner]:
        logger.error(f"Registry structure error for runner: {runner}. 'runners' list not found.")
        return render_template('no_registration_token.html',
            error_message="An internal configuration error occurred. Please contact support."
        )
    
    current_runner_count = len(runner_registry["nodes"][runner]["runners"])
    next_runner_id = f"{runner}-runner-{current_runner_count + 1}"
    
    # Attempt to register the gitlab runner on the machine
    registration_status = register_runner_attempt(
        runner, gitlab_server_url, runner_creation_token, LOG_FILE,
        INVENTORY_FILE, next_runner_id, RUNNER_REGISTRATION_PLAYBOOK
    )
    
    if registration_status:
        # Add runner info with current UTC timestamp in ISO format
        runner_registry["nodes"][runner]["runners"].append({
            "id": next_runner_id,
            "token": runner_creation_token, # Consider if storing token is secure/necessary
            "url": gitlab_server_url,
            "user_email": user_email,
            "gitlab_project_link": gitlab_project_link,
            "registered_at": datetime.now(timezone.utc).isoformat()
        })
        
        # Increment runner_count, ensuring it exists first
        if "runner_count" not in runner_registry["nodes"][runner]:
            runner_registry["nodes"][runner]["runner_count"] = 0
        runner_registry["nodes"][runner]["runner_count"] += 1

        save_registry(runner_registry, RUNNER_REGISTRY_FILE)
        logger.info("Runner registered successfully")
        
        return render_template('runner_creation_complete.html', runner_name=target_platform)
        
    else:
        logger.warning("Runner registration failed via Ansible.")
        
        fail_code = check_latest_failed_attempt(LOG_FILE)
        if fail_code == 1: # Meaning wrong token provided
            return render_template('no_registration_token.html',
                error_message="The GitLab registration token you entered has either expired or is invalid. Kindly check the token again or generate a new token by creating another GitLab runner."
            )
        elif fail_code == 2: # Meaning the request cannot be processed code 422. Due to either wrong token or wrong gitlab server url
            return render_template('no_registration_token.html',
                error_message="Your GitLab token is invalid or expired, or the server URL is incorrect. Please verify these details or generate a new token."
            )
        elif fail_code == 3: # New error for "not found"
            return render_template('no_registration_token.html',
                error_message="The GitLab Runner package was not found on the selected machine and could not be installed automatically. Please try again or contact support."
            )
        
        # Generic error message if no specific failure pattern matched
        return render_template('no_registration_token.html',
            error_message="We encountered an internal issue and were unable to assign the requested machine. Please try again shortly, or contact support at cloud-v@10xengineers.ai for assistance."
        )

# Run the Flask app
if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs(os.path.join(APP_ROOT, "ansible"), exist_ok=True)
    os.makedirs(os.path.join(APP_ROOT, "static"), exist_ok=True)
    os.makedirs(os.path.join(APP_ROOT, "templates"), exist_ok=True)

    # Initialize the registry file if it doesn't exist to ensure initial structure
    # This also handles cases where it exists but is empty/malformed
    load_registry(RUNNER_REGISTRY_FILE)

    app.run(debug=True) # Set debug=False for production
