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
ANSIBLE_SETUP_LOG_FILE = os.path.join(APP_ROOT, "ansible-setup.log")
ANSIBLE_UNREGISTER_LOG_FILE = os.path.join(APP_ROOT, "ansible-unregister.log") # New log file for unregistration
RUNNER_REGISTRATION_PLAYBOOK = os.path.join(APP_ROOT, "ansible", "register-runner.yml")
SETUP_BOARD_PLAYBOOK = os.path.join(APP_ROOT, "ansible", "setup-board.yml")
UNREGISTER_BOARD_PLAYBOOK = os.path.join(APP_ROOT, "ansible", "remove_board.yml") # New playbook path

# --- Utility Functions ---

def check_gitlab_server(url):
    """
    Checks if a given URL is a valid and reachable GitLab instance.
    This version is more robust against Cloudflare and similar protections.
    """
    url = url.rstrip("/")
    URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
    if not URL_REGEX.match(url):
        logger.info(f"'{url}' does not appear to be a valid URL format.")
        return False
    logger.info(f"\n--- Checking URL: {url} ---")
    try:
        head_resp = requests.head(url, timeout=5, allow_redirects=True)
        if 'X-Gitlab-Instance' in head_resp.headers:
            logger.info(f"'{url}' is a GitLab URL (X-Gitlab-Instance header confirmed).")
            return True
    except requests.exceptions.RequestException:
        pass
    try:
        base_resp = requests.get(url, timeout=5, allow_redirects=True)
        if 'X-Gitlab-Instance' in base_resp.headers:
            logger.info(f"'{url}' is a GitLab URL (Homepage content 'GitLab' confirmed).")
            return True
    except requests.exceptions.RequestException:
        pass
    api_version_url = f"{url}/api/v4/version"
    logger.info(f"Attempting to reach GitLab API at: {api_version_url}")
    try:
        api_resp = requests.get(api_version_url, timeout=5)
        if api_resp.status_code == 200:
            if 'application/json' in api_resp.headers.get('Content-Type', ''):
                try:
                    data = api_resp.json()
                    if 'version' in data and 'revision' in data:
                        logger.info(f"'{url}' is a GitLab URL (API /version confirmed, version: {data['version']}).")
                        return True
                except requests.exceptions.JSONDecodeError:
                    pass
        if 'X-Gitlab-Instance' in api_resp.headers:
            logger.info(f"'{url}' is a GitLab URL (API /version header confirmed, even with status {api_resp.status_code}).")
            return True
        if "GitLab" in api_resp.text:
            logger.info(f"'{url}' is a GitLab URL (API /version content 'GitLab' confirmed, even with status {api_resp.status_code}).")
            return True
    except requests.exceptions.RequestException:
        pass
    health_url = f"{url}/-/health"
    logger.info(f"Attempting to reach GitLab health endpoint at: {health_url}")
    try:
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
    except requests.exceptions.RequestException:
        pass
    login_page_url = f"{url}/users/sign_in"
    logger.info(f"All API checks failed/undetermined. Falling back to login page check at: {login_page_url}")
    try:
        login_resp = requests.get(login_page_url, timeout=5, allow_redirects=True)
        if "_gitlab_session" in login_resp.headers.get("Set-Cookie", ""):
            logger.info(f"'{url}' is a GitLab URL (login page cookie confirmed).")
            return True
        if "GitLab" in login_resp.text:
            logger.info(f"'{url}' is a GitLab URL (login page content 'GitLab' confirmed).")
            return True
    except requests.exceptions.RequestException as e:
        logger.info(f"Could not reach '{url}' or an error occurred: {e}")
        return False
    except Exception as e:
        logger.info(f"An unexpected error occurred while checking '{url}': {e}")
        return False
    logger.info(f"'{url}' is not a GitLab URL (no conclusive evidence found after all checks).")
    return False


def is_online(target_node):
    """
    Runs an Ansible ping module to check if a target node is alive.
    Returns True if alive, False otherwise.
    """
    logger.info(f"--- Checking if {target_node} is online via Ansible ping...")
    try:
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
            text=True
        )
        output = result.stdout
        logger.info(f"--- Ansible Ping Output for {target_node}:\n{output[:500]}...")
        if f"SUCCESS" in output and "ping" in output and "pong" in output:
            logger.info(f"--- ✅ {target_node} is online.")
            return True
        else:
            logger.info(f"--- ❌ {target_node} is not responding or ping failed.")
            return False
    except FileNotFoundError:
        logger.error("Error: 'ansible' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.error(f"Error running Ansible ping for {target_node}: {e}")
        return False


def get_healthy_targets(registry, runner_type):
    """
    Gets a list of healthy nodes for a specific type,
    sorted by the number of runners (least first).
    """
    healthy_nodes = {
        name: data for name, data in registry.get("nodes", {}).items()
        if data.get("health") == "good" and data.get("type") == runner_type
    }
    if not healthy_nodes:
        return []
    sorted_nodes = sorted(
        healthy_nodes.items(),
        key=lambda x: len(x[1].get("runners", []))
    )
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
            return target
    logger.info(f"❌ No healthy *and* online nodes found for type '{runner_type}'.")
    return None


def load_registry(registry_path):
    """
    This function loads the runners_registry.yaml YAML file.
    If any such file does not exist, it creates an empty file
    with just a 'nodes' key. If the file exists but is empty or malformed,
    it also initializes it with an empty 'nodes' structure.
    It ensures each node has required fields if they are present.
    """
    # No default nodes are defined here; the 'nodes' dictionary will be empty initially.
    default_empty_registry_structure = {"nodes": {}}

    registry = None
    if not os.path.exists(registry_path):
        logger.info(f"Registry file not found at {registry_path}. Creating with empty structure.")
        registry = default_empty_registry_structure
        with open(registry_path, "w") as f:
            yaml.dump(registry, f, default_flow_style=False)
    else:
        try:
            with open(registry_path, "r") as f:
                registry = yaml.safe_load(f)
                if registry is None:
                    logger.warning(f"Registry file at {registry_path} is empty or invalid. Initializing with empty structure.")
                    registry = default_empty_registry_structure
                
                # Ensure 'nodes' key exists and is a dictionary
                if "nodes" not in registry or not isinstance(registry["nodes"], dict):
                    logger.warning(f"Registry file at {registry_path} has missing or malformed 'nodes' section. Reinitializing with empty structure.")
                    registry = default_empty_registry_structure
                else:
                    # For existing nodes, ensure required fields are present (if they were added previously)
                    # This loop now only ensures consistency for *already existing* nodes, not adding new defaults.
                    for node_name, node_data in list(registry["nodes"].items()): # Use list() to allow modification during iteration
                        if "health" not in node_data:
                            node_data["health"] = "unknown" # Default health for existing, untracked nodes
                        if "type" not in node_data:
                            node_data["type"] = "Unknown"
                        if "runner_count" not in node_data:
                            node_data["runner_count"] = 0
                        if "runners" not in node_data or not isinstance(node_data["runners"], list):
                            node_data["runners"] = []
                        if "ip_address" not in node_data:
                            node_data["ip_address"] = "N/A"
                        if "ssh_port" not in node_data:
                            node_data["ssh_port"] = "22"
                        # Remove setup_status if it exists from previous versions
                        if "setup_status" in node_data:
                            del node_data["setup_status"]

        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML from {registry_path}: {e}. Initializing with empty structure.")
            registry = default_empty_registry_structure
        
        # Always write back the potentially updated/initialized registry
        with open(registry_path, "w") as wf:
            yaml.dump(registry, wf, default_flow_style=False)
        
    return registry


def register_runner_attempt(target, gitlab_server_url, runner_reg_token, log_file, inventory_file, runner_name, runner_registeration_playbook):
    """
    Runs the Ansible playbook to register the GitLab runner on the requested machine.
    Returns True if successful, False otherwise.
    """
    cmd = [
        "ansible-playbook", runner_registeration_playbook,
        "-i", inventory_file,
        "-e", f"target_node={target}",
        "-e", f"registration_token={runner_reg_token}",
        "-e", f"gitlab_url={gitlab_server_url}",
        "-e", f"runner_name={runner_name}"
    ]
    logger.info(f"Executing Ansible command for runner registration: {' '.join(cmd)}")
    try:
        with open(log_file, "a") as f:
            f.write(f"\n--- Runner Registration Attempt Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
        logger.info(f"Ansible registration playbook return code: {process.returncode}")
        return process.returncode == 0
    except FileNotFoundError:
        logger.error("Error: 'ansible-playbook' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.error(f"Error running Ansible playbook for runner registration: {e}")
        return False

def setup_board_attempt(target_node, log_file, inventory_file, setup_playbook):
    """
    Runs the Ansible playbook to set up a new RISC-V board.
    Returns True if successful, False otherwise.
    """
    cmd = [
        "ansible-playbook", setup_playbook,
        "-i", inventory_file,
        "-e", f"target_node={target_node}", # Pass the target node dynamically
        "--extra-vars", f"ansible_user=root" # Ensure ansible_user is passed for setup
    ]
    logger.info(f"Executing Ansible command for board setup: {' '.join(cmd)}")
    try:
        with open(log_file, "a") as f: # Use the dedicated setup log file
            f.write(f"\n--- Board Setup Attempt Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
        logger.info(f"Ansible board setup playbook return code: {process.returncode}")
        return process.returncode == 0
    except FileNotFoundError:
        logger.error("Error: 'ansible-playbook' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.error(f"Error running Ansible playbook for board setup: {e}")
        return False

def unregister_board_attempt(target_node, log_file, inventory_file, unregister_playbook):
    """
    Runs the Ansible playbook to unregister and clean up a RISC-V board.
    Returns True if successful, False otherwise.
    """
    cmd = [
        "ansible-playbook", unregister_playbook,
        "-i", inventory_file,
        "-e", f"target_node={target_node}",
        "--extra-vars", f"ansible_user=root" # Ensure ansible_user is passed for cleanup
    ]
    logger.info(f"Executing Ansible command for board unregistration: {' '.join(cmd)}")
    try:
        with open(log_file, "a") as f: # Use the dedicated unregister log file
            f.write(f"\n--- Board Unregistration Attempt Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
            process = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, check=False)
        logger.info(f"Ansible board unregistration playbook return code: {process.returncode}")
        return process.returncode == 0
    except FileNotFoundError:
        logger.error("Error: 'ansible-playbook' command not found. Is Ansible installed and in your PATH?")
        return False
    except Exception as e:
        logger.error(f"Error running Ansible playbook for board unregistration: {e}")
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
        4: Generic board setup failure.
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
    elif "fatal:" in latest_attempt_text or "FAILED!" in latest_attempt_text: # Generic check for Ansible fatal/failed
        logger.info("Latest attempt failed due to a generic Ansible setup error.")
        return 4 # New error code for generic setup failure
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
    This function first adds the board to inventory.ini, then attempts to set up the board.
    If setup fails, the board is removed from inventory.ini.
    """
    board_name = request.form.get('board_name')
    ip_address = request.form.get('ip_address')
    ssh_port = request.form.get('ssh_port')
    runner_type = request.form.get('runner_type')
    
    if not all([board_name, ip_address, runner_type]):
        return render_template('add_board.html', message="Board Name, IP Address, and Runner Type are required.", is_error=True)

    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address) and \
       not re.match(r"^[a-zA-Z0-9.-]+$", ip_address):
        return render_template('add_board.html', message="Invalid IP Address or Hostname format.", is_error=True)

    registry = load_registry(RUNNER_REGISTRY_FILE)
    if board_name in registry["nodes"]:
        return render_template('add_board.html', message=f"A board with the name '{board_name}' already exists. Please choose a different name.", is_error=True)

    # Prepare the inventory line content
    inventory_line_content = f"{board_name} ansible_host={ip_address} ansible_user=gitlab-runner-user"
    if ssh_port and ssh_port.isdigit() and 1 <= int(ssh_port) <= 65535:
        inventory_line_content += f" ansible_port={ssh_port}"
    else:
        inventory_line_content += f" ansible_port=22"
    inventory_line_to_add = inventory_line_content + "\n"

    # Define the specific group header for this runner type
    runner_type_group_header = f"[{runner_type}]\n"

    original_inventory_content = ""
    try:
        # Read current inventory content
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, 'r') as f:
                original_inventory_content = f.read()

        # Temporarily add the board to inventory.ini for setup
        with open(INVENTORY_FILE, 'a') as f:
            # Check if the specific runner_type group header already exists
            if runner_type_group_header.strip() not in original_inventory_content:
                f.write(f"\n{runner_type_group_header}") # Add specific group header if not present
            f.write(inventory_line_to_add)
        logger.info(f"Temporarily added board '{board_name}' to inventory under group '{runner_type}' for setup attempt.")

        # Attempt to set up the board
        setup_success = setup_board_attempt(board_name, ANSIBLE_SETUP_LOG_FILE, INVENTORY_FILE, SETUP_BOARD_PLAYBOOK)

        if setup_success:
            # Setup successful: The board is already in inventory.ini.
            # Now add it to runner_registry.yaml permanently.
            registry["nodes"][board_name] = {
                "health": "good",
                "type": runner_type,
                "runner_count": 0,
                "runners": [],
                "ip_address": ip_address,
                "ssh_port": ssh_port if ssh_port and ssh_port.isdigit() else "22",
            }
            save_registry(registry, RUNNER_REGISTRY_FILE)
            logger.info(f"Board '{board_name}' successfully added to runner registry.")
            message = f"Board '{board_name}' successfully added and set up!"
            is_error = False
        else:
            # Setup failed: Remove the board from inventory.ini
            logger.warning(f"Board '{board_name}' setup failed. Removing from inventory.ini.")
            
            # Read current inventory content again to ensure we have the latest state
            current_inventory_lines = []
            if os.path.exists(INVENTORY_FILE):
                with open(INVENTORY_FILE, 'r') as f:
                    current_inventory_lines = f.readlines()

            updated_inventory_lines = []
            removed_line = False
            for line in current_inventory_lines:
                # Only remove the exact line we added
                if line.strip() == inventory_line_content.strip() and not removed_line:
                    removed_line = True # Ensure only the first match is removed
                    continue
                updated_inventory_lines.append(line)

            # Check if the specific runner_type group header needs to be removed
            temp_content_after_removal = "".join(updated_inventory_lines)
            
            group_pattern = re.compile(r'\[{}\]\s*\n(?P<hosts>.*?)(?=\n\[|\Z)'.format(re.escape(runner_type)), re.DOTALL)
            match = group_pattern.search(temp_content_after_removal)
            
            if match and not match.group('hosts').strip():
                final_inventory_lines = []
                skip_group_section = False
                for line in updated_inventory_lines:
                    if line.strip() == runner_type_group_header.strip():
                        skip_group_section = True
                        continue
                    if skip_group_section and line.strip().startswith('['):
                        skip_group_section = False
                    if not skip_group_section:
                        final_inventory_lines.append(line)
                updated_inventory_lines = final_inventory_lines
            elif not match and runner_type_group_header.strip() in temp_content_after_removal:
                 updated_inventory_lines = [line for line in updated_inventory_lines if line.strip() != runner_type_group_header.strip()]


            with open(INVENTORY_FILE, 'w') as f:
                f.write("".join(updated_inventory_lines))
            
            message = f"Board '{board_name}' setup failed. It has not been added to the inventory or registry. Please check the logs for details or contact support."
            is_error = True
    except IOError as e:
        logger.error(f"Error managing inventory file {INVENTORY_FILE}: {e}")
        message = f"Failed to manage inventory file during board setup: {e}"
        is_error = True
    except Exception as e:
        logger.error(f"An unexpected error occurred while adding board: {e}")
        message = f"An unexpected error occurred: {e}"
        is_error = True
    
    logger.info(f"Board '{board_name}' final outcome: {'Success' if setup_success and not is_error else 'Failure'}.")
    return render_template('add_board.html', message=message, is_error=is_error)


@app.route('/gitlab-riscv-runner', methods=['GET'])
def render_runner_registration_page():
    """
    Renders the GitLab Runner registration form.
    """
    return render_template('register-runner.html')

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
    
    if not all([runner_creation_token, gitlab_server_url, target_platform, user_email, gitlab_project_link]):
        logger.warning("Missing form fields in POST request.")
        return render_template('no_registration_token.html',
            error_message="It looks like you've landed here directly or submitted an incomplete form! To get started, please visit our registration page to provide the necessary details."
        )
    
    if not check_gitlab_server(gitlab_server_url):
        logger.warning(f"Invalid GitLab Server URL provided: {gitlab_server_url}")
        return render_template('no_registration_token.html',
            error_message="The GitLab URL you entered appears to be invalid. Please check the URL and try again."
        )
    
    runner_registry = load_registry(RUNNER_REGISTRY_FILE)
    
    runner = find_and_select_online_target(runner_registry, target_platform)
    
    if runner is None:
        logger.warning(f"No healthy and online runner found for platform: {target_platform}")
        return render_template('no_registration_token.html',
            error_message="We are sorry. Due to current limitations, the requested machine cannot be allocated at this time. Kindly try again briefly, or contact support at cloud-v@10xengineers.ai for further help."
        )

    if runner not in runner_registry["nodes"] or "runners" not in runner_registry["nodes"][runner]:
        logger.error(f"Registry structure error for runner: {runner}. 'runners' list not found.")
        return render_template('no_registration_token.html',
            error_message="An internal configuration error occurred. Please contact Gage support."
        )
    
    current_runner_count = len(runner_registry["nodes"][runner]["runners"])
    next_runner_id = f"{runner}-runner-{current_runner_count + 1}"
    
    registration_status = register_runner_attempt(
        runner, gitlab_server_url, runner_creation_token, LOG_FILE,
        INVENTORY_FILE, next_runner_id, RUNNER_REGISTRATION_PLAYBOOK
    )
    
    if registration_status:
        runner_registry["nodes"][runner]["runners"].append({
            "id": next_runner_id,
            "token": runner_creation_token,
            "url": gitlab_server_url,
            "user_email": user_email,
            "gitlab_project_link": gitlab_project_link,
            "registered_at": datetime.now(timezone.utc).isoformat()
        })
        
        if "runner_count" not in runner_registry["nodes"][runner]:
            runner_registry["nodes"][runner]["runner_count"] = 0
        runner_registry["nodes"][runner]["runner_count"] += 1

        save_registry(runner_registry, RUNNER_REGISTRY_FILE)
        logger.info("Runner registered successfully")
        
        return render_template('runner_creation_complete.html', runner_name=target_platform)
        
    else:
        logger.warning("Runner registration failed via Ansible.")
        
        fail_code = check_latest_failed_attempt(LOG_FILE)
        if fail_code == 1:
            return render_template('no_registration_token.html',
                error_message="The GitLab registration token you entered has either expired or is invalid. Kindly check the token again or generate a new token by creating another GitLab runner."
            )
        elif fail_code == 2:
            return render_template('no_registration_token.html',
                error_message="Your GitLab token is invalid or expired, or the server URL is incorrect. Please verify these details or generate a new token."
            )
        elif fail_code == 3:
            return render_template('no_registration_token.html',
                error_message="The GitLab Runner package was not found on the selected machine and could not be installed automatically. Please try again or contact support."
            )
        elif fail_code == 4:
            return render_template('no_registration_token.html',
                error_message="An unexpected error occurred during board setup. Please check the application logs for more details or contact support."
            )
        
        return render_template('no_registration_token.html',
            error_message="We encountered an internal issue and were unable to assign the requested machine. Please try again shortly, or contact support at cloud-v@10xengineers.ai for assistance."
        )

# Add new route for board status
@app.route('/board-status', methods=['GET'])
def render_board_status_page():
    """
    Renders the page showing the setup status of all RISC-V boards.
    """
    registry = load_registry(RUNNER_REGISTRY_FILE)
    boards_to_display = {
        name: data for name, data in registry.get("nodes", {}).items()
    }
    return render_template('board_status.html', boards=boards_to_display)

@app.route('/remove-board', methods=['GET'])
def render_unregister_board_page():
    """
    Renders the form to unregister a RISC-V board.
    """
    return render_template('remove_board.html')

@app.route('/remove-board', methods=['POST'])
def handle_unregister_board_post():
    """
    Handles the submission of the form to unregister a RISC-V board.
    This function attempts to unregister the board using Ansible.
    If successful, it removes the board from inventory.ini and runner_registry.yaml.
    """
    board_name = request.form.get('board_name')

    if not board_name:
        return render_template('remove_board.html', message="Board Name/ID is required.", is_error=True)

    registry = load_registry(RUNNER_REGISTRY_FILE)
    if board_name not in registry["nodes"]:
        return render_template('unregister_board.html', message=f"Board '{board_name}' not found in the registry. Please ensure the name is correct.", is_error=True)
    
    # Get board details from registry to construct inventory line for removal
    board_data = registry["nodes"][board_name]
    ip_address = board_data.get("ip_address", "N/A")
    ssh_port = board_data.get("ssh_port", "22")
    runner_type = board_data.get("type", "Unknown")

    # Construct the inventory line that would have been added
    inventory_line_content = f"{board_name} ansible_host={ip_address} ansible_user=gitlab-runner-user"
    inventory_line_content += f" ansible_port={ssh_port}" if ssh_port != "22" else f" ansible_port=22"
    
    runner_type_group_header = f"[{runner_type}]" # No newline here for comparison

    unregister_success = False
    try:
        # Attempt to unregister the board using the playbook
        unregister_success = unregister_board_attempt(board_name, ANSIBLE_UNREGISTER_LOG_FILE, INVENTORY_FILE, UNREGISTER_BOARD_PLAYBOOK)

        if unregister_success:
            # Unregistration successful: Remove from inventory.ini and runner_registry.yaml
            
            # Remove from runner_registry.yaml
            del registry["nodes"][board_name]
            save_registry(registry, RUNNER_REGISTRY_FILE)
            logger.info(f"Board '{board_name}' successfully removed from runner registry.")

            # Remove from inventory.ini
            current_inventory_lines = []
            if os.path.exists(INVENTORY_FILE):
                with open(INVENTORY_FILE, 'r') as f:
                    current_inventory_lines = f.readlines()

            updated_inventory_lines = []
            removed_board_line = False
            for line in current_inventory_lines:
                # Remove the exact board line
                if line.strip() == inventory_line_content.strip() and not removed_board_line:
                    removed_board_line = True
                    continue
                updated_inventory_lines.append(line)

            # Check if the group header for this runner_type is now empty and should be removed
            temp_content_after_removal = "".join(updated_inventory_lines)
            group_pattern = re.compile(r'\[{}\]\s*\n(?P<hosts>.*?)(?=\n\[|\Z)'.format(re.escape(runner_type)), re.DOTALL)
            match = group_pattern.search(temp_content_after_removal)
            
            if match and not match.group('hosts').strip(): # If the hosts section for this group is empty
                final_inventory_lines = []
                skip_group_section = False
                for line in updated_inventory_lines:
                    if line.strip() == runner_type_group_header.strip():
                        skip_group_section = True
                        continue
                    if skip_group_section and line.strip().startswith('['): # Found next group, stop skipping
                        skip_group_section = False
                    if not skip_group_section:
                        final_inventory_lines.append(line)
                updated_inventory_lines = final_inventory_lines
            elif not match and runner_type_group_header.strip() in temp_content_after_removal:
                 # Case where group header might be at the very end and becomes empty
                 updated_inventory_lines = [line for line in updated_inventory_lines if line.strip() != runner_type_group_header.strip()]

            with open(INVENTORY_FILE, 'w') as f:
                f.write("".join(updated_inventory_lines))
            logger.info(f"Board '{board_name}' successfully removed from inventory.ini.")

            message = f"Board '{board_name}' successfully unregistered and removed."
            is_error = False
        else:
            # Unregistration failed: Keep in registry and inventory, provide error message
            message = f"Failed to unregister board '{board_name}'. Please check the logs ({ANSIBLE_UNREGISTER_LOG_FILE}) for details and ensure the board is reachable via SSH."
            is_error = True
    except Exception as e:
        logger.error(f"An unexpected error occurred during unregistration of board '{board_name}': {e}")
        message = f"An unexpected error occurred during unregistration: {e}"
        is_error = True
    
    logger.info(f"Board '{board_name}' unregistration outcome: {'Success' if unregister_success else 'Failure'}.")
    return render_template('unregister_board.html', message=message, is_error=is_error)


# Run the Flask app
if __name__ == '__main__':
    # Create necessary directories if they don't exist
    os.makedirs(os.path.join(APP_ROOT, "ansible"), exist_ok=True)
    os.makedirs(os.path.join(APP_ROOT, "static"), exist_ok=True)
    os.makedirs(os.path.join(APP_ROOT, "templates"), exist_ok=True)

    # Initialize the registry file if it doesn't exist to ensure initial structure
    load_registry(RUNNER_REGISTRY_FILE)

    app.run(debug=True) # Set debug=False for production
