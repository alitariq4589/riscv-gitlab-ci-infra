# **RISC-V CI/CD Management: Technical Overview**

This document provides a comprehensive technical overview of the RISC-V GitLab Runner Management application. It explains the architecture, key components, workflows, and how errors are handled, making it useful for contributors and technical users.

## **Table of Contents**

1. [Introduction](https://www.google.com/search?q=%23introduction)  
2. [Architecture Overview](https://www.google.com/search?q=%23architecture-overview)  
3. [Key Components and Files](https://www.google.com/search?q=%23key-components-and-files)  
   * [Flask Application (app.py)](https://www.google.com/search?q=%23flask-application-apppy)  
   * [HTML Templates (templates/)](https://www.google.com/search?q=%23html-templates-templates)  
   * [Ansible Playbooks and Inventory (ansible/)](https://www.google.com/search?q=%23ansible-playbooks-and-inventory-ansible)  
   * [Runner Registry (runner\_registry.yaml)](https://www.google.com/search?q=%23runner-registry-runner_registryyaml)  
   * [Log Files (logs/)](https://www.google.com/search?q=%23log-files-logs)  
4. [Core Workflows](https://www.google.com/search?q=%23core-workflows)  
   * [Adding a New RISC-V Board](https://www.google.com/search?q=%23adding-a-new-risc-v-board)  
   * [Registering a GitLab Runner](https://www.google.com/search?q=%23registering-a-gitlab-runner)  
   * [Unregistering a RISC-V Board](https://www.google.com/search?q=%23unregistering-a-risc-v-board)  
   * [Unregistering a Specific GitLab Runner](https://www.google.com/search?q=%23unregistering-a-specific-gitlab-runner)  
5. [Error Handling Mechanism](https://www.google.com/search?q=%23error-handling-mechanism)  
6. [Deployment and Contribution](https://www.google.com/search?q=%23deployment-and-contribution)

## **1\. Introduction**

The RISC-V GitLab Runner Management application offers a web-based interface designed to simplify the process of integrating and managing RISC-V development boards as GitLab CI/CD runners. It automates essential tasks such as setting up boards, registering new runners, and removing existing ones, which significantly streamlines the CI/CD pipeline for projects involving RISC-V compute machines.

## **2\. Architecture Overview**

This application is built using the Flask web framework and uses Ansible for managing remote machines. It uses a YAML file as a registry to keep track of board and runner information. It also generates detailed logs for debugging and monitoring.

* **Flask (Python):** This is the main web server. It handles the user interface, processes user requests, runs Ansible playbooks, and manages the runner registry.  
* **Ansible:** This is the automation tool. It's used to set up boards and run commands on RISC-V boards. This includes installing GitLab Runner, registering and unregistering runners, and cleaning up systems.  
* **YAML Registry (`runner\_registry.yaml`):** This file acts as the application's data storage. It records information about registered boards and their associated GitLab runners.  
* **HTML/CSS:** These provide the user interface for interacting with the application.

## **3\. Key Components and Files**

The application's files are organized as follows:

```
.  
├── ansible  
│   ├── inventory.ini  
│   ├── inventory\_template.ini  
│   ├── register-runner.yml  
│   ├── setup-board.yml  
│   ├── unregister\_board.yml  
│   └── unregister\_runner.yml  
├── docs  
│   └── TECHNICAL\_DOCS.md  
├── LICENSE  
├── logs  
│   ├── ansible-registration.log  
│   └── ansible-setup.log  
├── README.md  
├── requirements.txt  
├── runner\_registry.yaml  
├── start.py  
├── static  
│   └── gitlab-runner-riscv.drawio.png  
└── templates  
    ├── add\_board.html  
    ├── index.html  
    ├── no\_registration\_token.html  
    ├── register-runner.html  
    ├── remove\_board.html  
    ├── runner\_creation\_complete.html  
    └── unregister\_runner.html
```

### **Flask Application (`app.py`)**

This file contains the main Python code for the application.

* **Routes:** It defines different web addresses (like `/`, `/add-board`, `/gitlab-riscv-runner`, `/unregister-board`, `/unregister-runner`) that serve HTML pages and handle form submissions.  
* **Utility Functions:**  
  * `check_gitlab_server(url)`: Checks if a given URL is a valid and reachable GitLab instance by trying various API and homepage checks.  
  * `is_online(target_node)`: Uses Ansible's ping module to see if a remote host can be reached via SSH.  
  * `get_healthy_targets(registry, runner_type)`: Filters the `runner_registry.yaml` to find healthy nodes of a specific type, then sorts them by the number of runners (least first).  
  * `find_and_select_online_target(registry, runner_type)`: Selects the best available (healthy and online) RISC-V board to assign a runner to.  
  * `load_registry(registry_path)`: Loads the `runner_registry.yaml` file. If the file doesn't exist or is corrupted, it creates a new one with the correct structure.  
  * `save_registry(registry, runner_registry_file\_path)`: Saves the current data from the `runner_registry` dictionary back to the YAML file.  
  * `register_runner_attempt(...)`, `setup_board_attempt(...)`, `unregister_board_attempt(...)`, `unregister_gitlab_runner_attempt(...)`: These functions run their respective Ansible playbooks using subprocess.run(), sending their output to specific log files. They return True for success and False for failure.  
  * `check_latest_failed_attempt(log_file)`: **(Important for error handling)** This function carefully reads the latest Ansible log content to find specific error messages (like invalid tokens, 422 errors, or missing binaries) and returns an error code. It's designed to extract error details from Ansible's log.

### **HTML Templates (`templates/`)**

These Jinja2 templates create the web-based user interface:

* `index.html`: The main page with navigation tabs for different management actions.  
* `add_board.html`: A form for adding a new RISC-V board to the system.  
* `register-runner.html`: A form for registering a GitLab Runner on an existing board.  
* `unregister_board.html`: A form for completely removing and cleaning up a RISC-V board.  
* `unregister_runner.html`: A form for removing a specific GitLab Runner from a board.  
* `runner_creation_complete.html`: The success page shown after a runner is successfully registered.  
* `no_registration_token.html`: A general error page, displayed when registration fails or incorrect input is given.  
* `board_status.html`: Shows the health and runner status of all registered boards.

### **Ansible Playbooks and Inventory (`ansible/`)**

Ansible is the automation engine used by the application.

* `inventory.ini`: This file lists the hosts (RISC-V boards) that Ansible can manage. app.py updates its contents dynamically when boards are added or removed.  
* `register-runner.yml`: This playbook installs and registers a GitLab Runner on a target board. It takes `runner_name`, `gitlab_url`, and `registration_token` as inputs. It also includes tasks to check for specific GitLab Runner errors.  
* `setup-board.yml`: This playbook performs the initial setup on a new RISC-V board. This includes creating users, setting up SSH keys, installing Docker, and downloading the GitLab Runner binary.  
* `unregister_board.yml`: This playbook completely removes the GitLab Runner installation, its service, and related files from a specified board.  
* `unregister_gitlab_runner.yml`: This playbook removes a *specific* GitLab Runner from the GitLab server and deletes its entry from the local `config.toml` file. It intelligently manages the service: if other runners are still configured on the board, the GitLab Runner service is restarted to apply the changes; if the removed runner was the last one, the service is stopped, disabled, and its installation directory is removed.

### **Runner Registry (`runner_registry.yaml`)**

This YAML file stores the application's data. It keeps track of:

* `nodes`: A dictionary where each key is a unique board name (e.g., `visionfive2-01`).  
  * Each node entry includes:  
    * `health`: The board's operational status (e.g., good, unknown).  
    * `type`: The specific type of RISC-V board (e.g., visionfive2, qemu).  
    * `runner_count`: The number of GitLab runners currently registered on this board.  
    * `runners`: A list of dictionaries, each representing a registered GitLab runner.  
      * `id`: A unique identifier for the runner (e.g., sf2-3-runner-1).  
      * `token`: The GitLab registration token used for this runner.  
      * `url`: The GitLab server's URL.  
      * `user_email`: The email address of the user whose RISC-V machine is registered.  
      * `gitlab_project_link`: A link to the associated GitLab project.  
      * `registered_at`: The timestamp when the runner was registered.  
    * `ip_address`: The board's IP address or hostname.  
    * `ssh_port`: The SSH port used to communicate with the board (defaults to `22`).

### **Log Files (`logs/`)**

These dedicated log files record the output from Ansible playbook executions:

* `ansible-registration.log`: Logs output from register-runner.yml.  
* `ansible-setup.log`: Logs output from setup-board.yml.  
* `ansible-unregister-board.log`: Logs output from `unregister_board.yml`.  
* `ansible-unregister-runner.log`: Logs output from `unregister_gitlab_runner.yml`.

## **4. Core Workflows**

### **Adding a New RISC-V Board**

1. **Get User Input:** The user provides the `board_name`, `ip_address`, `ssh_port (optional)`, and `runner_type` through the `add_board.html` form.  
2. **Validate Input:** `app.py` checks the input and confirms if the `board_name` already exists in `runner_registry.yaml`.  
3. **Update Inventory Temporarily:** The board's details are added to `ansible/inventory.ini` under its specified `runner_type` group.  
4. **Set up Board:** `app.py` runs `ansible/setup-board.yml` on the new board. This playbook handles tasks like setting up SSH keys, creating user accounts, installing Docker, and downloading the GitLab Runner binary.  
5. **Update Registry Conditionally:**  
   * If setup-board.yml succeeds, the board's details (including health: good) are permanently saved to `runner_registry.yaml`.  
   * If `setup-board.yml fails`, the board's entry is removed from `ansible/inventory.ini` to prevent further attempts on a non-functional board.

### **Registering a GitLab Runner**

1. **Get User Input:** The user submits the `runner_token`, `gitlab_server_url`, `target_platform`, `user_email`, and `gitlab_project_link` using the `register-runner.html` form.  
2. **Verify GitLab Server:** `app.py` checks the `gitlab_server_url` using the `check_gitlab_server()` function.  
3. **Select Board:** `app.py` calls `find_and_select_online_target()` to find the least-used, healthy, and online board of the specified `target_platform` from `runner_registry.yaml`.  
4. **Run Registration:** `app.py` runs `ansible/register-runner.yml` on the selected board, passing the GitLab URL, registration token, and a newly generated `runner_name` (e.g., `sf2-3-runner-1`).  
5. **Update Registry:**  
   * If `register-runner.yml` succeeds, the new runner's details (ID, token, URL, user info, timestamp) are added to the runners list of the selected board in `runner_registry.yaml`. The `runner_count` for that board is increased.  
   * If `register-runner.yml` fails, `check_latest_failed_attempt()` is called to read the Ansible log for specific error messages (e.g., invalid token, `422` error, missing binary). This provides precise feedback to the user.

### **Unregistering a RISC-V Board**

1. **Get User Input:** The user provides the `board_name` to unregister via the `unregister_board.html` form.  
2. **Verify Registry:** `app.py` confirms that the `board_name` exists in `runner_registry.yaml`.  
3. **Run Board Unregistration:** `app.py` runs `ansible/unregister_board.yml` on the specified board. This playbook performs a full cleanup, stopping and disabling the GitLab Runner service, removing its installation directory, and deleting related files.  
4. **Update Registry and Inventory:**  
   * If `unregister_board.yml` succeeds, the board is completely removed from `runner_registry.yaml`, and its entry is deleted from `ansible/inventory.ini`.  
   * If it fails, an error message is shown.

### **Unregistering a Specific GitLab Runner**

1. **Get User Input:** The user provides the `node_name` (board ID) and `runner_id` via the `unregister_runner.html` form.  
2. **Verify Registry:** `app.py` checks that both the `node_name` and `runner_id` exist in `runner_registry.yaml`.  
3. **Run Runner Unregistration:** `app.py` runs `ansible/unregister_gitlab_runner.yml` on the specified board, passing the `runner_id`.  
   * This playbook first reads the remote `config.toml` to get the runner's authentication token.  
   * Then, it runs `gitlab-runner unregister --url <url> --token <auth_token>` to remove the runner from the GitLab server.  
   * It updates the remote `config.toml` to remove only the entry for the specified runner.  
4. **Update Registry:**  
   * If `unregister_gitlab_runner.yml` succeeds, the specific runner is removed from the runners list of the board in `runner_registry.yaml`, and the `runner_count` is decremeneted.  
   * If it fails, an error message is shown.

## **5. Error Handling Mechanism**

The application's error handling for Ansible playbook runs is managed by the `check_latest_failed_attempt(log_file)` function in `app.py`.

* **Read Log:** This function reads the relevant Ansible log file (e.g., `ansible-registration.log`).    
* **Extract error string:** It pulls out the error string embedded in the latest run in the log. This line contains detailed failure information, including the msg (Ansible's error message), rc (the command's return code), and importantly, stderr\_lines (the standard error output from the command, like gitlab-runner register).  

## **6. Deployment and Contribution**

To run this application:

1. **Clone the repository.**  
2. **Install Python dependencies:** `pip install Flask PyYAML requests`.  
3. **Install Ansible:** Make sure Ansible is installed and set up to connect to your RISC-V boards via SSH (e.g., SSH keys configured for the gitlab-runner-user on the boards).  
4. **Run the Flask app:** Execute `python start.py`.

For contributing:

* Follow the existing code structure and naming conventions.  
* Ensure all Ansible playbooks can be run multiple times without issues (idempotent).  
* Update the `runner_registry.yaml` schema documentation if you make changes.  