import sys
import os
import subprocess
import yaml

current_pwd = os.path.dirname(os.path.abspath(__file__))
inventory_path = os.path.join(current_pwd, '../ansible/inventory.ini')


def read_inventory(inventory_path):
    """
    Reads the inventory.ini file and extracts host information.
    This function currently just checks for host existence.
    For more complex parsing (groups, variables), consider using
    Ansible's inventory parsing capabilities or a more robust parser.
    """
    
    
    
    hosts = set()
    try:
        with open(inventory_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('['):
                    host_name = line.split()[0]
                    hosts.add(host_name)
    except FileNotFoundError:
        print(f"Error: Inventory file not found at {inventory_path}")
        sys.exit(1)
    return hosts

def run_ansible_playbook(target_node, playbook_path, extra_vars):
    """
    Executes the Ansible playbook using the ansible-playbook command.
    """
    cmd = [
        'ansible-playbook',
        playbook_path,
        '-i', 'inventory.ini', # Assuming inventory.ini is in the same directory
        '-e', f'target_node={target_node}'
    ]
    
    # Add extra variables from the dictionary
    for key, value in extra_vars.items():
        cmd.extend(['-e', f'{key}={value}'])

    print(f"\nRunning Ansible command: {' '.join(cmd)}")
    try:
        process = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("\nAnsible Playbook Output:\n")
        print(process.stdout)
        if process.stderr:
            print("\nAnsible Playbook Errors (if any):\n")
            print(process.stderr)
        print(f"\nAnsible playbook for '{target_node}' completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"\nError running Ansible playbook for '{target_node}':")
        print(f"Command: {e.cmd}")
        print(f"Return Code: {e.returncode}")
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: 'ansible-playbook' command not found. Please ensure Ansible is installed and in your PATH.")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 setup_board.py <host_or_group_name>")
        sys.exit(1)

    target = sys.argv[1]
    inventory_file = 'inventory.ini'
    playbook_file = 'runner_registration.yml'

    # --- Configuration for GitLab Runner Registration ---
    # IMPORTANT: Replace these with your actual values or retrieve them securely.
    gitlab_url = "https://your-gitlab-instance.com" # e.g., "https://gitlab.com"
    registration_token = "YOUR_REGISTRATION_TOKEN" # Get this from your GitLab project/group CI/CD settings
    runner_name = f"gitlab-runner-{target}" # Example: dynamic runner name

    extra_vars = {
        "gitlab_url": gitlab_url,
        "registration_token": registration_token,
        "runner_name": runner_name,
    }
    # ----------------------------------------------------

    # Verify if the target exists in the inventory (basic check)
    # For robust group/host checking, a more advanced Ansible inventory parser is needed.
    # Here, we just check if the target name exists as a host.
    available_hosts = read_inventory(inventory_file)
    if target not in available_hosts:
        print(f"Warning: '{target}' not explicitly found as a host in '{inventory_file}'.")
        print("Ansible might still resolve it if it's a group or pattern, but explicit host names are recommended.")
        # Decide if you want to exit here or proceed based on your requirements
        # sys.exit(1) 

    if not os.path.exists(playbook_file):
        print(f"Error: Playbook file not found at {playbook_file}")
        sys.exit(1)

    run_ansible_playbook(target, playbook_file, extra_vars)