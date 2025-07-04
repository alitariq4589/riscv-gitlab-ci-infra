# Managing RISC-V compute machines as GitLab CI/CD runners

## What does this setup do

This infrastructure is for managing RISC-V boards as the GitLab runners. This setup works almost out of the box to:

- Set up the RISC-V boards with the infrastructure
- Registering RISC-V board as CI/CD compute machines in the GitLab projects
- Unregistering the boards as runners
- Removing the boards from this infrastructure


![GitLab RISC-V Management Infrastructure](static/flask_app_gitalb-riscv.drawio.png)

## Getting Started

### Pre-requisites

- The RISC-V boards which are to be added to this infrastructure have to be accessible through SSH private key with `root` (for installing packages and installing gitlab runner as systemd service) user and a new user called `gitlab-runner-user`
- The `gitlab-runner-user` should be added as a non-sudo user in the board
- `python3` should be installed on the board as well as on the machine running this flow as a system-wide package
- `pip` should be installed on the compute machine running this flow

```
sudo apt install python3 python3-pip
```

### Starting the webflow

Web flow can be started by executing the following commands.

```
git clone https://github.com/alitariq4589/riscv-gitlab-ci-infra.git
cd riscv-gitlab-ci-infra
pip install -r requirements.txt
./start.py
```

After running this command, the web UI can be accessible through web browser at `localhost:5000`.

## Contributing

We welcome any contribution to this flow. If you find any issues, feel free to create an issue.

Need to add a new feature? Create a PR

Be sure to read the complete [documentation of this infrastructure](/docs/)