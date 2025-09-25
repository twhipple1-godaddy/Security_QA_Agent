# 🚀 Security QA Agent - Amazon Linux EC2 Deployment Guide

This guide provides step-by-step instructions for deploying the Security QA Agent on an AWS EC2 instance running Amazon Linux 2023.

## Prerequisites

- AWS Account with EC2 access
- SSH key pair for EC2 access
- Splunk instance with HTTP Event Collector (HEC) enabled
- Confluence instance with playbooks
- Basic knowledge of Linux command line

## 1. Launch EC2 Instance

### Instance Specifications
- **OS**: Amazon Linux 2023 (recommended) or Amazon Linux 2
- **Instance Type**: `t3.medium` or larger (recommended: `t3.large` for better performance)
- **Storage**: 20-30 GB EBS volume
- **Security Group**: Allow SSH (port 22) and HTTP (port 8080) if needed

### Launch Command
```bash
# For Amazon Linux 2023
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d3f9 \
  --instance-type t3.large \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxxxxx \
  --subnet-id subnet-xxxxxxxxx \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=Security-QA-Agent}]'
```

## 2. Connect and Prepare the Instance

```bash
# Connect to your instance
ssh -i your-key.pem ec2-user@your-ec2-ip

# Update system
sudo dnf update -y

# Install required system packages
sudo dnf install -y python3 python3-pip python3-venv git curl wget unzip gcc gcc-c++ make
```

## 3. Install Ollama

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Start Ollama service
sudo systemctl start ollama
sudo systemctl enable ollama

# Pull the required model
ollama pull llama3:8b

# Verify installation
ollama list
```

## 4. Deploy the Security QA Agent

### Option A: Using GitHub with SAML Authentication (Recommended for Enterprise)

```bash
# Create application directory
sudo mkdir -p /opt/soc_qa_agent
sudo chown ec2-user:ec2-user /opt/soc_qa_agent
cd /opt/soc_qa_agent

# Install GitHub CLI for SAML authentication (Amazon Linux method)
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(uname -m) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/yum.repos.d/github-cli.repo > /dev/null
sudo dnf install -y gh

# Alternative: Install from GitHub releases (if repo method fails)
# wget https://github.com/cli/cli/releases/latest/download/gh_*_linux_amd64.tar.gz
# tar -xzf gh_*_linux_amd64.tar.gz
# sudo cp gh_*/bin/gh /usr/local/bin/

# Authenticate with GitHub using SAML
gh auth login --web --scopes repo,read:org

# Clone the repository using GitHub CLI (handles SAML authentication)
gh repo clone your-organization/Security_QA_Agent .

# Verify the clone was successful
ls -la
```

### Option B: Using Personal Access Token (Alternative)

```bash
# Create application directory
sudo mkdir -p /opt/soc_qa_agent
sudo chown ec2-user:ec2-user /opt/soc_qa_agent
cd /opt/soc_qa_agent

# Clone using personal access token
git clone https://your-token@github.com/your-organization/Security_QA_Agent.git .

# Or set up Git credentials for the session
git config --global credential.helper store
echo "https://your-username:your-token@github.com" > ~/.git-credentials
git clone https://github.com/your-organization/Security_QA_Agent.git .
```

### Option C: Using SSH Key Authentication

```bash
# Create application directory
sudo mkdir -p /opt/soc_qa_agent
sudo chown ec2-user:ec2-user /opt/soc_qa_agent
cd /opt/soc_qa_agent

# Generate SSH key for GitHub (if not already done)
ssh-keygen -t ed25519 -C "ec2-user@your-instance" -f ~/.ssh/github_key

# Add SSH key to GitHub (copy the public key)
cat ~/.ssh/github_key.pub

# Configure SSH for GitHub
echo "Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/github_key
    IdentitiesOnly yes" >> ~/.ssh/config

# Test SSH connection
ssh -T git@github.com

# Clone using SSH
git clone git@github.com:your-organization/Security_QA_Agent.git .
```

### Option D: Manual Upload (Fallback)

```bash
# Create application directory
sudo mkdir -p /opt/soc_qa_agent
sudo chown ec2-user:ec2-user /opt/soc_qa_agent
cd /opt/soc_qa_agent

# Upload files via SCP from your local machine
# scp -i your-key.pem -r /path/to/Security_QA_Agent/* ec2-user@your-ec2-ip:/opt/soc_qa_agent/

# Or create a zip file and upload
# zip -r Security_QA_Agent.zip /path/to/Security_QA_Agent/
# scp -i your-key.pem Security_QA_Agent.zip ec2-user@your-ec2-ip:/tmp/
# ssh -i your-key.pem ec2-user@your-ec2-ip "cd /opt/soc_qa_agent && unzip /tmp/Security_QA_Agent.zip && mv Security_QA_Agent/* . && rmdir Security_QA_Agent"
```

### Verify Deployment

```bash
# Check that all files are present
ls -la /opt/soc_qa_agent/

# Verify the structure
tree /opt/soc_qa_agent/ || find /opt/soc_qa_agent/ -type f -name "*.py" | head -10

# Check file permissions
ls -la /opt/soc_qa_agent/scripts/
```

### Enterprise SAML Configuration Notes

If your organization uses SAML SSO with GitHub:

1. **SAML Authentication**: The GitHub CLI will prompt you to authenticate via your organization's SAML provider
2. **Token Management**: SAML tokens may have shorter lifespans - consider setting up automated renewal
3. **Organization Access**: Ensure your GitHub account has access to the repository through your organization's SAML SSO
4. **Repository Permissions**: Verify you have `read` access to the repository and any required organization resources

### Troubleshooting GitHub Authentication

```bash
# Check GitHub CLI authentication status
gh auth status

# Re-authenticate if needed
gh auth login --web --scopes repo,read:org

# Test repository access
gh repo view your-organization/Security_QA_Agent

# Check available repositories
gh repo list your-organization
```

## 5. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "import langchain, chromadb, ollama; print('Dependencies OK')"
```

## 6. Configure the Application

```bash
# Create configuration files
cp config/secrets.py.template config/secrets.py
cp .env.template .env

# Edit configuration files
nano config/secrets.py
nano .env
```

### Update `config/secrets.py`:
```python
# Splunk HEC Configuration
SPLUNK_HEC_TOKEN = "your-actual-splunk-hec-token"

# Confluence Configuration  
CONFLUENCE_USERNAME = "your-confluence-username"
CONFLUENCE_TOKEN = "your-confluence-token"

# MITRE ATT&CK Configuration
MITRE_ATTACK_URL = "https://cti-taxii.mitre.org/taxii/"
MITRE_ATTACK_USERNAME = "your-username"
MITRE_ATTACK_PASSWORD = "your-password"
```

### Update `.env`:
```bash
# Splunk HEC Configuration
SPLUNK_HEC_URL=https://your-splunk-server:8088
SPLUNK_QA_INDEX=qa_reports
SPLUNK_HEC_SSL_VERIFY=True

# Confluence Configuration
CONFLUENCE_URL=https://your-confluence.instance
CONFLUENCE_SPACE_KEY=SOC

# LLM Configuration
LLM_MODEL=llama3:8b
LLM_TEMPERATURE=0.1
LLM_TIMEOUT=120

# MITRE ATT&CK Configuration
MITRE_DOMAIN=enterprise-attack
MITRE_VERSION=latest
MITRE_UPDATE_INTERVAL=30

# Paths
VECTOR_DB_PATH=/opt/soc_qa_agent/vector_db
LOG_PATH=/var/log/soc_qa_agent.log
LAST_UPDATE_FILE=/opt/soc_qa_agent/last_mitre_update.txt
```

## 7. Set Up Logging and Directories

```bash
# Create log directory
sudo mkdir -p /var/log
sudo touch /var/log/soc_qa_agent.log
sudo touch /var/log/mitre_attack_updater.log
sudo chown ec2-user:ec2-user /var/log/soc_qa_agent.log
sudo chown ec2-user:ec2-user /var/log/mitre_attack_updater.log

# Create vector database directory
mkdir -p vector_db

# Make scripts executable
chmod +x scripts/*.py
chmod +x runagent.sh
```

## 8. Test the Installation

```bash
# Test basic functionality
cd /opt/soc_qa_agent
source venv/bin/activate
python3 scripts/soc_qa_agent.py

# Test MITRE updater
python3 scripts/mitre_attack_updater.py

# Test Confluence integration
python3 scripts/confluence_to_vector_db.py
```

## 9. Set Up System Service (Optional)

Create a systemd service for automatic startup:

```bash
# Create service file
sudo nano /etc/systemd/system/soc-qa-agent.service
```

### Service file content:
```ini
[Unit]
Description=Security QA Agent
After=network.target ollama.service

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/soc_qa_agent
Environment=PATH=/opt/soc_qa_agent/venv/bin
ExecStart=/opt/soc_qa_agent/venv/bin/python3 scripts/soc_qa_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Enable and start service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable soc-qa-agent
sudo systemctl start soc-qa-agent
sudo systemctl status soc-qa-agent
```

## 10. Set Up Cron Jobs

```bash
# Edit crontab
crontab -e

# Add these lines:
# Run QA agent every hour
0 * * * * /opt/soc_qa_agent/runagent.sh

# Update MITRE ATT&CK knowledge base monthly
0 2 1 * * /opt/soc_qa_agent/venv/bin/python3 /opt/soc_qa_agent/scripts/mitre_attack_updater.py >> /var/log/mitre_attack_updater.log 2>&1
```

## 11. Security Considerations

```bash
# Set proper file permissions
chmod 600 config/secrets.py
chmod 600 .env

# Create a non-root user for running the service
sudo useradd -r -s /bin/false socqa
sudo chown -R socqa:socqa /opt/soc_qa_agent
```

## 12. Monitoring and Logs

```bash
# View logs
tail -f /var/log/soc_qa_agent.log
tail -f /var/log/mitre_attack_updater.log

# Check service status
sudo systemctl status soc-qa-agent
sudo systemctl status ollama

# Monitor resource usage
htop
df -h
```

## 13. Amazon Linux Specific Considerations

### SELinux Configuration
```bash
# Check SELinux status
sestatus

# If SELinux is enforcing, you may need to set contexts
sudo setsebool -P httpd_can_network_connect 1
sudo chcon -R -t bin_t /opt/soc_qa_agent/venv/bin/python3
```

### Firewall Configuration (if using firewalld)
```bash
# Check firewall status
sudo systemctl status firewalld

# If firewalld is running, allow Ollama port
sudo firewall-cmd --permanent --add-port=11434/tcp
sudo firewall-cmd --reload
```

### Amazon Linux Package Management
```bash
# Check available Python versions
dnf list available | grep python3

# Install additional development tools if needed
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y python3-devel
```

## 14. Troubleshooting Commands

```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Test model availability
ollama list

# Check Python environment
source venv/bin/activate
python3 -c "import ollama; print(ollama.list())"

# Test configuration
python3 -c "from config import *; print('Config OK')"

# Check disk space
df -h

# Check memory usage
free -h

# Check system logs
sudo journalctl -u ollama
sudo journalctl -u soc-qa-agent

# Check if services are enabled
sudo systemctl is-enabled ollama
sudo systemctl is-enabled soc-qa-agent
```

## 15. Backup and Maintenance

### Create backup script
```bash
nano /opt/soc_qa_agent/backup.sh
```

### Backup script content:
```bash
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/soc_qa_agent"
mkdir -p $BACKUP_DIR

# Backup configuration and data
tar -czf $BACKUP_DIR/soc_qa_agent_$DATE.tar.gz \
  /opt/soc_qa_agent/config \
  /opt/soc_qa_agent/vector_db \
  /opt/soc_qa_agent/logs

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

### Make backup script executable:
```bash
chmod +x /opt/soc_qa_agent/backup.sh
```

## 16. Expected Costs

- **EC2 t3.large**: ~$60-80/month
- **EBS Storage (30GB)**: ~$3-5/month
- **Data Transfer**: Minimal for this use case
- **Total**: ~$65-85/month

## 17. Quick Start Commands

```bash
# One-liner to test everything
cd /opt/soc_qa_agent && source venv/bin/activate && python3 scripts/soc_qa_agent.py

# Check if everything is working
curl http://localhost:11434/api/tags && echo "Ollama OK" || echo "Ollama not running"

# Amazon Linux specific health check
sudo systemctl status ollama && echo "Ollama service OK" || echo "Ollama service not running"
```

## 18. Production Checklist

- [ ] EC2 instance launched with appropriate security groups
- [ ] Amazon Linux 2023 instance configured
- [ ] Ollama installed and model downloaded
- [ ] Application deployed and configured
- [ ] Secrets and environment variables set
- [ ] Logging directories created with proper permissions
- [ ] SELinux configured (if applicable)
- [ ] Firewall rules configured (if using firewalld)
- [ ] System service configured (optional)
- [ ] Cron jobs set up for automation
- [ ] Backup script created and tested
- [ ] Monitoring and alerting configured
- [ ] Security hardening applied

## 19. Support and Troubleshooting

### Common Issues

1. **Ollama not starting**: Check if port 11434 is available and Ollama service is running
2. **Permission denied**: Ensure proper file ownership and permissions (ec2-user:ec2-user)
3. **Import errors**: Verify Python virtual environment is activated
4. **Memory issues**: Consider upgrading to a larger instance type
5. **Disk space**: Monitor EBS volume usage and clean up old logs
6. **SELinux issues**: Check SELinux status and configure contexts if needed
7. **Firewall blocking**: Ensure Ollama port 11434 is open in security groups and local firewall
8. **Python compilation errors**: Install development tools and Python headers

### Getting Help

- Check logs in `/var/log/soc_qa_agent.log`
- Verify configuration in `config/secrets.py` and `.env`
- Test individual components using the troubleshooting commands
- Ensure all dependencies are installed correctly

## 20. Amazon Linux Optimizations

### Performance Tuning
```bash
# Optimize for AI workloads
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Set CPU governor to performance (if needed)
echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

### Memory Management
```bash
# Check memory usage
free -h
cat /proc/meminfo

# Monitor Ollama memory usage
ps aux | grep ollama
```

### Storage Optimization
```bash
# Check disk I/O
iostat -x 1

# Monitor vector database size
du -sh /opt/soc_qa_agent/vector_db/
```

## 21. Alternative Deployment Methods

### Using AWS Systems Manager
```bash
# Install AWS CLI and SSM agent (usually pre-installed on Amazon Linux)
sudo dnf install -y awscli

# Use SSM to run commands remotely
aws ssm send-command \
  --instance-ids i-1234567890abcdef0 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["cd /opt/soc_qa_agent && source venv/bin/activate && python3 scripts/soc_qa_agent.py"]'
```

### Using CloudFormation
Consider creating a CloudFormation template for repeatable deployments with all the necessary IAM roles, security groups, and instance configurations.

---

This deployment guide will give you a fully functional Security QA Agent running on Amazon Linux EC2 with proper logging, monitoring, and automated maintenance!
