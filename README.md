# Security_QA_Agent
A localized Agent to process Security Notable Events through a Quality assurance pipeline

![alt text](https://github.com/gdcorp-infosec/Security_QA_Agent/blob/main/data/soc_qa_flowchart.png)



Prerequisites

    Linux server with Python 3.11+

    Ollama installed with a local LLM (e.g., llama3:8b)

    Splunk instance with HTTP Event Collector (HEC) enabled

    Confluence instance with playbooks

    MITRE ATT&CK knowledge base (will be automatically downloaded)

Installation Steps
1. Create Directory Structure
bash

sudo mkdir -p /opt/soc_qa_agent/{config,scripts,data}
sudo chown $USER:$USER /opt/soc_qa_agent

2. Copy Files to Their Respective Locations

Copy all the provided files to their appropriate directories in /opt/soc_qa_agent/:

    Configuration files → /opt/soc_qa_agent/config/

    Python scripts → /opt/soc_qa_agent/scripts/

    Data files → /opt/soc_qa_agent/data/

3. Make Scripts Executable
bash

chmod +x /opt/soc_qa_agent/scripts/*.py
chmod +x /opt/soc_qa_agent/scripts/run_agent.sh

4. Set Up Environment Variables
bash

cp /opt/soc_qa_agent/.env.template /opt/soc_qa_agent/.env
# Edit the .env file with your actual settings

5. Configure Secrets
bash

cp /opt/soc_qa_agent/config/secrets.py.template /opt/soc_qa_agent/config/secrets.py
# Edit the secrets.py file with your actual credentials

6. Install Dependencies
bash

pip install -r /opt/soc_qa_agent/requirements.txt

7. Build Knowledge Bases
bash

cd /opt/soc_qa_agent
python3 scripts/confluence_to_vector_db.py
python3 scripts/mitre_attack_updater.py

8. Set Up Cron Jobs
bash

crontab -e

Add the following lines to the crontab:
bash

# Run QA agent hourly
0 * * * * /opt/soc_qa_agent/scripts/run_agent.sh

# Update MITRE ATT&CK knowledge base monthly
0 2 1 * * /usr/bin/python3 /opt/soc_qa_agent/scripts/mitre_attack_updater.py >> /var/log/mitre_attack_updater.log 2>&1

9. Test the Installation
bash

python3 /opt/soc_qa_agent/scripts/soc_qa_agent.py

Verification

Check the log files to verify proper operation:

    /var/log/soc_qa_agent.log - Main agent logs

    /var/log/mitre_attack_updater.log - MITRE update logs

Troubleshooting

If you encounter issues:

    Verify all credentials in .env and config/secrets.py are correct

    Check that Ollama is running and the specified model is available

    Ensure Splunk HEC is properly configured and accessible

    Confirm Confluence API access is working

Maintenance

    Regularly check log files for errors

    Update the MITRE ATT&CK knowledge base monthly (automated via cron)

    Review and update playbooks in Confluence as needed

    Monitor Splunk index usage for QA reports
