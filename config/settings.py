import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Splunk HEC Configuration
SPLUNK_CONFIG = {
    'hec_url': os.getenv('SPLUNK_HEC_URL', 'https://http-inputs-godaddy.splunkcloud.com/services/collector/event'),
    'index': os.getenv('SPLUNK_QA_INDEX', 'qa_bot'),
    'hec_ssl_verify': os.getenv('SPLUNK_HEC_SSL_VERIFY', 'True').lower() in ('true', '1', 'yes')
}

# Confluence Configuration
CONFLUENCE_CONFIG = {
    'url': os.getenv('CONFLUENCE_URL'),
    'space_key': os.getenv('CONFLUENCE_SPACE_KEY', 'SOC')
}

# LLM Configuration
LLM_CONFIG = {
    'model': os.getenv('LLM_MODEL', 'llama3:8b'),
    'temperature': float(os.getenv('LLM_TEMPERATURE', 0.1)),
    'timeout': int(os.getenv('LLM_TIMEOUT', 120))
}

# MITRE ATT&CK Configuration
MITRE_ATTACK_CONFIG = {
    'domain': os.getenv('MITRE_DOMAIN', 'enterprise-attack'),
    'version': os.getenv('MITRE_VERSION', 'latest'),
    'update_interval_days': int(os.getenv('MITRE_UPDATE_INTERVAL', 30)),
    'vector_db_subpath': 'mitre_attack'
}

# Paths
VECTOR_DB_PATH = os.getenv('VECTOR_DB_PATH', str(BASE_DIR / 'vector_db'))
LOG_PATH = os.getenv('LOG_PATH', str(BASE_DIR / 'logs' / 'soc_qa_agent.log'))
LAST_UPDATE_FILE = os.getenv('LAST_UPDATE_FILE', str(BASE_DIR / 'last_mitre_update.txt'))

# Query Templates
SPLUNK_QUERIES = {
    'closed_incidents': '''
        | `incident_review` 
        | search status="closed" 
        | fields incident_id, title, analyst, owner, status
        | head 10
    ''',
    'notable_details': '''
        | `notable` 
        | where incident_id="{incident_id}" 
        | fields *
    ''',
    'audit_log': '''
        | `audit` 
        | search incident_id="{incident_id}" 
        | sort by _time 
        | fields user, action, comment, _time
    '''
}