#!/usr/bin/env python3
"""
Module for automated monthly retrieval and processing of MITRE ATT&CK data.
Integrates with the mitreattack-python library to fetch the latest STIX data and convert it to a local knowledge base.
"""

import os
import sys
import logging
import json
from datetime import datetime
import requests

# Add the parent directory to the path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import VECTOR_DB_PATH, MITRE_ATTACK_CONFIG, LAST_UPDATE_FILE
from config.secrets import MITRE_ATTACK_URL, MITRE_ATTACK_USERNAME, MITRE_ATTACK_PASSWORD

# Set up logging
import os
from pathlib import Path

# Ensure log directory exists
log_dir = Path(__file__).parent.parent / 'logs'
log_dir.mkdir(exist_ok=True)
log_file = log_dir / 'mitre_attack_updater.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_file)),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('mitre_attack_updater')

def fetch_mitre_attack_data(domain="enterprise-attack", version="latest"):
    """
    Fetches MITRE ATT&CK data in STIX format. Can use TAXII server or direct download.
    Returns the STIX data as a MemoryStore.
    """
    try:
        # Method 1: Using mitreattack-python library (Recommended)
        try:
            from mitreattack.attackToExcel import attackToExcel
            logger.info(f"Fetching MITRE ATT&CK data for {domain} (Version: {version})")
            # get_stix_data returns a MemoryStore object
            stix_store = attackToExcel.get_stix_data(domain=domain, version=version)
            return stix_store
        
        # Fallback Method 2: Direct download from MITRE/CTI GitHub repository
        except (ImportError, AttributeError) as e:
            logger.warning(f"mitreattack-python method failed: {e}. Using direct GitHub download.")
            github_url = f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json"
            response = requests.get(github_url)
            response.raise_for_status()  # Raise an exception for bad status codes
            return response.json()
    
    except Exception as e:
        logger.error(f"Failed to fetch MITRE ATT&CK data: {str(e)}")
        return None

def process_techniques_to_documents(stix_data):
    """
    Processes MITRE ATT&CK STIX data into document format for vector database.
    Extracts key information from each technique.
    """
    documents = []
    
    # Handle both MemoryStore and dict formats
    if hasattr(stix_data, 'query'):  # MemoryStore object
        # Query for attack-pattern objects (techniques)
        techniques = stix_data.query([{"type": "attack-pattern"}])
        items = techniques
    else:  # Dictionary format (fallback)
        items = stix_data.get('objects', [])
    
    for item in items:
        # Skip sub-techniques for now, focus on main techniques
        if hasattr(item, 'x_mitre_is_subtechnique') and item.x_mitre_is_subtechnique:
            continue
            
        # Get technique ID from external references
        technique_id = "N/A"
        if hasattr(item, 'external_references') and item.external_references:
            technique_id = item.external_references[0].get('external_id', 'N/A')
        
        # Create a structured text document for each technique
        doc_text = f"""
        MITRE ATT&CK Technique: {getattr(item, 'name', 'N/A')}
        ID: {technique_id}
        Description: {getattr(item, 'description', 'No description available')}
        
        Platform: {', '.join(getattr(item, 'x_mitre_platforms', []))}
        Permissions Required: {', '.join(getattr(item, 'x_mitre_permissions_required', []))}
        
        Detection: {getattr(item, 'x_mitre_detection', 'No detection information available')}
        
        Related Techniques: {len(getattr(item, 'relationships', []))} relationships found
        """
        
        # Add metadata for filtering
        metadata = {
            "technique_id": technique_id,
            "technique_name": getattr(item, 'name', 'N/A'),
            "mitre_domain": "enterprise-attack",
            "last_updated": datetime.now().isoformat()
        }
        
        documents.append({"page_content": doc_text, "metadata": metadata})
    
    return documents

def update_attack_knowledge_base():
    """
    Main function to update the MITRE ATT&CK knowledge base.
    Fetches latest data, processes it, and updates the vector database.
    """
    logger.info("Starting MITRE ATT&CK knowledge base update...")
    
    # Fetch the latest ATT&CK data
    stix_data = fetch_mitre_attack_data()
    
    if not stix_data:
        logger.error("Failed to fetch MITRE ATT&CK data. Update aborted.")
        return False
    
    # Process techniques into documents
    documents = process_techniques_to_documents(stix_data)
    logger.info(f"Processed {len(documents)} ATT&CK techniques")
    
    # Update vector database
    try:
        from langchain_community.embedders import HuggingFaceEmbeddings
        from langchain_community.vectorstores import Chroma
        
        embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",
            model_kwargs={'device': 'cpu'}
        )
        
        # Create or update vector database
        vector_db = Chroma.from_documents(
            documents=documents,
            embedding=embeddings,
            persist_directory=os.path.join(VECTOR_DB_PATH, MITRE_ATTACK_CONFIG['vector_db_subpath'])
        )
        
        vector_db.persist()
        logger.info(f"MITRE ATT&CK knowledge base updated successfully with {len(documents)} techniques")
        return True
        
    except Exception as e:
        logger.error(f"Failed to update vector database: {str(e)}")
        return False

def check_update_needed(last_update_file):
    """
    Checks if a monthly update is needed based on the last update timestamp.
    """
    if not os.path.exists(last_update_file):
        return True
    
    try:
        with open(last_update_file, 'r') as f:
            last_update = datetime.fromisoformat(f.read().strip())
        
        # Check if at least 30 days have passed
        return (datetime.now() - last_update).days >= MITRE_ATTACK_CONFIG['update_interval_days']
        
    except Exception as e:
        logger.warning(f"Error reading last update file: {str(e)}. Forcing update.")
        return True

def record_update_time(last_update_file):
    """
    Records the current time as the last successful update time.
    """
    try:
        with open(last_update_file, 'w') as f:
            f.write(datetime.now().isoformat())
    except Exception as e:
        logger.error(f"Failed to record update time: {str(e)}")

def main():
    """
    Main function to run the MITRE ATT&CK updater.
    """
    if check_update_needed(LAST_UPDATE_FILE):
        logger.info("Monthly update check passed. Updating MITRE ATT&CK data...")
        if update_attack_knowledge_base():
            record_update_time(LAST_UPDATE_FILE)
            logger.info("MITRE ATT&CK update process completed successfully")
        else:
            logger.error("MITRE ATT&CK update process failed")
    else:
        logger.info("Monthly update not yet due. Skipping.")
    
    return 0

if __name__ == "__main__":
    exit(main())