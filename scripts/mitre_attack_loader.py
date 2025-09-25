#!/usr/bin/env python3
"""
Script to fetch and process MITRE ATT&CK data from attack.mitre.org
and build a vector database for use as a secondary source of truth.
"""

import os
import sys
import json
import requests
import logging
from datetime import datetime
from pathlib import Path

# Add the parent directory to the path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import VECTOR_DB_PATH, MITRE_ATTACK_CONFIG
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain.schema import Document
from langchain_community.vectorstores.utils import filter_complex_metadata

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('mitre_loader')

class MITREAttackLoader:
    def __init__(self):
        self.base_url = "https://attack.mitre.org"
        self.stix_url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
        self.techniques = []
        self.tactics = []
        self.mitigations = []
        self.groups = []
        self.software = []
        
    def fetch_stix_data(self):
        """Fetch MITRE ATT&CK data from STIX format"""
        logger.info("Fetching MITRE ATT&CK STIX data...")
        try:
            response = requests.get(self.stix_url, timeout=60)
            response.raise_for_status()
            
            stix_data = response.json()
            objects = stix_data.get('objects', [])
            
            # Parse STIX objects by type
            for obj in objects:
                obj_type = obj.get('type', '')
                
                if obj_type == 'attack-pattern':  # Techniques
                    self.techniques.append(obj)
                elif obj_type == 'x-mitre-tactic':  # Tactics
                    self.tactics.append(obj)
                elif obj_type == 'course-of-action':  # Mitigations
                    self.mitigations.append(obj)
                elif obj_type == 'intrusion-set':  # Groups
                    self.groups.append(obj)
                elif obj_type == 'malware' or obj_type == 'tool':  # Software
                    self.software.append(obj)
            
            logger.info(f"Fetched {len(self.techniques)} techniques, {len(self.tactics)} tactics, {len(self.mitigations)} mitigations, {len(self.groups)} groups, {len(self.software)} software")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch STIX data: {str(e)}")
            return False
    
    def process_technique(self, technique):
        """Process a single technique into a document"""
        try:
            # Extract key information from STIX format
            technique_id = 'Unknown'
            for ext_ref in technique.get('external_references', []):
                if ext_ref.get('source_name') == 'mitre-attack':
                    technique_id = ext_ref.get('external_id', 'Unknown')
                    break
            
            name = technique.get('name', 'Unknown')
            description = technique.get('description', '')
            
            # Get tactic information from kill chain phases
            tactics = []
            for kill_chain_phase in technique.get('kill_chain_phases', []):
                if kill_chain_phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(kill_chain_phase.get('phase_name', ''))
            
            # Get mitigation information from relationships
            mitigations = []
            for relationship in technique.get('relationships', []):
                if relationship.get('relationship_type') == 'mitigated-by':
                    mitigations.append(relationship.get('target_ref', ''))
            
            # Get sub-techniques from relationships
            sub_techniques = []
            for relationship in technique.get('relationships', []):
                if relationship.get('relationship_type') == 'subtechnique-of':
                    sub_techniques.append(relationship.get('source_ref', ''))
            
            # Create comprehensive content
            content = f"""
MITRE ATT&CK Technique: {name}
Technique ID: {technique_id}
Description: {description}

Tactics: {', '.join(tactics) if tactics else 'None specified'}

Mitigations: {', '.join(mitigations) if mitigations else 'None specified'}

Sub-techniques: {', '.join(sub_techniques) if sub_techniques else 'None'}

Detection Recommendations:
- Monitor for indicators associated with {name}
- Implement detection rules for technique {technique_id}
- Consider mitigations: {', '.join(mitigations) if mitigations else 'Review available mitigations'}

Playbook Integration:
- Include {name} in relevant incident response playbooks
- Map to tactics: {', '.join(tactics) if tactics else 'Map to appropriate tactics'}
- Reference technique {technique_id} in detection procedures
"""
            
            return Document(
                page_content=content.strip(),
                metadata={
                    'type': 'technique',
                    'technique_id': technique_id,
                    'name': name,
                    'tactics': tactics,
                    'mitigations': mitigations,
                    'source': 'mitre_attack',
                    'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
                }
            )
        except Exception as e:
            logger.error(f"Error processing technique {technique.get('name', 'Unknown')}: {str(e)}")
            return None
    
    def process_tactic(self, tactic):
        """Process a single tactic into a document"""
        try:
            # Extract tactic ID from external references
            tactic_id = 'Unknown'
            for ext_ref in tactic.get('external_references', []):
                if ext_ref.get('source_name') == 'mitre-attack':
                    tactic_id = ext_ref.get('external_id', 'Unknown')
                    break
            
            name = tactic.get('name', 'Unknown')
            description = tactic.get('description', '')
            
            content = f"""
MITRE ATT&CK Tactic: {name}
Tactic ID: {tactic_id}
Description: {description}

Playbook Integration:
- Include {name} as a phase in incident response playbooks
- Map detection capabilities to tactic {tactic_id}
- Ensure coverage for all techniques under {name}
- Consider defensive strategies for {name} phase
"""
            
            return Document(
                page_content=content.strip(),
                metadata={
                    'type': 'tactic',
                    'tactic_id': tactic_id,
                    'name': name,
                    'source': 'mitre_attack',
                    'url': f"https://attack.mitre.org/tactics/{tactic_id}/"
                }
            )
        except Exception as e:
            logger.error(f"Error processing tactic {tactic.get('name', 'Unknown')}: {str(e)}")
            return None
    
    def process_mitigation(self, mitigation):
        """Process a single mitigation into a document"""
        try:
            # Extract mitigation ID from external references
            mitigation_id = 'Unknown'
            for ext_ref in mitigation.get('external_references', []):
                if ext_ref.get('source_name') == 'mitre-attack':
                    mitigation_id = ext_ref.get('external_id', 'Unknown')
                    break
            
            name = mitigation.get('name', 'Unknown')
            description = mitigation.get('description', '')
            
            content = f"""
MITRE ATT&CK Mitigation: {name}
Mitigation ID: {mitigation_id}
Description: {description}

Playbook Integration:
- Include {name} in prevention and detection playbooks
- Implement {name} as a defensive measure
- Reference mitigation {mitigation_id} in security procedures
- Consider {name} for relevant attack techniques
"""
            
            return Document(
                page_content=content.strip(),
                metadata={
                    'type': 'mitigation',
                    'mitigation_id': mitigation_id,
                    'name': name,
                    'source': 'mitre_attack',
                    'url': f"https://attack.mitre.org/mitigations/{mitigation_id}/"
                }
            )
        except Exception as e:
            logger.error(f"Error processing mitigation {mitigation.get('name', 'Unknown')}: {str(e)}")
            return None
    
    def process_groups(self, groups):
        """Process groups into documents"""
        documents = []
        for group in groups:
            try:
                group_id = group.get('external_references', [{}])[0].get('external_id', 'Unknown')
                name = group.get('name', 'Unknown')
                description = group.get('description', '')
                
                # Get associated techniques
                techniques = []
                for technique in group.get('techniques', []):
                    techniques.append(technique.get('name', ''))
                
                content = f"""
MITRE ATT&CK Group: {name}
Group ID: {group_id}
Description: {description}

Known Techniques: {', '.join(techniques) if techniques else 'None specified'}

Playbook Integration:
- Include {name} threat intelligence in playbooks
- Reference group {group_id} in threat hunting procedures
- Consider techniques: {', '.join(techniques) if techniques else 'Review group techniques'}
"""
                
                documents.append(Document(
                    page_content=content.strip(),
                    metadata={
                        'type': 'group',
                        'group_id': group_id,
                        'name': name,
                        'techniques': techniques,
                        'source': 'mitre_attack',
                        'url': f"https://attack.mitre.org/groups/{group_id}/"
                    }
                ))
            except Exception as e:
                logger.error(f"Error processing group {group.get('name', 'Unknown')}: {str(e)}")
                continue
        
        return documents
    
    def process_software(self, software):
        """Process software into documents"""
        documents = []
        for sw in software:
            try:
                software_id = sw.get('external_references', [{}])[0].get('external_id', 'Unknown')
                name = sw.get('name', 'Unknown')
                description = sw.get('description', '')
                
                # Get associated techniques
                techniques = []
                for technique in sw.get('techniques', []):
                    techniques.append(technique.get('name', ''))
                
                content = f"""
MITRE ATT&CK Software: {name}
Software ID: {software_id}
Description: {description}

Associated Techniques: {', '.join(techniques) if techniques else 'None specified'}

Playbook Integration:
- Include {name} in malware detection playbooks
- Reference software {software_id} in incident response
- Consider techniques: {', '.join(techniques) if techniques else 'Review software techniques'}
"""
                
                documents.append(Document(
                    page_content=content.strip(),
                    metadata={
                        'type': 'software',
                        'software_id': software_id,
                        'name': name,
                        'techniques': techniques,
                        'source': 'mitre_attack',
                        'url': f"https://attack.mitre.org/software/{software_id}/"
                    }
                ))
            except Exception as e:
                logger.error(f"Error processing software {sw.get('name', 'Unknown')}: {str(e)}")
                continue
        
        return documents
    
    def build_vector_database(self):
        """Build vector database from MITRE ATT&CK data"""
        logger.info("Building MITRE ATT&CK vector database...")
        
        try:
            # Create embeddings
            embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'}
            )
            
            # Process all data into documents
            documents = []
            
            # Process techniques
            for technique in self.techniques:
                doc = self.process_technique(technique)
                if doc:
                    documents.append(doc)
            
            # Process tactics
            for tactic in self.tactics:
                doc = self.process_tactic(tactic)
                if doc:
                    documents.append(doc)
            
            # Process mitigations
            for mitigation in self.mitigations:
                doc = self.process_mitigation(mitigation)
                if doc:
                    documents.append(doc)
            
            # Process groups
            documents.extend(self.process_groups(self.groups))
            
            # Process software
            documents.extend(self.process_software(self.software))
            
            logger.info(f"Processed {len(documents)} documents from MITRE ATT&CK")
            
            if not documents:
                logger.error("No documents to process")
                return False
            
            # Filter complex metadata to avoid Chroma issues
            filtered_documents = []
            for doc in documents:
                # Create a new document with filtered metadata
                filtered_metadata = {}
                for key, value in doc.metadata.items():
                    if isinstance(value, (str, int, float, bool)) or value is None:
                        filtered_metadata[key] = value
                    elif isinstance(value, list):
                        # Convert lists to comma-separated strings
                        filtered_metadata[key] = ', '.join(str(item) for item in value)
                    else:
                        # Convert other types to strings
                        filtered_metadata[key] = str(value)
                
                filtered_doc = Document(
                    page_content=doc.page_content,
                    metadata=filtered_metadata
                )
                filtered_documents.append(filtered_doc)
            
            logger.info(f"Filtered {len(filtered_documents)} documents for vector database")
            
            # Create vector store
            mitre_vector_db_path = os.path.join(VECTOR_DB_PATH, MITRE_ATTACK_CONFIG['vector_db_subpath'])
            os.makedirs(mitre_vector_db_path, exist_ok=True)
            
            vector_db = Chroma.from_documents(
                documents=filtered_documents,
                embedding=embeddings,
                persist_directory=mitre_vector_db_path
            )
            
            vector_db.persist()
            logger.info(f"MITRE ATT&CK vector database built and persisted to {mitre_vector_db_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error building MITRE ATT&CK vector database: {str(e)}")
            return False
    
    def save_raw_data(self):
        """Save raw MITRE ATT&CK data for reference"""
        try:
            data_dir = Path(__file__).parent.parent / 'data' / 'mitre_attack'
            data_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save each data type
            with open(data_dir / f'techniques_{timestamp}.json', 'w') as f:
                json.dump(self.techniques, f, indent=2)
            
            with open(data_dir / f'tactics_{timestamp}.json', 'w') as f:
                json.dump(self.tactics, f, indent=2)
            
            with open(data_dir / f'mitigations_{timestamp}.json', 'w') as f:
                json.dump(self.mitigations, f, indent=2)
            
            with open(data_dir / f'groups_{timestamp}.json', 'w') as f:
                json.dump(self.groups, f, indent=2)
            
            with open(data_dir / f'software_{timestamp}.json', 'w') as f:
                json.dump(self.software, f, indent=2)
            
            logger.info(f"Raw MITRE ATT&CK data saved to {data_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving raw data: {str(e)}")
            return False

def main():
    """Main function to load MITRE ATT&CK data"""
    loader = MITREAttackLoader()
    
    # Fetch STIX data
    if not loader.fetch_stix_data():
        logger.error("Failed to fetch MITRE ATT&CK STIX data")
        return 1
    
    # Save raw data
    loader.save_raw_data()
    
    # Build vector database
    if not loader.build_vector_database():
        logger.error("Failed to build MITRE ATT&CK vector database")
        return 1
    
    logger.info("MITRE ATT&CK data loading completed successfully")
    return 0

if __name__ == "__main__":
    exit(main())
