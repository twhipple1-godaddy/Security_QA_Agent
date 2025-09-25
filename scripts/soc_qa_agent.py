#!/usr/bin/env python3
"""
Main SOC QA Agent that reviews closed incidents and generates QA reports.
Designed to run on a schedule (e.g., via cron).
"""

import os
import sys
import logging
import json
import time
import socket
import requests
from typing import Optional
from datetime import datetime

# Add the parent directory to the path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from config package
from config import SPLUNK_CONFIG, CONFLUENCE_CONFIG, LLM_CONFIG, SPLUNK_QUERIES, VECTOR_DB_PATH, MITRE_ATTACK_CONFIG
from config.secrets import SPLUNK_HEC_TOKEN, SPLUNK_SEARCH_TOKEN

from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_ollama import ChatOllama
from langchain.prompts import ChatPromptTemplate
from langchain.schema.output_parser import StrOutputParser
from scripts.splunk_query import build_notable_query, DEFAULT_EARLIEST, DEFAULT_LATEST

# Set up logging
import os
from pathlib import Path

# Ensure log directory exists
log_dir = Path(__file__).parent.parent / 'logs'
log_dir.mkdir(exist_ok=True)
log_file = log_dir / 'soc_qa_agent.log'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_file)),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('soc_qa_agent')

class SOCQAAgent:
    def __init__(self):
        self.splunk_service = None
        self.vector_db = None
        self.llm = None
        self.prompt_template = None
        self.setup_clients()
        self.load_prompt_template()
        
    def setup_clients(self):
        """Initialize connections to Splunk and local services"""
        try:
            # Validate configuration
            self._validate_config()
            
            # Load vector database
            embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'}
            )
            self.vector_db = Chroma(
                persist_directory=VECTOR_DB_PATH,
                embedding_function=embeddings
            )
            logger.info("Vector database loaded")
            
            # Initialize local LLM and request JSON-formatted outputs when possible
            self.llm = ChatOllama(
                model=LLM_CONFIG['model'],
                temperature=LLM_CONFIG['temperature'],
                timeout=LLM_CONFIG['timeout'],
                format="json"
            )
            logger.info(f"Local LLM initialized: {LLM_CONFIG['model']}")
            
        except Exception as e:
            logger.error(f"Error setting up clients: {str(e)}")
            raise
    
    def _validate_config(self):
        """Validate required configuration values"""
        required_configs = [
            ('VECTOR_DB_PATH', VECTOR_DB_PATH),
            ('LLM_CONFIG', LLM_CONFIG),
            ('SPLUNK_CONFIG', SPLUNK_CONFIG)
        ]
        
        for name, config in required_configs:
            if not config:
                raise ValueError(f"Required configuration {name} is missing or empty")
        
        # Check if vector DB directory exists or can be created
        vector_db_path = Path(VECTOR_DB_PATH)
        if not vector_db_path.exists():
            try:
                vector_db_path.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created vector database directory: {vector_db_path}")
            except Exception as e:
                raise ValueError(f"Cannot create vector database directory {vector_db_path}: {e}")
        
        # Validate LLM configuration
        if not LLM_CONFIG.get('model'):
            raise ValueError("LLM model not specified in configuration")
        
        logger.info("Configuration validation passed")
    
    def load_prompt_template(self):
        """Load the prompt template from an external file"""
        try:
            prompt_file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'prompt.txt')
            with open(prompt_file_path, 'r') as file:
                self.prompt_template = ChatPromptTemplate.from_template(file.read())
            logger.info("Prompt template loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load prompt template: {str(e)}")
            # Fallback to a default prompt
            self.prompt_template = ChatPromptTemplate.from_template("""
            You are a senior SOC analyst performing quality assurance review.

            INCIDENT: {title}
            ANALYST: {analyst}
            INCIDENT_ID: {incident_id}

            RAW NOTABLE DATA:
            {notable_data}

            ANALYST ACTION TIMELINE:
            {audit_data}

            OFFICIAL SOC PLAYBOOK:
            {playbook_text}

            MITRE ATT&CK CONTEXT:
            {mitre_context}

            Compare the analyst's actions against the official playbook and MITRE ATT&CK context.
            Provide a comprehensive QA report with:
            1. Accuracy score (1-5): Was the final classification correct?
            2. Procedure score (1-5): Were all playbook steps followed?
            3. Documentation score (1-5): Are the notes clear and complete?
            4. List any missed steps or incorrect actions
            5. Identify if escalation was required but not performed
             6. Overall assessment and recommendations

            Format your response as valid JSON with this structure:
            {{
                "event_id": "incident_id",
                "analyst": "analyst_name",
                "scores": {{
                    "accuracy": 0,
                    "procedure": 0,
                    "documentation": 0
                }},
                "missed_steps": [],
                "escalation_required": false,
                "summary": "brief summary",
                "recommendations": []
            }}
            """)
            logger.info("Using fallback prompt template")
    
    def execute_splunk_search(self, search_query):
        """Execute a Splunk search via REST API export endpoint and return a list of result dicts"""
        try:
            # Determine Splunk management API URL (default to :8089 if HEC is :8088)
            hec_url = SPLUNK_CONFIG.get('hec_url', 'https://localhost:8088')
            default_api_url = hec_url.replace(':8088', ':8089') if ':8088' in hec_url else 'https://localhost:8089'
            api_url = os.getenv('SPLUNK_API_URL', default_api_url).rstrip('/')

            headers = {
                "Authorization": f"Bearer {SPLUNK_SEARCH_TOKEN}"
            }

            # Ensure the query has the proper 'search' prefix
            search_str = search_query.strip()
            if not (search_str.startswith('search ') or search_str.startswith('|')):
                search_str = f"search {search_str}"

            verify_ssl = SPLUNK_CONFIG.get('hec_ssl_verify', True)

            # Use export endpoint (streams results immediately)
            # Support ES app namespace so ES macros (e.g., `notable`) resolve
            # Set SPLUNK_API_NAMESPACE to something like: servicesNS/nobody/SplunkEnterpriseSecuritySuite
            namespace = os.getenv('SPLUNK_API_NAMESPACE', '').strip('/ ')
            export_base = f"{api_url}/services/search/jobs/export" if not namespace else f"{api_url}/{namespace}/search/jobs/export"
            export_url = export_base
            data = {
                'search': search_str,
                'output_mode': 'json'
            }
            r = requests.post(export_url, headers=headers, data=data, stream=True, verify=verify_ssl)
            if r.status_code != 200:
                logger.error(f"Failed to export Splunk search results: {r.status_code} - {r.text}")
                return []

            results = []
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    # Some lines might be keepalive or partial; skip quietly
                    continue
                # export returns lines with keys like 'result' and metadata keys
                if isinstance(obj, dict):
                    if 'result' in obj and isinstance(obj['result'], dict):
                        results.append(obj['result'])
                    elif 'results' in obj and isinstance(obj['results'], list):
                        results.extend(obj['results'])
            return results

        except Exception as e:
            logger.error(f"Splunk search failed: {str(e)}")
<<<<<<< HEAD
        return []
=======
            return []
>>>>>>> 01b0fb7 (major update 13)
    
    def retrieve_playbook(self, alert_title):
        """Retrieve relevant playbook sections for the alert"""
        try:
            relevant_docs = self.vector_db.similarity_search(
                f"SOC playbook for {alert_title}", k=3
            )
            if not relevant_docs:
                return "No playbook found"
            
            # Extract playbook titles from metadata or content
            playbook_titles = []
            playbook_content = []
            
            for doc in relevant_docs:
                content = doc.page_content
                playbook_content.append(content)
                
                # Try to extract title from metadata first
                if hasattr(doc, 'metadata') and 'title' in doc.metadata:
                    playbook_titles.append(doc.metadata['title'])
                else:
                    # Extract title from content (look for common patterns)
                    lines = content.split('\n')
                    for line in lines[:5]:  # Check first 5 lines
                        line = line.strip()
                        if line and len(line) < 100 and not line.startswith(('1.', '2.', '3.', '4.', '5.')):
                            # Likely a title if it's short and doesn't start with numbers
                            playbook_titles.append(line)
                            break
            
            # Combine content and add titles for context
            full_content = "\n".join(playbook_content)
            if playbook_titles:
                titles_section = f"AVAILABLE PLAYBOOK TITLES: {', '.join(set(playbook_titles))}\n\n"
                return titles_section + full_content
            else:
                return full_content
                
        except Exception as e:
            logger.error(f"Playbook retrieval failed: {str(e)}")
            return "No playbook found"
    
    def retrieve_mitre_context(self, technique_ids, alert_title: Optional[str] = None):
        """
        Retrieve MITRE ATT&CK context for specific technique IDs.

        If no techniques are provided or no results are found for the given
        techniques, this method will fall back to a similarity search using the
        alert title (when available) to retrieve relevant MITRE context.
        """
        try:
            from langchain_community.embeddings import HuggingFaceEmbeddings
            from langchain_community.vectorstores import Chroma
            
            # Load MITRE ATT&CK vector database
            mitre_embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'}
            )
            
            mitre_vector_db = Chroma(
                persist_directory=os.path.join(VECTOR_DB_PATH, MITRE_ATTACK_CONFIG['vector_db_subpath']),
                embedding_function=mitre_embeddings
            )
            
            # Search for each technique
            collected_sections: list[str] = []
            for technique_id in technique_ids or []:
                results = mitre_vector_db.similarity_search(
                    f"MITRE technique {technique_id}", k=1
                )
                if results:
                    collected_sections.append(results[0].page_content)

            # Fallback: if nothing found via technique IDs, try alert title
            if not collected_sections and alert_title:
                title_results = mitre_vector_db.similarity_search(
                    f"{alert_title} relevant MITRE ATT&CK technique mitigation tactic", k=2
                )
                for r in title_results:
                    collected_sections.append(r.page_content)

            if collected_sections:
                return "\n\n".join(collected_sections)
            
            return "No MITRE ATT&CK context found."
        
        except Exception as e:
            logger.error(f"Failed to retrieve MITRE context: {str(e)}")
            return "Error retrieving MITRE ATT&CK context."
    
    def retrieve_mitre_recommendations(self, alert_title, notable_data):
        """
        Retrieve MITRE ATT&CK-based recommendations for playbook improvements.
        """
        try:
            from langchain_community.embeddings import HuggingFaceEmbeddings
            from langchain_community.vectorstores import Chroma
            
            # Load MITRE ATT&CK vector database
            mitre_embeddings = HuggingFaceEmbeddings(
                model_name="all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'}
            )
            
            mitre_vector_db = Chroma(
                persist_directory=os.path.join(VECTOR_DB_PATH, MITRE_ATTACK_CONFIG['vector_db_subpath']),
                embedding_function=mitre_embeddings
            )
            
            # Search for relevant techniques, tactics, and mitigations
            search_queries = [
                f"playbook recommendations for {alert_title}",
                f"mitigation strategies for {alert_title}",
                f"detection techniques for {alert_title}",
                "incident response playbook improvements",
                "security procedure enhancements"
            ]
            
            recommendations = []
            for query in search_queries:
                results = mitre_vector_db.similarity_search(query, k=2)
                for result in results:
                    if result.metadata.get('type') in ['technique', 'mitigation', 'tactic']:
                        recommendations.append({
                            'type': result.metadata.get('type'),
                            'name': result.metadata.get('name'),
                            'id': result.metadata.get('technique_id') or result.metadata.get('mitigation_id') or result.metadata.get('tactic_id'),
                            'content': result.page_content,
                            'url': result.metadata.get('url')
                        })
            
            # Remove duplicates based on ID
            seen_ids = set()
            unique_recommendations = []
            for rec in recommendations:
                if rec['id'] not in seen_ids:
                    unique_recommendations.append(rec)
                    seen_ids.add(rec['id'])
            
            return unique_recommendations[:5]  # Limit to top 5 recommendations
        
        except Exception as e:
            logger.error(f"Failed to retrieve MITRE recommendations: {str(e)}")
            return []
    
    def extract_mitre_techniques(self, notable_data):
        """
        Extract MITRE technique IDs and context from annotation_mitre_* fields in notable event data.
        """
        mitre_context = []
        techniques = []
        
        try:
            # Process each event in notable_data
            for event in notable_data:
                if not isinstance(event, dict):
                    continue
                    
                # Look for annotation_mitre_* fields
                for key, value in event.items():
                    if key.startswith('annotation_mitre_') and value:
                        mitre_context.append(f"{key}: {value}")
                        
                        # Extract technique IDs from the value
                        if isinstance(value, str):
                            # Look for MITRE technique patterns like T1234, T1.234, etc.
                            import re
                            tech_matches = re.findall(r'T\d+(?:\.\d+)?', value)
                            techniques.extend(tech_matches)
                        elif isinstance(value, list):
                            # If it's a list, check each item
                            for item in value:
                                if isinstance(item, str):
                                    tech_matches = re.findall(r'T\d+(?:\.\d+)?', item)
                                    techniques.extend(tech_matches)
                                    mitre_context.append(f"{key}: {item}")
                                    
        except Exception as e:
            logger.error(f"Error extracting MITRE techniques: {str(e)}")
            
        return {
            'techniques': list(set(techniques)),  # Remove duplicates
            'context': mitre_context
        }
    
    def get_closed_incidents(self, earliest: str = DEFAULT_EARLIEST, latest: str = DEFAULT_LATEST):
        """
        Get notable events from Splunk using ES macros for the given time window.
        """
        logger.info(f"Retrieving notable events from Splunk for QA review (earliest={earliest}, latest={latest})...")

        # Build the macro-based ES query
        query = build_notable_query(earliest=earliest, latest=latest)
        results = self.execute_splunk_search(query) or []

        incidents: list[dict] = []

        def _normalize_record(r: dict) -> dict:
            return {
                "incident_id": r.get("ticket_id") or r.get("event_id") or r.get("rule_id") or r.get("_cd"),
                "title": r.get("source") or r.get("rule_name") or "Notable Event",
                "analyst": r.get("analyst") or r.get("owner") or r.get("user") or "unknown",
                "status": r.get("disposition_label") or r.get("status_label") or "closed",
                "notable_data": [r],
                "audit_data": []
            }

        for r in results:
            incidents.append(_normalize_record(r))

        logger.info(f"Found {len(incidents)} notable events for QA review")
        return incidents
    
    def extract_json_from_response(self, response_text):
        """Extract the first valid JSON object from LLM response"""
        import re
        
        # Remove common prefixes that LLMs add
        response_text = response_text.strip()
        prefixes_to_remove = [
            "Here is the QA report in JSON format:",
            "Here's the QA report in JSON format:",
            "Here is the analysis in JSON format:",
            "Here's the analysis in JSON format:",
            "Here is the report in JSON format:",
            "Here's the report in JSON format:",
<<<<<<< HEAD
            "Here is the valid JSON:",
            "Here's the valid JSON:",
=======
>>>>>>> 01b0fb7 (major update 13)
            "JSON:",
            "```json",
            "```"
        ]
        
        for prefix in prefixes_to_remove:
            if response_text.startswith(prefix):
                response_text = response_text[len(prefix):].strip()
        
<<<<<<< HEAD
        # Remove markdown code blocks
        if response_text.startswith("```"):
            response_text = response_text[3:].strip()
        if response_text.endswith("```"):
            response_text = response_text[:-3].strip()
        
        # Try to find JSON object(s) in the response
        json_patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Simple nested braces
            r'\{[\s\S]*\}',  # Greedy capture across lines
        ]
        
        candidate_matches = []
        for pattern in json_patterns:
            matches = re.findall(pattern, response_text, re.DOTALL)
            for match in matches:
                candidate_matches.append(match)

        # Prefer the largest candidate, which tends to be the full JSON object
        candidate_matches.sort(key=lambda m: len(m), reverse=True)
        for match in candidate_matches:
=======
        # Remove trailing text after JSON
        if response_text.endswith("```"):
            response_text = response_text[:-3].strip()
        
        # Try to find JSON object in the response
        json_patterns = [
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Simple nested braces
            r'\{.*?\}',  # Any content between braces
        ]
        
        for pattern in json_patterns:
            matches = re.findall(pattern, response_text, re.DOTALL)
            for match in matches:
>>>>>>> 01b0fb7 (major update 13)
                try:
                    # Clean up JSON comments and other issues
                    cleaned_match = re.sub(r'//.*?\n', '\n', match)  # Remove // comments
                    cleaned_match = re.sub(r'/\*.*?\*/', '', cleaned_match, flags=re.DOTALL)  # Remove /* */ comments
                    cleaned_match = cleaned_match.strip()
                    
                    # Try to parse as JSON
                    parsed = json.loads(cleaned_match)
<<<<<<< HEAD
                    if isinstance(parsed, dict) and ('event_id' in parsed or 'incident_id' in parsed):
=======
                    if isinstance(parsed, dict) and 'incident_id' in parsed:
>>>>>>> 01b0fb7 (major update 13)
                        return cleaned_match
                except json.JSONDecodeError:
                    continue
        
        # If no valid JSON found, return the original response
        return response_text
<<<<<<< HEAD
    
=======

>>>>>>> 01b0fb7 (major update 13)
    def analyze_incident(self, incident_id, title, analyst, notable_data, audit_data):
        """Analyze a single incident and generate QA report"""
        logger.info(f"Analyzing incident {incident_id}: {title}")
        
        try:
            # Validate input data
            if not incident_id or not title:
                raise ValueError("Incident ID and title are required")
            
            # Retrieve relevant playbook
            playbook_text = self.retrieve_playbook(title)
            
            # Extract MITRE techniques and context from annotation_mitre_* fields
            mitre_data = self.extract_mitre_techniques(notable_data)
            technique_ids = mitre_data['techniques']
            mitre_context_from_annotations = "; ".join(mitre_data['context']) if mitre_data['context'] else "No MITRE annotations found"
            
<<<<<<< HEAD
            # Also retrieve additional MITRE context from vector DB (with fallback by title)
            mitre_context_from_db = self.retrieve_mitre_context(technique_ids, alert_title=title)
=======
            # Also retrieve additional MITRE context from vector DB
            mitre_context_from_db = self.retrieve_mitre_context(technique_ids)
>>>>>>> 01b0fb7 (major update 13)
            
            # Retrieve MITRE-based recommendations for playbook improvements
            mitre_recommendations = self.retrieve_mitre_recommendations(title, notable_data)
            
            # Combine both sources of MITRE context
            combined_mitre_context = f"ANNOTATION MITRE CONTEXT: {mitre_context_from_annotations}\n\nVECTOR DB MITRE CONTEXT: {mitre_context_from_db}"
            
            # Add MITRE recommendations to context
            if mitre_recommendations:
                recommendations_text = "\n\nMITRE ATT&CK RECOMMENDATIONS FOR PLAYBOOK IMPROVEMENTS:\n"
                for i, rec in enumerate(mitre_recommendations, 1):
                    recommendations_text += f"{i}. {rec['type'].upper()}: {rec['name']} ({rec['id']})\n"
                    recommendations_text += f"   {rec['content'][:200]}...\n"
                    recommendations_text += f"   Reference: {rec['url']}\n\n"
                combined_mitre_context += recommendations_text
            
<<<<<<< HEAD
            # Build a structured MITRE context object: technique, name, description
            import re as _re
            primary_technique = technique_ids[0] if technique_ids else ""
            mitre_name = ""
            mitre_description = ""
            if isinstance(mitre_context_from_db, str) and mitre_context_from_db:
                m_name = _re.search(r"MITRE ATT&CK Technique:\s*(.+)", mitre_context_from_db)
                if m_name:
                    mitre_name = m_name.group(1).strip()
                m_desc = _re.search(r"Description:\s*(.+)", mitre_context_from_db, flags=_re.DOTALL)
                if m_desc:
                    mitre_description = m_desc.group(1).strip()
                    # Trim long descriptions
                    if len(mitre_description) > 600:
                        mitre_description = mitre_description[:600].rstrip() + "..."
            
            mitre_context_obj = {
                "technique": primary_technique,
                "name": mitre_name,
                "description": mitre_description
            }
            
            # Create a concise MITRE summary for the prompt text block
            mitre_summary = (
                f"Technique: {mitre_context_obj['technique']}\n"
                f"Name: {mitre_context_obj['name']}\n"
                f"Description: {mitre_context_obj['description']}\n\n"
            )
            mitre_context_for_prompt = mitre_summary + combined_mitre_context
            
=======
>>>>>>> 01b0fb7 (major update 13)
            # Extract create time from notable data
            notable_event_create_time = "Unknown"
            if notable_data and len(notable_data) > 0:
                first_event = notable_data[0]
                # Try different possible time fields
                for time_field in ['created_time', '_time', 'timestamp', 'firstTime']:
                    if time_field in first_event and first_event[time_field]:
                        notable_event_create_time = str(first_event[time_field])
                        break
            
            # Get current UTC epoch time for QA run
            import time
            utc_qa_run_time = int(time.time())
            
            # Prepare data for LLM
            notable_data_str = json.dumps(notable_data, indent=2) if notable_data else "No data"
            audit_data_str = json.dumps(audit_data, indent=2) if audit_data else "No actions logged"
            
            # Provide a QA definition block for the LLM to use in scoring explanations
            qa_definition = (
                "Use strong evidence to justify any score deductions. If there is no solid evidence of failures, "
                "scores should be high (ideally 5/5). Do not suggest generic improvements; only include "
                "recommendations when clear, evidence-based improvements are required. Recommendations must be limited "
                "to playbook_changes or analyst_training."
            )
            
            # Create chain
            chain = self.prompt_template | self.llm | StrOutputParser()
            
            # Generate report
            raw_report = chain.invoke({
                "title": title,
                "analyst": analyst,
                "event_id": incident_id,
                "notable_data": notable_data_str,
                "audit_data": audit_data_str,
                "playbook_text": playbook_text,
<<<<<<< HEAD
                "mitre_context": mitre_context_for_prompt,
                "qa_definition": qa_definition,
=======
                "mitre_context": combined_mitre_context,
>>>>>>> 01b0fb7 (major update 13)
                "notable_event_create_time": notable_event_create_time,
                "utc_qa_run_time": utc_qa_run_time
            })
            
<<<<<<< HEAD
            # Extract JSON from response and validate/normalize
            report = self.extract_json_from_response(raw_report)
            try:
                data = json.loads(report)
            except Exception:
                # If parsing fails, wrap as error report using the expected schema
                data = {
                    "event_id": incident_id,
                    "analyst": analyst or "unknown",
                    "scores": {"accuracy": 0, "procedure": 0, "documentation": 0},
                    "missed_steps": ["LLM output was not valid JSON"],
                    "escalation_required": False,
                    "summary": "LLM output could not be parsed as JSON. See raw output in logs.",
                    "recommendations": {"playbook_changes": [], "analyst_training": []}
                }
                report = json.dumps(data)
=======
            # Extract JSON from response
            report = self.extract_json_from_response(raw_report)
>>>>>>> 01b0fb7 (major update 13)
            
            # Validate report format
            try:
                json.loads(report)  # Test if it's valid JSON
                logger.info(f"Successfully generated QA report for incident {incident_id}")
            except json.JSONDecodeError:
                logger.warning(f"Generated report for {incident_id} is not valid JSON, but continuing")
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to analyze incident {incident_id}: {str(e)}")
            # Return a basic error report
            return json.dumps({
                "event_id": incident_id,
                "analyst": analyst or "unknown",
                "scores": {"accuracy": 0, "procedure": 0, "documentation": 0},
                "missed_steps": ["Analysis failed due to error"],
                "escalation_required": False,
                "summary": f"Analysis failed: {str(e)}",
                "recommendations": {"playbook_changes": [], "analyst_training": []}
            })
    
    def save_report_to_splunk(self, report_json):
        """Save QA report back to Splunk using HTTP Event Collector (HEC)"""
        try:
            # Parse to validate JSON and extract data for metadata
            report_data = json.loads(report_json)
            
            # Prepare HEC payload with metadata
            hec_payload = {
                "time": time.time(),  # Current epoch time
                "host": socket.gethostname(),  # Name of the QA agent host
                "source": "soc_qa_agent",
                "sourcetype": "_json",
                "index": SPLUNK_CONFIG['index'],
                "event": report_data  # The actual QA report data
            }
            
            # HEC endpoint: accept full endpoint or append default path
            base_hec = SPLUNK_CONFIG['hec_url'].rstrip('/')
            if '/services/collector/event' in base_hec or '/services/collector' in base_hec:
                hec_url = base_hec
            else:
                hec_url = f"{base_hec}/services/collector/event"
            
            # Headers with HEC token authorization
            headers = {
                "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
                "Content-Type": "application/json"
            }
            
            # Send to Splunk HEC
            response = requests.post(
                hec_url,
                headers=headers,
                data=json.dumps(hec_payload),
                verify=SPLUNK_CONFIG['hec_ssl_verify']
            )
            
            # Check response
            if response.status_code == 200:
                response_data = response.json()
                if response_data.get('code') == 0:
                    logger.info(f"Report successfully sent to Splunk HEC")
                    return True
                else:
                    logger.error(f"HEC error: {response_data.get('text', 'Unknown error')}")
                    return False
            else:
                logger.error(f"HEC HTTP error: {response.status_code} - {response.text}")
                return False
                
        except json.JSONDecodeError:
            logger.error("Generated report is not valid JSON")
            return False
        except Exception as e:
            logger.error(f"Failed to send report to Splunk HEC: {str(e)}")
            return False
    
    def run_qa_cycle(self):
        """Main method to run the QA process"""
        logger.info("Starting QA cycle")
        
        # Get closed incidents
        incidents = self.get_closed_incidents()
        
        logger.info(f"Found {len(incidents)} closed incidents to review")
        
        for incident in incidents:
            try:
                report = self.analyze_incident(
                    incident['incident_id'],
                    incident['title'],
                    incident.get('analyst', 'unknown'),
                    incident.get('notable_data', []),
                    incident.get('audit_data', [])
                )
                self.save_report_to_splunk(report)
                
            except Exception as e:
                logger.error(f"Failed to process incident {incident.get('incident_id')}: {str(e)}")
                continue
        
        logger.info("QA cycle completed")

def main():
    """Main entry point"""
    try:
        agent = SOCQAAgent()
        agent.run_qa_cycle()
    except Exception as e:
        logger.error(f"QA Agent failed: {str(e)}")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())