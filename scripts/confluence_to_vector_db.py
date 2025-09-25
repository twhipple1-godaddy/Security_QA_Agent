#!/usr/bin/env python3
"""
Script to build and update the Vector Database from Confluence playbooks.
Run this initially and periodically to keep playbooks updated.
"""

import os
import sys
import logging

# Add the parent directory to the path to import config
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONFLUENCE_CONFIG, VECTOR_DB_PATH

PDF_FALLBACK_PATH = os.environ.get('SOC_PLAYBOOKS_PDF', os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'soc_playbooks.pdf'))

try:
    from config.secrets import CONFLUENCE_USERNAME, CONFLUENCE_TOKEN  # may be commented out
except Exception:
    CONFLUENCE_USERNAME = None
    CONFLUENCE_TOKEN = None

from langchain_community.document_loaders import ConfluenceLoader, PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('confluence_loader')

def build_knowledge_base():
    """Build or update the vector database from Confluence, with PDF fallback."""
    
    logger.info("Starting Confluence knowledge base build...")
    
    try:
        documents = []
        if CONFLUENCE_USERNAME and CONFLUENCE_TOKEN and CONFLUENCE_CONFIG.get('url'):
            # Try Confluence first if configured
            try:
                loader = ConfluenceLoader(
                    url=CONFLUENCE_CONFIG['url'],
                    username=CONFLUENCE_USERNAME,
                    api_key=CONFLUENCE_TOKEN,
                    space_key=CONFLUENCE_CONFIG.get('space_key'),
                    include_attachments=False,
                    limit=50
                )
                documents = loader.load()
                logger.info(f"Loaded {len(documents)} documents from Confluence")
            except Exception as e:
                logger.warning(f"Confluence load failed, will try PDF fallback: {e}")

        if not documents:
            # Fallback: load from local PDF
            if not os.path.exists(PDF_FALLBACK_PATH):
                raise FileNotFoundError(f"SOC playbooks PDF not found at {PDF_FALLBACK_PATH}")
            pdf_loader = PyPDFLoader(PDF_FALLBACK_PATH)
            documents = pdf_loader.load()
            logger.info(f"Loaded {len(documents)} pages from PDF fallback: {PDF_FALLBACK_PATH}")
        
        # Split documents into chunks
        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=200
        )
        
        chunks = text_splitter.split_documents(documents)
        logger.info(f"Split into {len(chunks)} chunks")
        
        # Create embeddings - using a local model
        embeddings = HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",  # Lightweight local model
            model_kwargs={'device': 'cpu'}
        )
        
        # Create and persist vector store
        vector_db = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=VECTOR_DB_PATH
        )
        
        vector_db.persist()
        logger.info(f"Vector database built and persisted to {VECTOR_DB_PATH}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error building knowledge base: {str(e)}")
        return False

if __name__ == "__main__":
    build_knowledge_base()