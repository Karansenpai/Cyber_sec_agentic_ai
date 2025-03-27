"""
Initialize VectorDB with Past Attack Cases
This module loads historical attack cases into FAISS VectorDB for LangChain context.
"""
from langchain.vectorstores import FAISS
from langchain.docstore.document import Document
from loguru import logger
import os
import google.generativeai as genai

class GeminiEmbeddings:
    def __init__(self, api_key):
        self.api_key = api_key
        genai.configure(api_key=api_key)
        
    def embed_documents(self, texts):
        embeddings = []
        for text in texts:
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(text)
            # Convert the response to a fixed-size embedding
            embedding = [hash(str(response.text)) % 1000 for _ in range(512)]
            embeddings.append(embedding)
        return embeddings
    
    def embed_query(self, text):
        return self.embed_documents([text])[0]

# Example attack cases for initialization
INITIAL_CASES = [
    {
        "title": "Brute Force Login Attempt",
        "description": "Multiple failed login attempts from single IP",
        "severity": "Medium",
        "mitigation": "Block IP and enforce 2FA"
    },
    {
        "alert": "Unusual data transfer to external IP 203.0.113.42",
        "severity": "CRITICAL",
        "action_taken": "quarantine endpoint",
        "outcome": "data exfiltration prevented",
        "context": "Potential data breach attempt"
    },
    {
        "alert": "Known malware signature detected on endpoint WIN-PC01",
        "severity": "CRITICAL",
        "action_taken": "quarantine endpoint and apply patch",
        "outcome": "malware contained and system patched",
        "context": "Zero-day exploit attempt"
    }
]

def initialize_vector_db(vector_db_path="./data/vector_db"):
    """Initialize FAISS VectorDB with past attack cases."""
    try:
        # Create directory if it doesn't exist
        os.makedirs(vector_db_path, exist_ok=True)

        # Convert cases to documents
        documents = []
        for case in INITIAL_CASES:
            text = f"""
            Alert: {case['alert']}
            Severity: {case['severity']}
            Action Taken: {case['action_taken']}
            Outcome: {case['outcome']}
            Context: {case['context']}
            """
            documents.append(Document(page_content=text))

        # Initialize embeddings
        embeddings = GeminiEmbeddings(api_key="AIzaSyCLGCT56ZbZ0Ww9J0Y__sBimQZ1msZkRzk")

        # Create and save the vector store
        vector_store = FAISS.from_documents(documents, embeddings)
        vector_store.save_local(vector_db_path)

        logger.info(f"VectorDB initialized with {len(INITIAL_CASES)} cases")
        return True

    except Exception as e:
        logger.error(f"Error initializing VectorDB: {e}")
        return False

if __name__ == "__main__":
    initialize_vector_db()