"""
Initialize VectorDB with Past Attack Cases
This module loads historical attack cases into FAISS VectorDB for LangChain context.
"""
from langchain_community.vectorstores import FAISS
from langchain_community.docstore.document import Document
from loguru import logger
import os
import google.generativeai as genai

class GeminiEmbeddings:
    def __init__(self, api_key):
        self.api_key = api_key
        genai.configure(api_key=api_key)
        print("Google Generative AI client configured with API key.")

    def embed_documents(self, texts):
        embeddings = []
        for text in texts:
            model = genai.GenerativeModel('gemini-2.0-flash')
            response = model.generate_content(text)
            # Convert the response to a fixed-size embedding
            embedding = [hash(str(response.text)) % 1000 for _ in range(512)]
            embeddings.append(embedding)
        return embeddings

    def embed_query(self, text):
        return self.embed_documents([text])[0]

# Initialize FAISS vector database and save the index file
def initialize_vector_db():
    vector_db_path = os.path.join(os.path.dirname(__file__), '../../data/vector_db')
    os.makedirs(vector_db_path, exist_ok=True)

    # Example documents to populate the vector database
    documents = [
        Document(page_content="This is a sample document about cybersecurity."),
        Document(page_content="Another document discussing threat detection and response."),
        Document(page_content="A third document on anomaly detection in networks.")
    ]

    # Initialize FAISS vector database
    embeddings = GeminiEmbeddings(api_key=os.getenv("GENAI_API_KEY"))
    vector_db = FAISS.from_documents(documents, embeddings)

    # Save the vector database to the specified path
    vector_db.save_local(vector_db_path)
    print(f"Vector database initialized and saved to {vector_db_path}")

if __name__ == "__main__":
    initialize_vector_db()