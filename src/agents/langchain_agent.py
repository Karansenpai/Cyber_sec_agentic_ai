"""
LangChain Agent for Autonomous Decision-Making
This module uses LangChain to process threat alerts and make mitigation decisions.
"""
from langchain_core.language_models.base import BaseLanguageModel
from langchain_core.tools import Tool
from langchain_core.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
import os
import google.generativeai as genai
from typing import List, Optional

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

class GeminiLLM(BaseLanguageModel):
    def __init__(self, api_key: str, temperature: float = 0.7):
        self.api_key = api_key
        self.temperature = temperature
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
    
    def predict(self, text: str) -> str:
        response = self.model.generate_content(text)
        return response.text

    def generate(self, prompts: List[str], **kwargs) -> List[str]:
        return [self.predict(prompt) for prompt in prompts]

    @property
    def _llm_type(self) -> str:
        return "gemini"

class LangChainAgent:
    def __init__(self, vector_db_path):
        """Initialize the LangChain agent with a VectorDB for past attack cases."""
        self.vector_db_path = vector_db_path
        self.memory = ConversationBufferMemory(memory_key="chat_history")
        
        # Initialize with Gemini
        self.api_key = "AIzaSyCLGCT56ZbZ0Ww9J0Y__sBimQZ1msZkRzk"
        self.llm = GeminiLLM(api_key=self.api_key)
        self.embeddings = GeminiEmbeddings(api_key=self.api_key)
        
        try:
            self.vector_db = FAISS.load_local(vector_db_path, self.embeddings)
        except Exception as e:
            print(f"Error loading vector DB: {e}")
            # Initialize with empty DB if loading fails
            self.vector_db = FAISS.from_texts(["Initial document"], self.embeddings)

    def process_alert(self, alert):
        """Process a threat alert and return a mitigation decision."""
        prompt = PromptTemplate(
            input_variables=["alert"],
            template="""
            You are a cybersecurity AI agent. Based on the following alert:
            {alert}
            Assess the severity and recommend the best mitigation action.
            """
        )
        
        try:
            response = self.llm.predict(prompt.format(alert=alert))
            return response
        except Exception as e:
            print(f"Error processing alert: {e}")
            return "Error processing alert. Please check the system logs."

if __name__ == "__main__":
    # Example usage
    vector_db_path = "./vector_db"
    agent = LangChainAgent(vector_db_path)
    # Example alert
    alert = "Suspicious login attempt detected from IP 192.168.1.100."
    decision = agent.process_alert(alert)
    print("Decision:", decision)