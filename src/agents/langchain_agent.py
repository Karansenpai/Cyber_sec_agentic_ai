"""
LangChain Agent for Autonomous Decision-Making
This module uses LangChain to process threat alerts and make mitigation decisions.
"""
from langchain_core.language_models.base import BaseLanguageModel
from langchain_core.tools import Tool
from langchain_core.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain_community.document_loaders import TextLoader
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
        super().__init__()  # Ensure proper initialization of the parent class
        self.api_key = api_key
        self.temperature = temperature
        genai.configure(api_key=api_key)

class LangChainAgent:
    def __init__(self, vector_db_path: str):
        """Initialize the LangChain agent with a vector database."""
        self.vector_db = FAISS.load_local(
            vector_db_path, 
            GeminiEmbeddings(api_key=os.getenv("GENAI_API_KEY")),
            allow_dangerous_deserialization=True  # Enable deserialization with caution
        )
        self.llm = GeminiLLM(api_key=os.getenv("GENAI_API_KEY"))
        self.memory = ConversationBufferMemory(memory_key="chat_history")
        self.chain = LLMChain(
            llm=self.llm,
            prompt=PromptTemplate(
                input_variables=["context", "query"],
                template="""
                Context: {context}
                Query: {query}
                Response:
                """
            ),
            memory=self.memory
        )

    def query(self, user_query: str) -> str:
        """Query the LangChain agent and return a response."""
        context = self.vector_db.similarity_search(user_query, k=3)
        context_text = "\n".join([doc.page_content for doc in context])
        return self.chain.run(context=context_text, query=user_query)
