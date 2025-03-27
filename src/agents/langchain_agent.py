"""
LangChain Agent for Autonomous Decision-Making
This module uses LangChain to process threat alerts and make mitigation decisions.
"""
from langchain_core.language_models.base import BaseLanguageModel
from langchain_core.embeddings import Embeddings
from langchain_core.tools import Tool
from langchain_core.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
import os
import google.generativeai as genai
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

class GeminiEmbeddings(Embeddings):
    def __init__(self, api_key: str):
        self.api_key = api_key
        genai.configure(api_key=api_key)
        
    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        embeddings = []
        for text in texts:
            model = genai.GenerativeModel('gemini-pro')
            response = model.generate_content(text)
            # Convert the response to a fixed-size embedding
            embedding = [hash(str(response.text)) % 1000 / 1000 for _ in range(512)]  # Normalize to [0,1]
            embeddings.append(embedding)
        return embeddings
    
    def embed_query(self, text: str) -> List[float]:
        return self.embed_documents([text])[0]

class GeminiLLM(BaseLanguageModel):
    def __init__(self, api_key: str, temperature: float = 0.7):
        self._api_key = api_key
        self._temperature = temperature
        genai.configure(api_key=api_key)

    @property
    def _llm_type(self) -> str:
        return "gemini"

    def invoke(self, input: str, config: Optional[Dict] = None, **kwargs: Any) -> Any:
        if isinstance(input, str):
            return self.predict(input)
        return self.predict(str(input))

    def predict(self, prompt: str) -> str:
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(prompt)
        return response.text

    def predict_messages(self, messages: List[str]) -> List[str]:
        return [self.predict(message) for message in messages]

    async def ainvoke(self, input: Any, config: Optional[Dict] = None, **kwargs: Any) -> Any:
        return self.invoke(input)

    async def apredict(self, prompt: str) -> str:
        return self.predict(prompt)

    async def apredict_messages(self, messages: List[str]) -> List[str]:
        return self.predict_messages(messages)

class LangChainAgent:
    def __init__(self, vector_db_path: str):
        """Initialize the LangChain agent with a vector database."""
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is required")
            
        self.embeddings = GeminiEmbeddings(api_key=api_key)
        self.vector_db = FAISS.load_local(
            vector_db_path, 
            self.embeddings,
            allow_dangerous_deserialization=True
        )
        self.llm = GeminiLLM(api_key=api_key)
        self.memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
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
