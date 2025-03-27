"""
LangChain Agent for Autonomous Decision-Making
This module uses LangChain to process threat alerts and make mitigation decisions.
"""
from langchain.agents import initialize_agent, Tool
from langchain.llms import OpenAI
from langchain.vectorstores import FAISS
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain.document_loaders import TextLoader
from langchain.embeddings import OpenAIEmbeddings
import os

class LangChainAgent:
    def __init__(self, vector_db_path):
        """Initialize the LangChain agent with a VectorDB for past attack cases."""
        self.vector_db_path = vector_db_path
        self.memory = ConversationBufferMemory()
        self.llm = OpenAI(temperature=0.7)
        self.vector_db = FAISS.load_local(vector_db_path, OpenAIEmbeddings())

        # Define tools for the agent
        self.tools = [
            Tool(
                name="Search Past Cases",
                func=self.vector_db.similarity_search,
                description="Search past attack cases for context-aware decision-making."
            )
        ]

        # Initialize the agent
        self.agent = initialize_agent(
            tools=self.tools,
            llm=self.llm,
            memory=self.memory,
            agent_type="conversational-react-description"
        )

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
        chain = LLMChain(llm=self.llm, prompt=prompt)
        decision = chain.run(alert=alert)
        return decision

if __name__ == "__main__":
    # Example usage
    vector_db_path = "./vector_db"
    agent = LangChainAgent(vector_db_path)

    # Example alert
    alert = "Suspicious login attempt detected from IP 192.168.1.100."
    decision = agent.process_alert(alert)
    print("Decision:", decision)