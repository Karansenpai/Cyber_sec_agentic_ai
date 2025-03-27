"""
Orchestration Service for Autonomous Decision-Making and Response
This module connects the anomaly detection, LangChain agent, and incident response systems.
"""
import os
import json
from confluent_kafka import Consumer, Producer, KafkaError
from loguru import logger
from src.agents.langchain_agent import LangChainAgent
from src.agents.vector_db_init import initialize_vector_db
from src.response.incident_responder import IncidentResponder
from src.utils.config import load_config

class OrchestrationService:
    def __init__(self, config_path=None):
        """Initialize the orchestration service."""
        self.config = load_config(config_path)
        
        # Initialize VectorDB if not exists
        vector_db_path = os.path.join(os.path.dirname(__file__), '../../data/vector_db')
        if not os.path.exists(vector_db_path):
            initialize_vector_db(vector_db_path)
        
        # Initialize components
        self.agent = LangChainAgent(vector_db_path)
        self.responder = IncidentResponder(vector_db_path)
        
        # Configure Kafka consumer
        self.consumer_config = {
            'bootstrap.servers': self.config['kafka']['bootstrap_servers'],
            'group.id': self.config['kafka']['consumer_group'] + '_orchestrator',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False
        }
        
        # Configure Kafka producer for feedback
        self.producer_config = {
            'bootstrap.servers': self.config['kafka']['bootstrap_servers'],
            'client.id': 'orchestrator_feedback_producer'
        }
        
    def start(self):
        """Start the orchestration service."""
        try:
            # Create Kafka consumer
            consumer = Consumer(self.consumer_config)
            producer = Producer(self.producer_config)
            
            # Subscribe to anomaly topic
            anomaly_topic = self.config['kafka']['topics'].get('anomalies', 'anomalies')
            consumer.subscribe([anomaly_topic])
            
            logger.info(f"Starting orchestration service, listening on topic: {anomaly_topic}")
            
            while True:
                msg = consumer.poll(1.0)
                
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(f"Consumer error: {msg.error()}")
                        continue
                
                try:
                    # Process the anomaly
                    anomaly = json.loads(msg.value().decode('utf-8'))
                    logger.info(f"Processing anomaly: {anomaly}")
                    
                    # Get decision from LangChain agent
                    decision = self.agent.process_alert(anomaly)
                    logger.info(f"Agent decision: {decision}")
                    
                    # Execute response actions
                    self.responder.respond_to_alert(decision)
                    
                    # Send feedback for continuous learning
                    feedback = {
                        'anomaly': anomaly,
                        'decision': decision,
                        'timestamp': anomaly.get('timestamp'),
                        'status': 'processed'
                    }
                    
                    producer.produce(
                        self.config['kafka']['topics'].get('feedback', 'feedback'),
                        json.dumps(feedback).encode('utf-8')
                    )
                    producer.flush()
                    
                    # Commit offset
                    consumer.commit(msg)
                    
                except Exception as e:
                    logger.error(f"Error processing anomaly: {e}")
                    
        except KeyboardInterrupt:
            logger.info("Shutting down orchestration service")
        finally:
            consumer.close()

if __name__ == "__main__":
    orchestrator = OrchestrationService()
    orchestrator.start()