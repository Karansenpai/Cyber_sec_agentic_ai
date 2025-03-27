#!/usr/bin/env python
"""
Kafka Consumer for Cybersecurity Data

This module consumes data from Kafka topics and stores it in Elasticsearch.
It's part of the data ingestion pipeline for the cybersecurity system.
"""

import json
import sys
import os
import time
from datetime import datetime
from loguru import logger
from confluent_kafka import Consumer, KafkaError, KafkaException
from elasticsearch import Elasticsearch, helpers

# Import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import load_config


class CyberSecurityConsumer:
    """Consumer class for processing cybersecurity data from Kafka"""

    def __init__(self, config_path=None):
        """Initialize the consumer with configuration"""
        self.config = load_config(config_path)
        
        # Configure Kafka Consumer
        self.consumer_config = {
            'bootstrap.servers': self.config['kafka']['bootstrap_servers'],
            'group.id': self.config['kafka']['consumer_group'],
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
        }
        self.consumer = Consumer(self.consumer_config)
        
        # Subscribe to topics
        self.topics = list(self.config['kafka']['topics'].values())
        self.consumer.subscribe(self.topics)
        logger.info(f"Subscribed to topics: {', '.join(self.topics)}")
        
        # Configure Elasticsearch
        self.es = Elasticsearch(
            self.config['elasticsearch']['hosts']
        )
        
        # Check if Elasticsearch is available
        if not self.es.ping():
            logger.error("Could not connect to Elasticsearch")
            raise ConnectionError("Could not connect to Elasticsearch")
        logger.info("Connected to Elasticsearch")

    def setup_elasticsearch_indices(self):
        """Set up Elasticsearch indices with appropriate mappings"""
        index_prefix = self.config['elasticsearch']['index_prefix']
        
        # Network logs index mapping
        network_logs_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "source_port": {"type": "integer"},
                    "destination_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "bytes_sent": {"type": "integer"},
                    "bytes_received": {"type": "integer"},
                    "duration_ms": {"type": "integer"},
                    "status": {"type": "keyword"},
                    "user_agent": {"type": "text"}
                }
            }
        }
        
        # System alerts index mapping
        system_alerts_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "alert_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "message": {"type": "text"},
                    "affected_system": {"type": "keyword"},
                    "affected_user": {"type": "keyword"},
                    "alert_id": {"type": "keyword"}
                }
            }
        }
        
        # User events index mapping
        user_events_mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "user_id": {"type": "keyword"},
                    "username": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "ip_address": {"type": "ip"},
                    "device_info": {
                        "properties": {
                            "os": {"type": "keyword"},
                            "browser": {"type": "keyword"}
                        }
                    },
                    "success": {"type": "boolean"},
                    "details": {"type": "text"}
                }
            }
        }
        
        # Create or update indices with mappings
        indices_mappings = {
            f"{index_prefix}_{self.config['elasticsearch']['indices']['network_logs']}": network_logs_mapping,
            f"{index_prefix}_{self.config['elasticsearch']['indices']['system_alerts']}": system_alerts_mapping,
            f"{index_prefix}_{self.config['elasticsearch']['indices']['user_events']}": user_events_mapping
        }
        
        for index_name, mapping in indices_mappings.items():
            if not self.es.indices.exists(index=index_name):
                self.es.indices.create(index=index_name, body=mapping)
                logger.info(f"Created index: {index_name}")
            else:
                logger.info(f"Index already exists: {index_name}")

    def process_message(self, msg):
        """Process a message from Kafka and store it in Elasticsearch"""
        try:
            # Decode message value
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    # End of partition event
                    logger.debug(f"Reached end of partition: {msg.topic()}/{msg.partition()}")
                    return True
                else:
                    logger.error(f"Error processing message: {msg.error()}")
                    return False
            
            # Decode message
            message_value = msg.value().decode('utf-8')
            message_data = json.loads(message_value)
            
            # Determine index based on topic
            topic = msg.topic()
            index_prefix = self.config['elasticsearch']['index_prefix']
            
            if topic == self.config['kafka']['topics']['network_logs']:
                index_name = f"{index_prefix}_{self.config['elasticsearch']['indices']['network_logs']}"
            elif topic == self.config['kafka']['topics']['system_alerts']:
                index_name = f"{index_prefix}_{self.config['elasticsearch']['indices']['system_alerts']}"
            elif topic == self.config['kafka']['topics']['user_events']:
                index_name = f"{index_prefix}_{self.config['elasticsearch']['indices']['user_events']}"
            else:
                logger.warning(f"Unknown topic: {topic}")
                return True
            
            # Add timestamp for Elasticsearch if not present
            if 'timestamp' not in message_data:
                message_data['timestamp'] = datetime.now().isoformat()
            
            # Store in Elasticsearch
            res = self.es.index(index=index_name, body=message_data)
            logger.debug(f"Indexed document in {index_name}: {res['result']}")
            
            return True
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            return False

    def consume_messages(self):
        """Main loop to consume messages from Kafka topics"""
        try:
            # Setup Elasticsearch indices
            self.setup_elasticsearch_indices()
            
            logger.info("Starting to consume messages...")
            while True:
                # Poll for messages
                msg = self.consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                
                # Process the message
                success = self.process_message(msg)
                
                # Commit offset if processing was successful
                if success:
                    self.consumer.commit(msg)
                
        except KeyboardInterrupt:
            logger.info("Consumer interrupted by user")
        except Exception as e:
            logger.error(f"Unexpected error in consumer: {e}")
        finally:
            # Close the consumer
            logger.info("Closing consumer...")
            self.consumer.close()
            logger.info("Consumer closed")


if __name__ == "__main__":
    try:
        logger.info("Starting Cybersecurity Data Consumer")
        # Sleep briefly to allow Kafka and Elasticsearch to start up
        time.sleep(10)
        consumer = CyberSecurityConsumer()
        consumer.consume_messages()
    except Exception as e:
        logger.error(f"Failed to start consumer: {e}")