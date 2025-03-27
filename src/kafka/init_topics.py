#!/usr/bin/env python
"""
Kafka Topic Initialization Script

This script initializes the required Kafka topics for the cybersecurity system.
It should be run once before starting the producer and consumer.
"""

import sys
import os
import time
from confluent_kafka.admin import AdminClient, NewTopic
from loguru import logger

# Import utilities
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import load_config


def create_topics(admin_client, topic_list, num_partitions=3, replication_factor=1):
    """
    Create Kafka topics if they don't exist
    
    Args:
        admin_client: Kafka AdminClient instance
        topic_list: List of topic names to create
        num_partitions: Number of partitions for each topic
        replication_factor: Replication factor for each topic
    """
    # Check which topics already exist
    metadata = admin_client.list_topics(timeout=10)
    existing_topics = set(t for t in metadata.topics.keys())
    logger.info(f"Existing topics: {', '.join(existing_topics)}")
    
    # Create new topic objects for topics that don't exist
    new_topics = []
    for topic in topic_list:
        if topic not in existing_topics:
            new_topics.append(NewTopic(
                topic,
                num_partitions=num_partitions,
                replication_factor=replication_factor
            ))
    
    # Create the topics
    if new_topics:
        logger.info(f"Creating topics: {', '.join([t.topic for t in new_topics])}")
        fs = admin_client.create_topics(new_topics)
        
        # Wait for topics to be created
        for topic, f in fs.items():
            try:
                f.result()  # Wait for completion
                logger.info(f"Topic '{topic}' created")
            except Exception as e:
                logger.error(f"Failed to create topic '{topic}': {e}")
    else:
        logger.info("All topics already exist")


if __name__ == "__main__":
    try:
        logger.info("Initializing Kafka topics")
        
        # Load configuration
        config = load_config()
        
        # Wait for Kafka to be ready
        logger.info("Waiting for Kafka to be ready...")
        time.sleep(15)
        
        # Create Admin client
        admin_client = AdminClient({
            'bootstrap.servers': config['kafka']['bootstrap_servers']
        })
        
        # Get topic names from config
        topic_list = list(config['kafka']['topics'].values())
        
        # Create topics
        create_topics(admin_client, topic_list)
        
        logger.info("Kafka topic initialization completed")
        
    except Exception as e:
        logger.error(f"Failed to initialize Kafka topics: {e}")