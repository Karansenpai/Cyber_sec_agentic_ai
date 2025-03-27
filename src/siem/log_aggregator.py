"""
Log Aggregator for SIEM System

This module collects logs from various sources (Kafka topics),
normalizes them into a consistent format, and stores them in
Elasticsearch for analysis.
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List

from elasticsearch import Elasticsearch, helpers
from kafka import KafkaConsumer
from loguru import logger

# Add the parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.config import load_config


class LogAggregator:
    """
    Aggregates logs from multiple sources and stores them in Elasticsearch.
    
    This class:
    - Consumes logs from configured Kafka topics
    - Normalizes logs into a consistent format
    - Enriches logs with additional context
    - Stores logs in Elasticsearch for analysis
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the log aggregator
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        
        # Configure logging
        logger.info("Initializing Log Aggregator")
        
        # Initialize Elasticsearch client
        es_hosts = self.config['elasticsearch']['hosts']
        self.es = Elasticsearch(es_hosts)
        
        # Index prefix for logs
        self.index_prefix = self.config['elasticsearch']['index_prefix']
        
        # Initialize Kafka consumer
        kafka_config = self.config['kafka']
        self.consumer = KafkaConsumer(
            *kafka_config['log_topics'],
            bootstrap_servers=kafka_config['bootstrap_servers'],
            group_id='log_aggregator',
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            value_deserializer=lambda x: json.loads(x.decode('utf-8'))
        )
        
        # Check Elasticsearch connection
        if not self.es.ping():
            logger.error("Cannot connect to Elasticsearch")
            raise ConnectionError("Cannot connect to Elasticsearch")
            
        logger.info("Connected to Elasticsearch successfully")
        
        # Initialize indices if they don't exist
        self._initialize_indices()
        
        # Statistics
        self.stats = {
            'logs_processed': 0,
            'logs_failed': 0,
            'start_time': datetime.now()
        }
    
    def _initialize_indices(self):
        """Initialize required Elasticsearch indices with mappings"""
        # Common settings for all indices
        common_settings = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                "index.mapping.ignore_malformed": True
            }
        }
        
        # Common timestamp mapping for all indices
        timestamp_mapping = {
            "@timestamp": {
                "type": "date"
            }
        }
        
        # Network logs mapping
        network_mapping = {
            "mappings": {
                "properties": {
                    **timestamp_mapping,
                    "log_type": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "destination_ip": {"type": "ip"},
                    "source_port": {"type": "integer"},
                    "destination_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                    "bytes_sent": {"type": "long"},
                    "bytes_received": {"type": "long"},
                    "duration": {"type": "float"},
                    "action": {"type": "keyword"},
                    "status": {"type": "keyword"}
                }
            },
            **common_settings
        }
        
        # System alerts mapping
        system_mapping = {
            "mappings": {
                "properties": {
                    **timestamp_mapping,
                    "log_type": {"type": "keyword"},
                    "alert_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "affected_system": {"type": "keyword"},
                    "process_name": {"type": "keyword"},
                    "process_id": {"type": "long"},
                    "user": {"type": "keyword"},
                    "command": {"type": "text"},
                    "file_path": {"type": "keyword"},
                    "message": {"type": "text"}
                }
            },
            **common_settings
        }
        
        # User events mapping
        user_mapping = {
            "mappings": {
                "properties": {
                    **timestamp_mapping,
                    "log_type": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "username": {"type": "keyword"},
                    "source_ip": {"type": "ip"},
                    "user_agent": {"type": "keyword"},
                    "resource": {"type": "keyword"},
                    "action": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "details": {"type": "text"}
                }
            },
            **common_settings
        }
        
        # SIEM events mapping (for correlated events/incidents)
        siem_mapping = {
            "mappings": {
                "properties": {
                    **timestamp_mapping,
                    "event_id": {"type": "keyword"},
                    "correlation_id": {"type": "keyword"},
                    "rule_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "priority": {"type": "integer"},
                    "status": {"type": "keyword"},
                    "assigned_to": {"type": "keyword"},
                    "message": {"type": "text"},
                    "event_count": {"type": "integer"},
                    "related_events": {"type": "keyword"},
                    "related_ips": {"type": "ip"},
                    "related_users": {"type": "keyword"},
                    "related_systems": {"type": "keyword"},
                    "notes": {"type": "text"},
                    "resolution": {"type": "text"}
                }
            },
            **common_settings
        }
        
        # Create indices if they don't exist
        indices = {
            f"{self.index_prefix}_network_logs": network_mapping,
            f"{self.index_prefix}_system_alerts": system_mapping,
            f"{self.index_prefix}_user_events": user_mapping,
            f"{self.index_prefix}_siem_events": siem_mapping
        }
        
        for index_name, mapping in indices.items():
            if not self.es.indices.exists(index=index_name):
                try:
                    self.es.indices.create(index=index_name, body=mapping)
                    logger.info(f"Created index: {index_name}")
                except Exception as e:
                    logger.error(f"Error creating index {index_name}: {e}")
    
    def _normalize_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize log data into a consistent format
        
        Args:
            log_data: Raw log data
            
        Returns:
            Normalized log data
        """
        # Ensure timestamp exists and is in ISO format
        if "@timestamp" not in log_data:
            log_data["@timestamp"] = datetime.now().isoformat()
        
        # Convert any datetime objects to ISO format strings
        for key, value in log_data.items():
            if isinstance(value, datetime):
                log_data[key] = value.isoformat()
        
        # Add log_type if missing
        if "log_type" not in log_data:
            # Try to infer log type from data
            if "alert_type" in log_data:
                log_data["log_type"] = "system_alert"
            elif "source_ip" in log_data and "destination_ip" in log_data:
                log_data["log_type"] = "network_log"
            elif "username" in log_data:
                log_data["log_type"] = "user_event"
            else:
                log_data["log_type"] = "unknown"
        
        return log_data
    
    def _enrich_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich log data with additional context
        
        Args:
            log_data: Normalized log data
            
        Returns:
            Enriched log data
        """
        log_type = log_data.get("log_type")
        
        if log_type == "network_log":
            # Add geo-ip data if available
            # Add protocol information if missing
            # Add network zone information
            pass
            
        elif log_type == "system_alert":
            # Add system details
            # Add user context
            # Add process context
            pass
            
        elif log_type == "user_event":
            # Add user details
            # Add resource context
            # Add previous activity context
            pass
        
        return log_data
    
    def _determine_index(self, log_data: Dict[str, Any]) -> str:
        """
        Determine the appropriate Elasticsearch index for the log
        
        Args:
            log_data: Log data
            
        Returns:
            Index name
        """
        log_type = log_data.get("log_type", "unknown")
        
        if log_type == "network_log":
            return f"{self.index_prefix}_network_logs"
        elif log_type == "system_alert":
            return f"{self.index_prefix}_system_alerts"
        elif log_type == "user_event":
            return f"{self.index_prefix}_user_events"
        else:
            logger.warning(f"Unknown log type: {log_type}")
            return f"{self.index_prefix}_unknown"
    
    def _store_log(self, log_data: Dict[str, Any]):
        """
        Store log data in Elasticsearch
        
        Args:
            log_data: Log data to store
        """
        try:
            # Determine the index
            index = self._determine_index(log_data)
            
            # Store in Elasticsearch
            self.es.index(
                index=index,
                document=log_data
            )
            
            self.stats['logs_processed'] += 1
            
        except Exception as e:
            logger.error(f"Error storing log: {e}")
            self.stats['logs_failed'] += 1
    
    def _process_batch(self, messages: List[Dict[str, Any]]):
        """
        Process a batch of log messages
        
        Args:
            messages: List of log messages to process
        """
        actions = []
        
        for message in messages:
            try:
                # Normalize and enrich log data
                log_data = self._normalize_log(message)
                log_data = self._enrich_log(log_data)
                
                # Prepare bulk action
                action = {
                    "_index": self._determine_index(log_data),
                    "_source": log_data
                }
                
                actions.append(action)
                
            except Exception as e:
                logger.error(f"Error processing log message: {e}")
                self.stats['logs_failed'] += 1
        
        if actions:
            try:
                # Bulk insert into Elasticsearch
                success, failed = helpers.bulk(
                    self.es,
                    actions,
                    stats_only=True
                )
                
                self.stats['logs_processed'] += success
                self.stats['logs_failed'] += failed
                
            except Exception as e:
                logger.error(f"Error in bulk insert: {e}")
                self.stats['logs_failed'] += len(actions)
    
    def start(self, batch_size=100, batch_timeout_ms=5000):
        """
        Start the log aggregator service
        
        Args:
            batch_size: Number of messages to process in a batch
            batch_timeout_ms: Max time to wait for a full batch
        """
        logger.info("Starting log aggregator service")
        
        messages = []
        last_batch_time = datetime.now()
        
        try:
            for message in self.consumer:
                # Add message to batch
                messages.append(message.value)
                
                # Process batch if it's full or timeout reached
                current_time = datetime.now()
                timeout_reached = (current_time - last_batch_time).total_seconds() * 1000 >= batch_timeout_ms
                
                if len(messages) >= batch_size or timeout_reached:
                    self._process_batch(messages)
                    messages = []
                    last_batch_time = current_time
                    
                    # Log stats periodically
                    self._log_stats()
                    
        except KeyboardInterrupt:
            logger.info("Log aggregator service interrupted")
        except Exception as e:
            logger.error(f"Error in log aggregator service: {e}")
        finally:
            # Process any remaining messages
            if messages:
                self._process_batch(messages)
            
            # Close connections
            self.consumer.close()
    
    def _log_stats(self):
        """Log processing statistics"""
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        
        logger.info(
            f"Stats: {self.stats['logs_processed']} logs processed "
            f"({self.stats['logs_processed']/elapsed:.2f} logs/sec), "
            f"{self.stats['logs_failed']} failed"
        )


if __name__ == "__main__":
    # Create and start log aggregator
    aggregator = LogAggregator()
    aggregator.start()