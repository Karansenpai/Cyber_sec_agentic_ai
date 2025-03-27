#!/usr/bin/env python
"""
Kafka Producer for Cybersecurity Data

This module simulates various data sources sending logs and events to Kafka topics.
It generates synthetic cybersecurity data for testing and development purposes.
"""

import time
import json
import random
import ipaddress
import datetime
from loguru import logger
from confluent_kafka import Producer
from faker import Faker

# Import utilities
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.config import load_config

# Initialize faker for generating realistic data
fake = Faker()


class CyberSecurityProducer:
    """Producer class for generating cybersecurity data and sending to Kafka"""

    def __init__(self, config_path=None):
        """Initialize the producer with configuration"""
        self.config = load_config(config_path)
        self.producer_config = {
            'bootstrap.servers': self.config['kafka']['bootstrap_servers'],
            'client.id': 'cyber-security-producer'
        }
        self.producer = Producer(self.producer_config)
        logger.info("CyberSecurity Kafka Producer initialized")

    def delivery_report(self, err, msg):
        """Callback for message delivery reports"""
        if err is not None:
            logger.error(f"Message delivery failed: {err}")
        else:
            logger.debug(f"Message delivered to {msg.topic()} [{msg.partition()}] at offset {msg.offset()}")

    def generate_network_log(self):
        """Generate a synthetic network log"""
        protocols = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'DNS', 'SMTP', 'POP3', 'IMAP']
        source_port = random.randint(49152, 65535)
        dest_port = random.choice([21, 22, 25, 53, 80, 443, 110, 143, 3306, 5432])
        
        log_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'source_ip': str(fake.ipv4()),
            'destination_ip': str(fake.ipv4()),
            'source_port': source_port,
            'destination_port': dest_port,
            'protocol': random.choice(protocols),
            'bytes_sent': random.randint(60, 9000),
            'bytes_received': random.randint(60, 9000),
            'duration_ms': random.randint(1, 10000),
            'status': random.choice(['SUCCESS', 'FAILURE', 'TIMEOUT']),
            'user_agent': fake.user_agent() if random.random() < 0.8 else None
        }
        return log_entry

    def generate_system_alert(self):
        """Generate a synthetic system alert"""
        alert_types = [
            'High CPU Usage', 'Memory Leak', 'Disk Space Low',
            'Connection Refused', 'Unauthorized Access Attempt',
            'Suspicious File Activity', 'Failed Login',
            'Malware Detected', 'Unusual Network Traffic'
        ]
        
        severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        severity_weights = [0.5, 0.3, 0.15, 0.05]  # Adjust probability of different severities
        
        alert_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'alert_type': random.choice(alert_types),
            'severity': random.choices(severity_levels, weights=severity_weights)[0],
            'source': fake.hostname(),
            'message': fake.text(max_nb_chars=100),
            'affected_system': fake.domain_name() if random.random() < 0.5 else None,
            'affected_user': fake.user_name() if random.random() < 0.7 else None,
            'alert_id': fake.uuid4()
        }
        return alert_entry

    def generate_user_event(self):
        """Generate a synthetic user event"""
        event_types = [
            'LOGIN', 'LOGOUT', 'PASSWORD_CHANGE', 'FILE_ACCESS',
            'ADMIN_ACTION', 'PERMISSION_CHANGE', 'ACCOUNT_CREATION',
            'DATA_EXPORT', 'PROFILE_UPDATE'
        ]
        
        event_entry = {
            'timestamp': datetime.datetime.now().isoformat(),
            'user_id': fake.uuid4(),
            'username': fake.user_name(),
            'event_type': random.choice(event_types),
            'ip_address': str(fake.ipv4()),
            'device_info': {
                'os': random.choice(['Windows 10', 'macOS', 'Linux', 'iOS', 'Android']),
                'browser': random.choice(['Chrome', 'Firefox', 'Safari', 'Edge']),
            },
            'success': random.random() < 0.95,  # 95% successful events
            'details': fake.text(max_nb_chars=50) if random.random() < 0.5 else None
        }
        return event_entry

    def produce_messages(self):
        """Main loop to produce messages to Kafka topics"""
        try:
            # Get simulation rates from config
            network_logs_per_minute = self.config['simulation']['network_logs_per_minute']
            system_alerts_per_minute = self.config['simulation']['system_alerts_per_minute']
            user_events_per_minute = self.config['simulation']['user_events_per_minute']
            
            # Calculate sleep times
            network_sleep = 60.0 / max(1, network_logs_per_minute)
            alerts_sleep = 60.0 / max(1, system_alerts_per_minute)
            events_sleep = 60.0 / max(1, user_events_per_minute)
            
            # Get topic names from config
            network_topic = self.config['kafka']['topics']['network_logs']
            alerts_topic = self.config['kafka']['topics']['system_alerts']
            events_topic = self.config['kafka']['topics']['user_events']
            
            network_last_time = alerts_last_time = events_last_time = time.time()
            
            logger.info("Starting to produce messages...")
            while True:
                current_time = time.time()
                
                # Produce network logs
                if current_time - network_last_time >= network_sleep:
                    network_log = self.generate_network_log()
                    self.producer.produce(
                        network_topic,
                        json.dumps(network_log).encode('utf-8'),
                        callback=self.delivery_report
                    )
                    network_last_time = current_time
                
                # Produce system alerts
                if current_time - alerts_last_time >= alerts_sleep:
                    system_alert = self.generate_system_alert()
                    self.producer.produce(
                        alerts_topic,
                        json.dumps(system_alert).encode('utf-8'),
                        callback=self.delivery_report
                    )
                    alerts_last_time = current_time
                
                # Produce user events
                if current_time - events_last_time >= events_sleep:
                    user_event = self.generate_user_event()
                    self.producer.produce(
                        events_topic,
                        json.dumps(user_event).encode('utf-8'),
                        callback=self.delivery_report
                    )
                    events_last_time = current_time
                
                # Poll to handle delivery reports
                self.producer.poll(0)
                
                # Small sleep to prevent CPU hogging
                time.sleep(0.01)
                
        except KeyboardInterrupt:
            logger.info("Producer interrupted by user")
        except Exception as e:
            logger.error(f"Unexpected error in producer: {e}")
        finally:
            # Make sure all messages are sent
            logger.info("Flushing producer messages...")
            self.producer.flush()
            logger.info("Producer shut down")


if __name__ == "__main__":
    try:
        logger.info("Starting Cybersecurity Data Producer")
        producer = CyberSecurityProducer()
        producer.produce_messages()
    except Exception as e:
        logger.error(f"Failed to start producer: {e}")