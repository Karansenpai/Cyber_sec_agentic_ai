"""
Dashboard Service for Monitoring and Reporting
This module integrates with Kibana for visualization and sets up real-time alerts.
"""
import os
import json
import time
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from loguru import logger
from confluent_kafka import Consumer, KafkaError

from src.utils.config import load_config


class DashboardService:
    """
    Dashboard service for monitoring threats and providing real-time alerts.
    Integrates with Kibana for visualizations and sends alerts via multiple channels.
    """
    
    def __init__(self, config_path=None):
        """Initialize the dashboard service."""
        self.config = load_config(config_path)
        
        # Elasticsearch and Kibana configuration
        self.es_host = self.config.get('elasticsearch', {}).get('host', 'http://elasticsearch:9200')
        self.kibana_host = self.config.get('kibana', {}).get('host', 'http://kibana:5601')
        
        # Alert configuration
        self.alert_config = self.config.get('alerts', {})
        self.alert_threshold = self.alert_config.get('severity_threshold', 'high')
        self.email_enabled = self.alert_config.get('email', {}).get('enabled', False)
        self.slack_enabled = self.alert_config.get('slack', {}).get('enabled', False)
        self.webhook_enabled = self.alert_config.get('webhook', {}).get('enabled', False)
        
        # Configure Kafka consumer for decisions
        self.consumer_config = {
            'bootstrap.servers': self.config['kafka']['bootstrap_servers'],
            'group.id': self.config['kafka']['consumer_group'] + '_dashboard',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False
        }
        
        # Rate limiting for alerts
        self.last_alert_time = {}  # Track last alert time by alert type
        self.min_alert_interval = 300  # Minimum seconds between alerts of same type
    
    def setup_kibana_dashboards(self):
        """Setup or update Kibana dashboards for security monitoring."""
        try:
            # Check if Kibana is available
            response = requests.get(f"{self.kibana_host}/api/status", timeout=10)
            if response.status_code != 200:
                logger.error(f"Kibana unavailable: {response.status_code}")
                return False
                
            # Import dashboards and visualizations if available
            dashboard_path = os.path.join(os.path.dirname(__file__), 
                                         '../../config/kibana_dashboards')
            
            if os.path.exists(dashboard_path):
                for filename in os.listdir(dashboard_path):
                    if filename.endswith('.ndjson'):
                        file_path = os.path.join(dashboard_path, filename)
                        with open(file_path, 'rb') as dashboard_file:
                            # Import dashboard to Kibana
                            import_url = f"{self.kibana_host}/api/saved_objects/_import"
                            files = {'file': dashboard_file}
                            params = {'overwrite': 'true'}
                            headers = {'kbn-xsrf': 'true'}
                            
                            import_response = requests.post(
                                import_url, 
                                files=files,
                                params=params,
                                headers=headers
                            )
                            
                            if import_response.status_code == 200:
                                logger.info(f"Imported dashboard: {filename}")
                            else:
                                logger.error(f"Failed to import dashboard {filename}: {import_response.status_code}")
            else:
                logger.warning(f"Kibana dashboard directory not found: {dashboard_path}")
                
            return True
            
        except Exception as e:
            logger.error(f"Error setting up Kibana dashboards: {e}")
            return False
    
    def send_email_alert(self, alert_data):
        """Send an email alert."""
        if not self.email_enabled:
            return False
            
        try:
            email_config = self.alert_config.get('email', {})
            smtp_server = email_config.get('smtp_server')
            smtp_port = email_config.get('smtp_port', 587)
            sender_email = email_config.get('sender_email')
            recipient_emails = email_config.get('recipient_emails', [])
            username = email_config.get('username')
            password = email_config.get('password')
            
            if not (smtp_server and sender_email and recipient_emails and username and password):
                logger.error("Email configuration incomplete, cannot send alert")
                return False
                
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = ', '.join(recipient_emails)
            msg['Subject'] = f"SECURITY ALERT: {alert_data.get('severity')} - {alert_data.get('type')}"
            
            # Email body
            body = f"""
            <h2>Security Alert</h2>
            <p><strong>Severity:</strong> {alert_data.get('severity')}</p>
            <p><strong>Type:</strong> {alert_data.get('type')}</p>
            <p><strong>Description:</strong> {alert_data.get('description')}</p>
            <p><strong>Time:</strong> {alert_data.get('timestamp')}</p>
            <p><strong>Source IP:</strong> {alert_data.get('source_ip')}</p>
            <p><strong>Target:</strong> {alert_data.get('target')}</p>
            <p><strong>Action Taken:</strong> {alert_data.get('action')}</p>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Connect to SMTP server and send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent to {recipient_emails}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False
    
    def send_slack_alert(self, alert_data):
        """Send a Slack alert."""
        if not self.slack_enabled:
            return False
            
        try:
            slack_config = self.alert_config.get('slack', {})
            webhook_url = slack_config.get('webhook_url')
            channel = slack_config.get('channel', '#security-alerts')
            
            if not webhook_url:
                logger.error("Slack webhook URL not configured")
                return False
                
            # Create Slack message
            message = {
                "channel": channel,
                "username": "Security Bot",
                "icon_emoji": ":warning:",
                "attachments": [
                    {
                        "fallback": f"Security Alert: {alert_data.get('type')}",
                        "color": "danger" if alert_data.get('severity') == 'critical' else "warning",
                        "title": f"Security Alert: {alert_data.get('severity')} - {alert_data.get('type')}",
                        "text": alert_data.get('description'),
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert_data.get('severity'),
                                "short": True
                            },
                            {
                                "title": "Time",
                                "value": alert_data.get('timestamp'),
                                "short": True
                            },
                            {
                                "title": "Source IP",
                                "value": alert_data.get('source_ip'),
                                "short": True
                            },
                            {
                                "title": "Target",
                                "value": alert_data.get('target'),
                                "short": True
                            },
                            {
                                "title": "Action Taken",
                                "value": alert_data.get('action'),
                                "short": False
                            }
                        ]
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(webhook_url, json=message)
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent to {channel}")
                return True
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False
    
    def send_webhook_alert(self, alert_data):
        """Send alert to a custom webhook."""
        if not self.webhook_enabled:
            return False
            
        try:
            webhook_config = self.alert_config.get('webhook', {})
            webhook_url = webhook_config.get('url')
            
            if not webhook_url:
                logger.error("Webhook URL not configured")
                return False
                
            # Send to webhook
            response = requests.post(webhook_url, json=alert_data)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"Webhook alert sent to {webhook_url}")
                return True
            else:
                logger.error(f"Failed to send webhook alert: {response.status_code} {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
            return False
    
    def process_alert(self, alert_data):
        """Process an alert and send notifications if needed."""
        severity = alert_data.get('severity', '').lower()
        alert_type = alert_data.get('type', 'unknown')
        
        # Check if this alert exceeds our threshold
        if self._should_send_alert(severity, alert_type):
            # Update last alert time
            self.last_alert_time[alert_type] = time.time()
            
            # Send alerts through configured channels
            if self.email_enabled:
                self.send_email_alert(alert_data)
                
            if self.slack_enabled:
                self.send_slack_alert(alert_data)
                
            if self.webhook_enabled:
                self.send_webhook_alert(alert_data)
    
    def _should_send_alert(self, severity, alert_type):
        """Determine if an alert should be sent based on severity and rate limiting."""
        # Check severity threshold
        severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        threshold_level = severity_levels.get(self.alert_threshold.lower(), 3)  # Default to high
        alert_level = severity_levels.get(severity.lower(), 1)  # Default to low
        
        if alert_level < threshold_level:
            return False
            
        # Check rate limiting
        current_time = time.time()
        last_time = self.last_alert_time.get(alert_type, 0)
        
        if (current_time - last_time) < self.min_alert_interval:
            logger.info(f"Rate limiting alert of type {alert_type}")
            return False
            
        return True
    
    def start_monitoring(self):
        """Start the monitoring and alerting service."""
        try:
            # Setup Kibana dashboards
            self.setup_kibana_dashboards()
            
            # Create Kafka consumer
            consumer = Consumer(self.consumer_config)
            
            # Subscribe to decisions and alerts topics
            topics = [
                self.config['kafka']['topics'].get('decisions', 'decisions'),
                self.config['kafka']['topics'].get('alerts', 'system_alerts')
            ]
            consumer.subscribe(topics)
            
            logger.info(f"Starting monitoring service, listening on topics: {topics}")
            
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
                    # Process the message
                    data = json.loads(msg.value().decode('utf-8'))
                    
                    # Add timestamp if not present
                    if 'timestamp' not in data:
                        data['timestamp'] = datetime.now().isoformat()
                        
                    # Process as an alert if it meets our criteria
                    if 'severity' in data and 'type' in data:
                        logger.info(f"Processing potential alert: {data}")
                        self.process_alert(data)
                    
                    # Commit offset
                    consumer.commit(msg)
                    
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    
        except KeyboardInterrupt:
            logger.info("Shutting down monitoring service")
        finally:
            consumer.close()

if __name__ == "__main__":
    # Example usage
    dashboard = DashboardService()
    dashboard.start_monitoring()