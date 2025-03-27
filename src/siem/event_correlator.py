"""
Event Correlator for SIEM System

This module analyzes security events and logs to identify
relationships between them, detect attack patterns, and
create higher-level security incidents from related events.
"""

import json
import time
import uuid
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch, helpers
from loguru import logger
import os
import sys

# Add the parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.config import load_config


class EventCorrelator:
    """
    Correlates security events to identify attack patterns and create incidents.
    
    This class applies correlation rules to events stored in Elasticsearch to:
    - Group related events by common attributes (IPs, users, time windows)
    - Detect attack patterns using temporal and behavioral analysis
    - Generate high-level security incidents from correlated events
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the event correlator
        
        Args:
            config_path: Path to configuration file
        """
        # Load configuration
        self.config = load_config(config_path)
        
        # Configure logging
        logger.info("Initializing Event Correlator")
        
        # Initialize Elasticsearch client
        es_hosts = self.config['elasticsearch']['hosts']
        self.es = Elasticsearch(es_hosts)
        
        # Index prefix for logs
        self.index_prefix = self.config['elasticsearch']['index_prefix']
        
        # Check Elasticsearch connection
        if not self.es.ping():
            logger.error("Cannot connect to Elasticsearch")
            raise ConnectionError("Cannot connect to Elasticsearch")
            
        logger.info("Connected to Elasticsearch successfully")
        
        # Load correlation rules
        self.rules = self._load_default_rules()
        
        # State for tracking ongoing correlations
        self.active_correlations = {}
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'correlations_created': 0,
            'incidents_created': 0,
            'start_time': datetime.now()
        }
    
    def _load_default_rules(self):
        """
        Load default correlation rules
        
        Returns:
            list: Default correlation rules
        """
        return [
            {
                "id": "brute_force",
                "name": "Brute Force Login Detection",
                "description": "Detect multiple failed login attempts from same source",
                "conditions": {
                    "event_type": "login_failure",
                    "count_threshold": 5,
                    "time_window_minutes": 10,
                    "group_by": ["source_ip", "username"]
                },
                "severity": "high"
            },
            {
                "id": "lateral_movement",
                "name": "Lateral Movement Detection",
                "description": "Detect successful logins from unusual hosts after suspicious activities",
                "conditions": {
                    "sequence": [
                        {"log_type": "network_log", "protocol": "ssh"},
                        {"log_type": "user_event", "event_type": "login_success", "timeframe_minutes": 10}
                    ],
                    "group_by": ["destination_ip", "username"]
                },
                "severity": "critical"
            },
            {
                "id": "port_scan",
                "name": "Port Scanning Detection",
                "description": "Detect connections to multiple ports from single source",
                "conditions": {
                    "log_type": "network_log",
                    "unique_count_field": "destination_port",
                    "unique_count_threshold": 10,
                    "time_window_minutes": 5,
                    "group_by": ["source_ip"]
                },
                "severity": "medium"
            },
            {
                "id": "data_exfiltration",
                "name": "Potential Data Exfiltration",
                "description": "Detect unusually large outbound data transfers",
                "conditions": {
                    "log_type": "network_log",
                    "bytes_sent_threshold": 10000000,  # 10 MB
                    "direction": "outbound",
                    "time_window_minutes": 15
                },
                "severity": "high"
            },
            {
                "id": "suspicious_process_chain",
                "name": "Suspicious Process Chain",
                "description": "Detect suspicious process execution patterns",
                "conditions": {
                    "log_type": "system_alert",
                    "alert_type": "process_execution",
                    "sequence_patterns": ["cmd.exe", "powershell.exe", "*download*"],
                    "time_window_minutes": 15,
                    "group_by": ["affected_system"]
                },
                "severity": "high"
            },
            {
                "id": "anomaly_with_alert",
                "name": "Anomaly with Security Alert",
                "description": "Detect when an anomaly is followed by a security alert",
                "conditions": {
                    "sequence": [
                        {"log_type": "anomaly"},
                        {"log_type": "system_alert", "timeframe_minutes": 30}
                    ],
                    "group_by": ["affected_system", "source_ip"]
                },
                "severity": "high"
            }
        ]
    
    def add_rule(self, rule):
        """
        Add a new correlation rule
        
        Args:
            rule (dict): Rule definition
        """
        # Validate rule format
        required_fields = ["id", "name", "description", "conditions", "severity"]
        for field in required_fields:
            if field not in rule:
                logger.error(f"Rule is missing required field: {field}")
                return False
        
        # Check if rule already exists
        for existing_rule in self.rules:
            if existing_rule["id"] == rule["id"]:
                logger.warning(f"Rule with ID '{rule['id']}' already exists. Updating.")
                self.rules.remove(existing_rule)
                break
                
        # Add the rule
        self.rules.append(rule)
        logger.info(f"Added correlation rule: {rule['name']}")
        return True
    
    def start(self, interval_seconds=60):
        """
        Start the event correlator service
        
        Args:
            interval_seconds (int): How often to run correlation analysis
        """
        logger.info("Starting event correlator service")
        
        try:
            while True:
                # Process events and correlate
                self._process_events()
                
                # Log stats periodically
                self._log_stats()
                
                # Wait for next interval
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            logger.info("Event correlator service interrupted")
        except Exception as e:
            logger.error(f"Error in event correlator service: {e}")
    
    def _process_events(self):
        """Process events and apply correlation rules"""
        logger.debug("Processing events for correlation")
        
        # Apply each rule
        for rule in self.rules:
            try:
                # Apply the rule
                self._apply_rule(rule)
            except Exception as e:
                logger.error(f"Error applying rule {rule['id']}: {e}")
    
    def _apply_rule(self, rule):
        """
        Apply a correlation rule to events
        
        Args:
            rule (dict): Rule definition
        """
        rule_id = rule["id"]
        conditions = rule["conditions"]
        
        # Different types of rules require different processing
        if "sequence" in conditions:
            self._apply_sequence_rule(rule)
        elif "count_threshold" in conditions:
            self._apply_threshold_rule(rule)
        elif "unique_count_field" in conditions:
            self._apply_unique_count_rule(rule)
        elif "bytes_sent_threshold" in conditions:
            self._apply_threshold_field_rule(rule)
        else:
            logger.warning(f"Unknown rule type for rule {rule_id}")
    
    def _apply_threshold_rule(self, rule):
        """
        Apply threshold-based correlation rule
        
        Args:
            rule (dict): Rule definition
        """
        conditions = rule["conditions"]
        event_type = conditions.get("event_type")
        count_threshold = conditions.get("count_threshold", 5)
        time_window = conditions.get("time_window_minutes", 10)
        group_by = conditions.get("group_by", [])
        
        # Create the Elasticsearch query
        now = datetime.now()
        time_from = (now - timedelta(minutes=time_window)).isoformat()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                    ]
                }
            },
            "aggs": {
                "group_by": {
                    "composite": {
                        "size": 1000,
                        "sources": [
                            {field: {"terms": {"field": field}}} for field in group_by
                        ]
                    },
                    "aggs": {
                        "event_count": {"value_count": {"field": "@timestamp"}}
                    }
                }
            },
            "size": 0  # We only need the aggregation results
        }
        
        # Add event type condition if specified
        if event_type:
            query["query"]["bool"]["must"].append({"term": {"event_type": event_type}})
        
        # Execute the query
        indices = [f"{self.index_prefix}_user_events", f"{self.index_prefix}_system_alerts"]
        response = self.es.search(index=",".join(indices), body=query)
        
        # Check aggregation results
        buckets = response["aggregations"]["group_by"]["buckets"]
        for bucket in buckets:
            count = bucket["event_count"]["value"]
            key_values = bucket["key"]
            
            if count >= count_threshold:
                # Create a correlation ID for this group
                correlation_key = f"{rule['id']}_{'-'.join([str(key_values[k]) for k in key_values])}"
                
                # Check if this is a new correlation or ongoing
                if correlation_key not in self.active_correlations:
                    # Create a new correlation incident
                    self._create_incident(rule, key_values, count)
                    
                    # Mark this as an active correlation
                    self.active_correlations[correlation_key] = {
                        "rule_id": rule["id"],
                        "first_seen": now,
                        "last_updated": now,
                        "count": count,
                        "status": "active"
                    }
                else:
                    # Update existing correlation
                    previous_count = self.active_correlations[correlation_key]["count"]
                    if count > previous_count:
                        # Update the incident with new information
                        self._update_incident(rule, key_values, count - previous_count)
                        
                        # Update the active correlation
                        self.active_correlations[correlation_key]["count"] = count
                        self.active_correlations[correlation_key]["last_updated"] = now
    
    def _apply_sequence_rule(self, rule):
        """
        Apply sequence-based correlation rule
        
        Args:
            rule (dict): Rule definition
        """
        conditions = rule["conditions"]
        sequence = conditions.get("sequence", [])
        group_by = conditions.get("group_by", [])
        
        if not sequence or len(sequence) < 2:
            logger.warning(f"Invalid sequence rule {rule['id']}: needs at least 2 events")
            return
        
        # Process first event in sequence
        first_event = sequence[0]
        second_event = sequence[1]
        timeframe = second_event.get("timeframe_minutes", 30)
        
        # Find matches for the first event
        first_results = self._find_events(first_event)
        
        # For each first event match, look for corresponding second events
        for first_match in first_results:
            # Extract fields for grouping
            group_values = {}
            for field in group_by:
                if field in first_match:
                    group_values[field] = first_match[field]
            
            # Skip if we can't extract group values
            if len(group_values) != len(group_by):
                continue
            
            # Find matching second events within timeframe
            timestamp = first_match.get("@timestamp")
            if not timestamp:
                continue
                
            # Convert timestamp to datetime if it's a string
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                
            time_from = timestamp.isoformat()
            time_to = (timestamp + timedelta(minutes=timeframe)).isoformat()
            
            # Add time constraints and group constraints to second event
            second_event_query = second_event.copy()
            second_event_query["@timestamp_range"] = {"gte": time_from, "lte": time_to}
            
            # Add group_by constraints
            for field, value in group_values.items():
                second_event_query[field] = value
            
            # Find matching second events
            second_results = self._find_events(second_event_query)
            
            if second_results:
                # We have a sequence match
                correlation_key = f"{rule['id']}_{'-'.join([str(group_values[k]) for k in group_values])}"
                
                # Check if this is a new correlation or ongoing
                if correlation_key not in self.active_correlations:
                    # Create a new correlation incident
                    self._create_incident(
                        rule, 
                        group_values, 
                        len(second_results),
                        [first_match] + second_results
                    )
                    
                    # Mark this as an active correlation
                    self.active_correlations[correlation_key] = {
                        "rule_id": rule["id"],
                        "first_seen": datetime.now(),
                        "last_updated": datetime.now(),
                        "count": len(second_results),
                        "events": [first_match["_id"]] + [e["_id"] for e in second_results],
                        "status": "active"
                    }
    
    def _apply_unique_count_rule(self, rule):
        """
        Apply unique count based correlation rule
        
        Args:
            rule (dict): Rule definition
        """
        conditions = rule["conditions"]
        log_type = conditions.get("log_type")
        field = conditions.get("unique_count_field")
        threshold = conditions.get("unique_count_threshold", 10)
        time_window = conditions.get("time_window_minutes", 5)
        group_by = conditions.get("group_by", [])
        
        if not field:
            logger.warning(f"Invalid unique count rule {rule['id']}: missing unique_count_field")
            return
        
        # Create the Elasticsearch query
        now = datetime.now()
        time_from = (now - timedelta(minutes=time_window)).isoformat()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"log_type": log_type}}
                    ]
                }
            },
            "aggs": {
                "group_by": {
                    "composite": {
                        "size": 1000,
                        "sources": [
                            {group_field: {"terms": {"field": group_field}}} for group_field in group_by
                        ]
                    },
                    "aggs": {
                        "unique_values": {"cardinality": {"field": field}}
                    }
                }
            },
            "size": 0  # We only need the aggregation results
        }
        
        # Determine the index based on log type
        index = f"{self.index_prefix}_{log_type.replace('_log', '_logs')}"
        
        # Execute the query
        response = self.es.search(index=index, body=query)
        
        # Check aggregation results
        buckets = response["aggregations"]["group_by"]["buckets"]
        for bucket in buckets:
            unique_count = bucket["unique_values"]["value"]
            key_values = bucket["key"]
            
            if unique_count >= threshold:
                # Create a correlation ID for this group
                correlation_key = f"{rule['id']}_{'-'.join([str(key_values[k]) for k in key_values])}"
                
                # Check if this is a new correlation or ongoing
                if correlation_key not in self.active_correlations:
                    # Create a new correlation incident
                    self._create_incident(rule, key_values, unique_count)
                    
                    # Mark this as an active correlation
                    self.active_correlations[correlation_key] = {
                        "rule_id": rule["id"],
                        "first_seen": now,
                        "last_updated": now,
                        "count": unique_count,
                        "status": "active"
                    }
                else:
                    # Update existing correlation if count increased significantly
                    previous_count = self.active_correlations[correlation_key]["count"]
                    if unique_count > previous_count * 1.2:  # 20% increase
                        # Update the incident with new information
                        self._update_incident(rule, key_values, unique_count - previous_count)
                        
                        # Update the active correlation
                        self.active_correlations[correlation_key]["count"] = unique_count
                        self.active_correlations[correlation_key]["last_updated"] = now
    
    def _apply_threshold_field_rule(self, rule):
        """
        Apply threshold on specific field correlation rule
        
        Args:
            rule (dict): Rule definition
        """
        conditions = rule["conditions"]
        log_type = conditions.get("log_type")
        time_window = conditions.get("time_window_minutes", 15)
        
        # Create the Elasticsearch query
        now = datetime.now()
        time_from = (now - timedelta(minutes=time_window)).isoformat()
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_from}}},
                        {"term": {"log_type": log_type}}
                    ]
                }
            },
            "size": 100,  # Limit results
            "sort": [{"@timestamp": {"order": "desc"}}]  # Most recent first
        }
        
        # Add bytes threshold if this is a data exfiltration rule
        if "bytes_sent_threshold" in conditions:
            threshold = conditions["bytes_sent_threshold"]
            query["query"]["bool"]["must"].append(
                {"range": {"bytes_sent": {"gte": threshold}}}
            )
            
            # Add direction filter if specified
            if "direction" in conditions:
                if conditions["direction"] == "outbound":
                    # For outbound, destination is external
                    # This is simplified - typically you'd have a list of internal networks
                    query["query"]["bool"]["must_not"] = [
                        {"prefix": {"destination_ip": "10."}},
                        {"prefix": {"destination_ip": "192.168."}},
                        {"prefix": {"destination_ip": "172.16."}}
                    ]
                elif conditions["direction"] == "inbound":
                    # For inbound, source is external
                    query["query"]["bool"]["must_not"] = [
                        {"prefix": {"source_ip": "10."}},
                        {"prefix": {"source_ip": "192.168."}},
                        {"prefix": {"source_ip": "172.16."}}
                    ]
        
        # Determine the index based on log type
        index = f"{self.index_prefix}_{log_type.replace('_log', '_logs')}"
        
        # Execute the query
        response = self.es.search(index=index, body=query)
        
        # Process matching events
        hits = response["hits"]["hits"]
        if hits:
            for hit in hits:
                source = hit["_source"]
                
                # Create a correlation key
                correlation_key = f"{rule['id']}_{source.get('source_ip', 'unknown')}_{source.get('destination_ip', 'unknown')}"
                
                # Check if this is a new correlation
                if correlation_key not in self.active_correlations:
                    # Create a new correlation incident
                    event_data = {
                        "source_ip": source.get("source_ip", "unknown"),
                        "destination_ip": source.get("destination_ip", "unknown"),
                        "bytes": source.get("bytes_sent", 0)
                    }
                    
                    self._create_incident(rule, event_data, 1, [source])
                    
                    # Mark this as an active correlation
                    self.active_correlations[correlation_key] = {
                        "rule_id": rule["id"],
                        "first_seen": now,
                        "last_updated": now,
                        "status": "active"
                    }
    
    def _find_events(self, event_criteria):
        """
        Find events matching given criteria
        
        Args:
            event_criteria (dict): Criteria to match events
            
        Returns:
            list: Matching events
        """
        query = {
            "query": {
                "bool": {
                    "must": []
                }
            },
            "size": 100,  # Limit results
            "sort": [{"@timestamp": {"order": "desc"}}]  # Most recent first
        }
        
        # Add criteria to query
        for key, value in event_criteria.items():
            if key == "timeframe_minutes":
                continue  # Skip special keys
            elif key == "@timestamp_range":
                query["query"]["bool"]["must"].append(
                    {"range": {"@timestamp": value}}
                )
            else:
                query["query"]["bool"]["must"].append(
                    {"term": {key: value}}
                )
        
        # Determine index based on log type
        log_type = event_criteria.get("log_type", "")
        if log_type == "network_log":
            index = f"{self.index_prefix}_network_logs"
        elif log_type == "system_alert":
            index = f"{self.index_prefix}_system_alerts"
        elif log_type == "user_event":
            index = f"{self.index_prefix}_user_events"
        elif log_type == "anomaly":
            index = f"{self.index_prefix}_anomalies"
        else:
            # Search across all indices
            index = f"{self.index_prefix}_*"
        
        # Execute the query
        try:
            response = self.es.search(index=index, body=query)
            
            # Extract and return events
            return [hit for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error searching for events: {e}")
            return []
    
    def _create_incident(self, rule, event_data, count, related_events=None):
        """
        Create a new security incident from correlated events
        
        Args:
            rule (dict): Rule that triggered
            event_data (dict): Data for the incident
            count (int): Number of events correlated
            related_events (list): Related events that triggered this incident
        """
        try:
            event_id = str(uuid.uuid4())
            
            # Basic incident data
            incident = {
                "event_id": event_id,
                "correlation_id": f"{rule['id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "@timestamp": datetime.now().isoformat(),
                "log_type": "siem_event",
                "log_source": "event_correlator",
                "severity": rule["severity"],
                "status": "new",
                "message": f"{rule['name']}: {rule['description']}",
                "rule_id": rule["id"],
                "event_count": count,
                "related_events": []
            }
            
            # Add data from the events that triggered this
            incident.update(event_data)
            
            # Add related event IDs if provided
            if related_events:
                incident["related_events"] = [
                    e.get("_id", "unknown") for e in related_events
                ]
                
                # Add more context from related events
                related_ips = set()
                related_users = set()
                related_systems = set()
                
                for event in related_events:
                    source = event.get("_source", {})
                    
                    # Collect related IPs
                    src_ip = source.get("source_ip")
                    dst_ip = source.get("destination_ip")
                    if src_ip:
                        related_ips.add(src_ip)
                    if dst_ip:
                        related_ips.add(dst_ip)
                        
                    # Collect related users
                    username = source.get("username")
                    if username:
                        related_users.add(username)
                        
                    # Collect related systems
                    system = source.get("affected_system")
                    if system:
                        related_systems.add(system)
                
                # Add collected data to incident
                if related_ips:
                    incident["related_ips"] = list(related_ips)
                if related_users:
                    incident["related_users"] = list(related_users)
                if related_systems:
                    incident["related_systems"] = list(related_systems)
            
            # Calculate priority based on severity and count
            priority_map = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 4
            }
            base_priority = priority_map.get(rule["severity"].lower(), 2)
            
            # Increase priority for higher event counts
            if count >= 50:
                priority_factor = 1.5
            elif count >= 20:
                priority_factor = 1.3
            elif count >= 10:
                priority_factor = 1.2
            else:
                priority_factor = 1.0
                
            incident["priority"] = min(int(base_priority * priority_factor), 4)
            
            # Index the incident
            self.es.index(
                index=f"{self.index_prefix}_siem_events",
                id=event_id,
                body=incident
            )
            
            logger.info(f"Created new security incident: {rule['name']} with ID {event_id}")
            self.stats["incidents_created"] += 1
            self.stats["correlations_created"] += 1
            
        except Exception as e:
            logger.error(f"Error creating incident: {e}")
    
    def _update_incident(self, rule, event_data, new_count):
        """
        Update an existing security incident with new information
        
        Args:
            rule (dict): Rule that triggered
            event_data (dict): Data for the incident
            new_count (int): Number of new events
        """
        try:
            # Find the existing incident
            correlation_key = f"{rule['id']}_{'-'.join([str(event_data[k]) for k in event_data])}"
            
            # Create query to find the incident
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"rule_id": rule["id"]}},
                            {"term": {"status": "new"}}
                        ]
                    }
                },
                "sort": [
                    {"@timestamp": {"order": "desc"}}
                ],
                "size": 1
            }
            
            # Add event data to query
            for key, value in event_data.items():
                query["query"]["bool"]["must"].append({"term": {key: value}})
            
            # Find the incident
            result = self.es.search(
                index=f"{self.index_prefix}_siem_events",
                body=query
            )
            
            hits = result["hits"]["hits"]
            if not hits:
                logger.warning(f"Could not find existing incident for update: {correlation_key}")
                return
            
            # Get the incident ID and data
            incident_id = hits[0]["_id"]
            incident = hits[0]["_source"]
            
            # Update the event count
            incident["event_count"] += new_count
            
            # Update last updated timestamp
            incident["last_updated"] = datetime.now().isoformat()
            
            # Increase priority if necessary
            if new_count >= 20:
                incident["priority"] = min(incident["priority"] + 1, 4)
                
            # Update the incident
            self.es.update(
                index=f"{self.index_prefix}_siem_events",
                id=incident_id,
                body={"doc": incident}
            )
            
            logger.info(f"Updated security incident {incident_id} with {new_count} new events")
            
        except Exception as e:
            logger.error(f"Error updating incident: {e}")
    
    def _clean_stale_correlations(self, max_age_hours=24):
        """
        Clean up stale correlations that haven't been updated
        
        Args:
            max_age_hours (int): Maximum age in hours for correlations
        """
        now = datetime.now()
        stale_keys = []
        
        # Find stale correlations
        for key, data in self.active_correlations.items():
            last_updated = data["last_updated"]
            if isinstance(last_updated, str):
                last_updated = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                
            age_hours = (now - last_updated).total_seconds() / 3600
            
            if age_hours >= max_age_hours:
                stale_keys.append(key)
        
        # Remove stale correlations
        for key in stale_keys:
            del self.active_correlations[key]
            
        if stale_keys:
            logger.info(f"Cleaned up {len(stale_keys)} stale correlations")
    
    def _log_stats(self):
        """Log processing statistics"""
        elapsed = (datetime.now() - self.stats['start_time']).total_seconds()
        
        logger.info(f"Stats: {self.stats['incidents_created']} incidents created, "
                   f"{self.stats['correlations_created']} correlations detected, "
                   f"{len(self.active_correlations)} active correlations")
        
        # Clean up stale correlations
        self._clean_stale_correlations()


if __name__ == "__main__":
    # Create and start event correlator
    correlator = EventCorrelator()
    correlator.start(interval_seconds=60)