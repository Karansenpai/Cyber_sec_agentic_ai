"""
Dashboard API for SIEM System

This module provides REST API endpoints for accessing SIEM data,
powering the security dashboard and allowing integration with
other security tools.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from elasticsearch import Elasticsearch
from loguru import logger
import uvicorn
from pydantic import BaseModel, Field

# Add the parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.utils.config import load_config


# Initialize FastAPI app
app = FastAPI(
    title="Cybersecurity SIEM API",
    description="API for cybersecurity SIEM dashboard and integrations",
    version="1.0.0"
)

# Add CORS middleware to allow cross-origin requests (for web dashboard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to your dashboard domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response validation
class IncidentResponse(BaseModel):
    event_id: str
    correlation_id: str
    timestamp: str = Field(alias='@timestamp')
    severity: str
    status: str
    message: str
    rule_id: str
    priority: int
    event_count: int
    related_events: List[str] = []
    related_ips: List[str] = []
    related_users: List[str] = []
    related_systems: List[str] = []
    
class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    resolution: Optional[str] = None

class SearchQuery(BaseModel):
    query_string: str
    time_from: Optional[str] = None
    time_to: Optional[str] = None
    indices: Optional[List[str]] = None
    size: Optional[int] = 100

class DashboardStats(BaseModel):
    total_events: int
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    top_sources: List[Dict[str, Any]]
    top_destinations: List[Dict[str, Any]]
    recent_events: List[Dict[str, Any]]


# Global variables
es_client = None
config = None
index_prefix = None


@app.on_event("startup")
def startup_event():
    """Initialize API on startup"""
    global es_client, config, index_prefix
    
    try:
        # Load configuration
        config = load_config()
        
        # Initialize Elasticsearch client
        es_hosts = config['elasticsearch']['hosts']
        es_client = Elasticsearch(es_hosts)
        
        # Index prefix for logs
        index_prefix = config['elasticsearch']['index_prefix']
        
        # Check Elasticsearch connection
        if not es_client.ping():
            logger.error("Cannot connect to Elasticsearch")
            raise ConnectionError("Cannot connect to Elasticsearch")
            
        logger.info("Dashboard API connected to Elasticsearch successfully")
        
    except Exception as e:
        logger.error(f"Error initializing dashboard API: {e}")
        # Let FastAPI handle the error


@app.get("/", tags=["Health"])
def health_check():
    """API health check endpoint"""
    return {"status": "operational", "version": "1.0.0"}


@app.get("/api/stats/dashboard", response_model=DashboardStats, tags=["Dashboard"])
def get_dashboard_stats(time_range: str = "24h"):
    """
    Get overview statistics for the dashboard
    
    Args:
        time_range: Time range (1h, 24h, 7d, 30d)
    """
    try:
        # Calculate time range
        now = datetime.now()
        if time_range == "1h":
            time_from = (now - timedelta(hours=1)).isoformat()
        elif time_range == "7d":
            time_from = (now - timedelta(days=7)).isoformat()
        elif time_range == "30d":
            time_from = (now - timedelta(days=30)).isoformat()
        else:  # Default is 24h
            time_from = (now - timedelta(days=1)).isoformat()
        
        # Get total events
        events_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_from
                    }
                }
            },
            "size": 0
        }
        
        events_result = es_client.search(
            index=f"{index_prefix}_*",
            body=events_query
        )
        total_events = events_result["hits"]["total"]["value"]
        
        # Get incident stats
        incidents_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_from
                    }
                }
            },
            "aggs": {
                "by_status": {
                    "terms": {
                        "field": "status",
                        "size": 10
                    }
                },
                "by_severity": {
                    "terms": {
                        "field": "severity",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        incidents_result = es_client.search(
            index=f"{index_prefix}_siem_events",
            body=incidents_query
        )
        
        # Extract incident counts
        total_incidents = incidents_result["hits"]["total"]["value"]
        
        # Count open incidents (status = new or in_progress)
        open_incidents = 0
        for bucket in incidents_result["aggregations"]["by_status"]["buckets"]:
            if bucket["key"] in ["new", "in_progress"]:
                open_incidents += bucket["doc_count"]
        
        # Count by severity
        critical_incidents = 0
        high_incidents = 0
        medium_incidents = 0
        low_incidents = 0
        
        for bucket in incidents_result["aggregations"]["by_severity"]["buckets"]:
            if bucket["key"] == "critical":
                critical_incidents = bucket["doc_count"]
            elif bucket["key"] == "high":
                high_incidents = bucket["doc_count"]
            elif bucket["key"] == "medium":
                medium_incidents = bucket["doc_count"]
            elif bucket["key"] == "low":
                low_incidents = bucket["doc_count"]
        
        # Get top source IPs
        top_sources_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_from
                                }
                            }
                        },
                        {
                            "exists": {
                                "field": "source_ip"
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "top_sources": {
                    "terms": {
                        "field": "source_ip",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        top_sources_result = es_client.search(
            index=f"{index_prefix}_network_logs",
            body=top_sources_query
        )
        
        top_sources = [
            {"ip": bucket["key"], "count": bucket["doc_count"]}
            for bucket in top_sources_result["aggregations"]["top_sources"]["buckets"]
        ]
        
        # Get top destination IPs
        top_dest_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_from
                                }
                            }
                        },
                        {
                            "exists": {
                                "field": "destination_ip"
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "top_destinations": {
                    "terms": {
                        "field": "destination_ip",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        top_dest_result = es_client.search(
            index=f"{index_prefix}_network_logs",
            body=top_dest_query
        )
        
        top_destinations = [
            {"ip": bucket["key"], "count": bucket["doc_count"]}
            for bucket in top_dest_result["aggregations"]["top_destinations"]["buckets"]
        ]
        
        # Get recent events
        recent_events_query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_from
                    }
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": 10
        }
        
        recent_events_result = es_client.search(
            index=f"{index_prefix}_siem_events",
            body=recent_events_query
        )
        
        recent_events = [hit["_source"] for hit in recent_events_result["hits"]["hits"]]
        
        # Return stats
        return {
            "total_events": total_events,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "high_incidents": high_incidents,
            "medium_incidents": medium_incidents,
            "low_incidents": low_incidents,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "recent_events": recent_events
        }
        
    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/incidents", tags=["Incidents"])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    assigned_to: Optional[str] = None,
    rule_id: Optional[str] = None,
    size: int = 100,
    from_: int = Query(0, alias="from")
):
    """
    Get security incidents with optional filters
    
    Args:
        status: Filter by status (new, in_progress, resolved, false_positive)
        severity: Filter by severity (critical, high, medium, low)
        time_from: Filter by time from (ISO format)
        time_to: Filter by time to (ISO format)
        assigned_to: Filter by assigned analyst
        rule_id: Filter by rule ID
        size: Number of results to return
        from_: Starting position for pagination
    """
    try:
        # Build the query
        query = {
            "query": {
                "bool": {
                    "must": []
                }
            },
            "sort": [
                {"priority": {"order": "desc"}},
                {"@timestamp": {"order": "desc"}}
            ],
            "size": size,
            "from": from_
        }
        
        # Add filters
        if status:
            query["query"]["bool"]["must"].append({"term": {"status": status}})
        
        if severity:
            query["query"]["bool"]["must"].append({"term": {"severity": severity}})
        
        if time_from or time_to:
            time_range = {"range": {"@timestamp": {}}}
            if time_from:
                time_range["range"]["@timestamp"]["gte"] = time_from
            if time_to:
                time_range["range"]["@timestamp"]["lte"] = time_to
            query["query"]["bool"]["must"].append(time_range)
        
        if assigned_to:
            query["query"]["bool"]["must"].append({"term": {"assigned_to": assigned_to}})
        
        if rule_id:
            query["query"]["bool"]["must"].append({"term": {"rule_id": rule_id}})
        
        # Execute the query
        result = es_client.search(
            index=f"{index_prefix}_siem_events",
            body=query
        )
        
        # Extract and format incidents
        incidents = []
        for hit in result["hits"]["hits"]:
            incident = hit["_source"]
            incident["id"] = hit["_id"]
            incidents.append(incident)
        
        # Return with total count for pagination
        return {
            "total": result["hits"]["total"]["value"],
            "incidents": incidents
        }
        
    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/incidents/{incident_id}", response_model=IncidentResponse, tags=["Incidents"])
def get_incident(incident_id: str):
    """
    Get a specific security incident by ID
    
    Args:
        incident_id: ID of the incident to retrieve
    """
    try:
        # Get the incident
        result = es_client.get(
            index=f"{index_prefix}_siem_events",
            id=incident_id
        )
        
        # Extract and return the incident
        incident = result["_source"]
        incident["id"] = result["_id"]
        
        return incident
        
    except Exception as e:
        logger.error(f"Error getting incident {incident_id}: {e}")
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


@app.patch("/api/incidents/{incident_id}", tags=["Incidents"])
def update_incident(incident_id: str, update_data: IncidentUpdate):
    """
    Update a security incident
    
    Args:
        incident_id: ID of the incident to update
        update_data: Data to update
    """
    try:
        # Check if incident exists
        es_client.get(
            index=f"{index_prefix}_siem_events",
            id=incident_id
        )
        
        # Prepare update data
        update_doc = {k: v for k, v in update_data.dict().items() if v is not None}
        
        # Add last updated timestamp
        update_doc["last_updated"] = datetime.now().isoformat()
        
        # Update the incident
        result = es_client.update(
            index=f"{index_prefix}_siem_events",
            id=incident_id,
            body={"doc": update_doc}
        )
        
        return {"status": "updated", "incident_id": incident_id}
        
    except Exception as e:
        logger.error(f"Error updating incident {incident_id}: {e}")
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found or update failed")


@app.post("/api/search", tags=["Search"])
def search_logs(search_query: SearchQuery):
    """
    Search logs with Elasticsearch query
    
    Args:
        search_query: Search query parameters
    """
    try:
        # Build the query
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": search_query.query_string
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": search_query.size or 100
        }
        
        # Add time range if specified
        if search_query.time_from or search_query.time_to:
            time_range = {"range": {"@timestamp": {}}}
            if search_query.time_from:
                time_range["range"]["@timestamp"]["gte"] = search_query.time_from
            if search_query.time_to:
                time_range["range"]["@timestamp"]["lte"] = search_query.time_to
            query["query"]["bool"]["must"].append(time_range)
        
        # Determine indices to search
        if search_query.indices:
            indices = [f"{index_prefix}_{index}" for index in search_query.indices]
        else:
            indices = f"{index_prefix}_*"
        
        # Execute the query
        result = es_client.search(
            index=indices,
            body=query
        )
        
        # Extract and format results
        hits = []
        for hit in result["hits"]["hits"]:
            log = hit["_source"]
            log["id"] = hit["_id"]
            log["index"] = hit["_index"]
            hits.append(log)
        
        # Return with total count
        return {
            "total": result["hits"]["total"]["value"],
            "hits": hits
        }
        
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/anomaly_timeline", tags=["Analytics"])
def get_anomaly_timeline(
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    interval: str = "1h"
):
    """
    Get timeline of anomalies for visualization
    
    Args:
        time_from: Start time in ISO format
        time_to: End time in ISO format
        interval: Aggregation interval (1m, 5m, 1h, 1d, etc.)
    """
    try:
        # Set default time range if not specified
        if not time_from:
            time_from = (datetime.now() - timedelta(days=7)).isoformat()
        if not time_to:
            time_to = datetime.now().isoformat()
        
        # Build the query
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": time_from,
                                    "lte": time_to
                                }
                            }
                        },
                        {
                            "term": {
                                "is_anomaly": True
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "anomalies_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": interval,
                        "format": "yyyy-MM-dd'T'HH:mm:ss",
                        "min_doc_count": 0
                    },
                    "aggs": {
                        "by_type": {
                            "terms": {
                                "field": "log_type",
                                "size": 10
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        # Execute the query
        result = es_client.search(
            index=f"{index_prefix}_*",
            body=query
        )
        
        # Extract and format timeline
        timeline = {
            "timestamps": [],
            "series": {}
        }
        
        # Create a dictionary to hold data for each log type
        log_types = set()
        for bucket in result["aggregations"]["anomalies_over_time"]["buckets"]:
            for type_bucket in bucket["by_type"]["buckets"]:
                log_types.add(type_bucket["key"])
                
        # Initialize series for each log type
        for log_type in log_types:
            timeline["series"][log_type] = []
        
        # Fill in the data
        for bucket in result["aggregations"]["anomalies_over_time"]["buckets"]:
            timestamp = bucket["key_as_string"]
            timeline["timestamps"].append(timestamp)
            
            # Get counts by type
            type_counts = {type_bucket["key"]: type_bucket["doc_count"] 
                          for type_bucket in bucket["by_type"]["buckets"]}
            
            # Add counts to each series
            for log_type in log_types:
                timeline["series"][log_type].append(type_counts.get(log_type, 0))
        
        return timeline
        
    except Exception as e:
        logger.error(f"Error getting anomaly timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/top_threats", tags=["Analytics"])
def get_top_threats(
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = 10
):
    """
    Get top threats based on incident priority and count
    
    Args:
        time_from: Start time in ISO format
        time_to: End time in ISO format
        limit: Number of results to return
    """
    try:
        # Set default time range if not specified
        if not time_from:
            time_from = (datetime.now() - timedelta(days=7)).isoformat()
        if not time_to:
            time_to = datetime.now().isoformat()
        
        # Build the query
        query = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": time_from,
                        "lte": time_to
                    }
                }
            },
            "aggs": {
                "by_rule": {
                    "terms": {
                        "field": "rule_id",
                        "size": limit,
                        "order": {
                            "avg_priority": "desc"
                        }
                    },
                    "aggs": {
                        "avg_priority": {
                            "avg": {
                                "field": "priority"
                            }
                        },
                        "rule_name": {
                            "terms": {
                                "field": "message",
                                "size": 1
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        # Execute the query
        result = es_client.search(
            index=f"{index_prefix}_siem_events",
            body=query
        )
        
        # Extract and format results
        threats = []
        for bucket in result["aggregations"]["by_rule"]["buckets"]:
            rule_id = bucket["key"]
            count = bucket["doc_count"]
            avg_priority = bucket["avg_priority"]["value"]
            
            # Extract rule name from message (if available)
            rule_name = rule_id
            if bucket["rule_name"]["buckets"]:
                message = bucket["rule_name"]["buckets"][0]["key"]
                if ": " in message:
                    rule_name = message.split(": ")[0]
            
            threats.append({
                "rule_id": rule_id,
                "name": rule_name,
                "count": count,
                "avg_priority": avg_priority,
                "threat_score": count * avg_priority  # Simple threat score calculation
            })
        
        # Sort by threat score
        threats.sort(key=lambda x: x["threat_score"], reverse=True)
        
        return {"threats": threats[:limit]}
        
    except Exception as e:
        logger.error(f"Error getting top threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security_posture", tags=["Analytics"])
def get_security_posture():
    """
    Calculate current security posture/risk score based on active incidents
    """
    try:
        # Get active incidents (new or in_progress)
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "terms": {
                                "status": ["new", "in_progress"]
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "by_priority": {
                    "terms": {
                        "field": "priority",
                        "size": 4
                    }
                }
            },
            "size": 0
        }
        
        result = es_client.search(
            index=f"{index_prefix}_siem_events",
            body=query
        )
        
        # Calculate risk score based on incident priorities
        # Priority weights: critical=10, high=5, medium=2, low=1
        priority_weights = {4: 10, 3: 5, 2: 2, 1: 1}
        priority_counts = {1: 0, 2: 0, 3: 0, 4: 0}  # Initialize counts for each priority
        
        for bucket in result["aggregations"]["by_priority"]["buckets"]:
            priority = int(bucket["key"])
            count = bucket["doc_count"]
            priority_counts[priority] = count
        
        # Calculate weighted score
        weighted_sum = sum(priority_weights[p] * priority_counts[p] for p in priority_weights)
        incident_count = sum(priority_counts.values())
        
        # Calculate risk score (0-100)
        risk_score = min(100, weighted_sum / 2)  # Scale to 0-100
        
        # Determine risk level
        risk_level = "Low"
        if risk_score > 75:
            risk_level = "Critical"
        elif risk_score > 50:
            risk_level = "High"
        elif risk_score > 25:
            risk_level = "Medium"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "active_incidents": incident_count,
            "incident_breakdown": {
                "critical": priority_counts[4],
                "high": priority_counts[3],
                "medium": priority_counts[2],
                "low": priority_counts[1]
            }
        }
        
    except Exception as e:
        logger.error(f"Error calculating security posture: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    # Run the API server
    uvicorn.run(app, host="0.0.0.0", port=8000)