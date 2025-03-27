# Agentic AI-Driven Cybersecurity System

A decentralized, Agentic AI-driven cybersecurity system that autonomously detects, analyzes, and mitigates cyber threats in real time—without requiring constant human intervention.

## Project Structure

```
.
├── config/                # Configuration files
│   └── config.yaml        # Main application configuration
├── data/                  # Data storage directory 
├── docker/                # Dockerfiles for each service
│   ├── data-consumer.Dockerfile
│   ├── data-producer.Dockerfile
│   └── kafka-init.Dockerfile
├── compose.yml            # Docker Compose configuration
├── requirements.txt       # Python dependencies
└── src/                   # Source code
    ├── agents/            # LangChain AI agents (Phase 3)
    ├── kafka/             # Kafka producers and consumers
    │   ├── consumer.py    # Kafka consumer for processing data
    │   ├── init_topics.py # Script to initialize Kafka topics
    │   └── producer.py    # Kafka data producer/simulator
    ├── models/            # ML models for anomaly detection (Phase 2)
    ├── response/          # Autonomous response system (Phase 3)
    ├── siem/              # SIEM integration
    └── utils/             # Utility functions
        └── config.py      # Configuration loading utilities
```

## Phase 1: Infrastructure Setup & Data Ingestion

This phase sets up the basic infrastructure for data ingestion:

- Kafka cluster for streaming data
- Elasticsearch for log storage
- Data producers to simulate network logs, system alerts, and user events
- Data consumers to process events and store them in Elasticsearch
- Kibana for visualization

## Prerequisites

- Docker
- Docker Compose

## Getting Started

1. Clone the repository:
   ```
   git clone <repository-url>
   cd Project_6th_sem
   ```

2. Start the system using Docker Compose:
   ```
   docker compose up -d
   ```

3. Monitor the logs:
   ```
   docker compose logs -f
   ```

4. Access the services:
   - Kafka UI: http://localhost:8080
   - Elasticsearch: http://localhost:9200
   - Kibana: http://localhost:5601

## System Components

### Kafka
- Message broker for real-time data streaming
- Topics:
  - `network_logs`: Network traffic and connection logs
  - `system_alerts`: System-generated security alerts
  - `user_events`: User activity events

### Elasticsearch
- Stores all log data and events
- Used for searching and analyzing security events

### Data Producer
- Simulates security-related data sources
- Generates synthetic network logs, system alerts, and user events

### Data Consumer
- Processes messages from Kafka topics
- Stores data in appropriate Elasticsearch indices
- Sets up index mappings for optimized search

## Configuration

The main configuration file is located at `config/config.yaml`. You can modify:

- Kafka settings (brokers, topics)
- Elasticsearch settings (hosts, indices)
- Simulation parameters (event generation rates)

## Next Steps

- **Phase 2**: Implement AI-powered threat detection and anomaly detection models
- **Phase 3**: Deploy LangChain AI for autonomous decision-making and response
- **Phase 4**: Establish continuous learning and feedback loops for the AI models