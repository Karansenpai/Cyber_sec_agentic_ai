# Agentic AI-Driven Cybersecurity System
A decentralized, Agentic AI-driven cybersecurity system that autonomously detects, analyzes, and mitigates cyber threats in real time—without requiring constant human intervention.

## Project Structure
```
.
├── config/                # Configuration files
│   ├── config.yaml       # Main application configuration
│   └── kibana_dashboards/ # Kibana visualization configs
├── data/                  # Data storage directory 
│   ├── elasticsearch/    # Elasticsearch data
│   ├── kafka/           # Kafka data
│   ├── models/          # Trained ML models
│   ├── vector_db/       # FAISS vector database
│   └── zookeeper/       # Zookeeper data
├── docker/               # Dockerfiles for each service
│   ├── anomaly-detection.Dockerfile
│   ├── dashboard-service.Dockerfile
│   ├── data-consumer.Dockerfile
│   ├── data-producer.Dockerfile
│   ├── feedback-loop.Dockerfile
│   ├── kafka-init.Dockerfile
│   └── orchestrator.Dockerfile
├── compose.yml          # Docker Compose configuration
├── requirements.txt     # Python dependencies
└── src/                # Source code
    ├── agents/         # LangChain AI agents
    │   ├── langchain_agent.py     # Core AI decision making
    │   ├── orchestrator_service.py # Service orchestration
    │   └── vector_db_init.py      # Vector DB setup
    ├── kafka/          # Kafka producers and consumers
    ├── models/         # ML models for anomaly detection
    │   ├── anomaly_detection/     # Detection algorithms
    │   ├── automl/              # AutoML pipeline
    │   └── features/            # Feature engineering
    ├── response/       # Autonomous response system
    ├── siem/          # SIEM integration
    └── utils/         # Utility functions
```

## System Components

### Infrastructure Layer
- **Kafka & Zookeeper**: Message broker cluster for real-time data streaming
- **Elasticsearch**: Stores all security events and logs
- **Kibana**: Security visualization and dashboards
- **FAISS Vector DB**: Stores embeddings for AI context memory

### Data Processing Layer
- **Data Producer**: Simulates security-related data sources
- **Data Consumer**: Processes and stores events in Elasticsearch
- **Dashboard Service**: Real-time security monitoring interface

### AI Layer
- **Anomaly Detection**: ML-based threat detection using TensorFlow
- **LangChain Agent**: Autonomous decision-making using Gemini
- **Feedback Loop**: Continuous model improvement system

### Response Layer
- **Orchestrator**: Coordinates automated response actions
- **Incident Responder**: Executes mitigation steps
- **Event Correlator**: Analyzes event relationships

## Features
- Real-time threat detection using ML/AI
- Autonomous decision-making with LangChain
- Automated incident response
- Self-improving models via feedback loops
- Comprehensive security dashboards
- Vector-based threat pattern matching

## Prerequisites
- Docker and Docker Compose
- Google API Key (for Gemini LLM)
- 8GB+ RAM recommended

## Getting Started

1. Clone the repository:
   ```
   git clone <repository-url>
   cd Project_6th_sem
   ```

2. Set up environment variables:
   ```
   export GOOGLE_API_KEY=your_api_key
   ```
