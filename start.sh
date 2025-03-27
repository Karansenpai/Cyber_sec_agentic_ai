#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Agentic AI Cybersecurity System${NC}"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Please start Docker first.${NC}"
    exit 1
fi

# Check for required environment variables
if [ -z "$GOOGLE_API_KEY" ]; then
    echo -e "${YELLOW}GOOGLE_API_KEY is not set. Setting it from the config file...${NC}"
    export GOOGLE_API_KEY=$(grep -o 'AIzaSy[a-zA-Z0-9_-]*' AIzaSyDdoz87TejpWftqUtgp2jDowvWoDzDOnwk)
fi

# Create necessary directories if they don't exist
mkdir -p data/{elasticsearch,kafka,models,vector_db,zookeeper}/{data,log}

# Function to check service health
check_service_health() {
    local service=$1
    local max_attempts=$2
    local attempt=1

    echo -e "${YELLOW}Waiting for $service to be healthy...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose ps $service | grep -q "(healthy)"; then
            echo -e "${GREEN}$service is healthy!${NC}"
            return 0
        fi
        echo -n "."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}$service failed to become healthy within the timeout period.${NC}"
    return 1
}

# Stop any existing containers
echo "Stopping any existing containers..."
docker compose down

# Start core infrastructure
echo "Starting core infrastructure..."
docker compose up -d zookeeper kafka elasticsearch kibana kafka-ui

# Wait for core services to be healthy
check_service_health zookeeper 12
check_service_health kafka 12
check_service_health elasticsearch 12
check_service_health kibana 12

# Start data services
echo "Starting data services..."
docker compose up -d data-producer data-consumer

# Start AI and processing services
echo "Starting AI and processing services..."
docker compose up -d anomaly-detection feedback-loop orchestrator dashboard-service

# Show service status
echo -e "\n${GREEN}Service Status:${NC}"
docker compose ps

# Show access information
echo -e "\n${GREEN}Access Information:${NC}"
echo -e "📊 Kibana Dashboard: ${YELLOW}http://localhost:5601${NC}"
echo -e "🔍 Kafka UI: ${YELLOW}http://localhost:8080${NC}"
echo -e "🔌 Elasticsearch API: ${YELLOW}http://localhost:9200${NC}"

# Tail logs for potential errors
echo -e "\n${YELLOW}Checking for any startup errors...${NC}"
docker compose logs --tail=20

echo -e "\n${GREEN}System startup complete!${NC}"
echo -e "${YELLOW}Use 'docker compose logs -f [service-name]' to monitor specific services${NC}"