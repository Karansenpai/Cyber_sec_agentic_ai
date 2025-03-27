#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Stopping Agentic AI Cybersecurity System...${NC}"

# Gracefully stop all services
docker compose down

echo -e "${GREEN}All services have been stopped.${NC}"

# Show any remaining containers (there shouldn't be any)
echo -e "\n${YELLOW}Checking for any remaining containers...${NC}"
docker compose ps

echo -e "\n${GREEN}System shutdown complete!${NC}"