#!/bin/bash
# Wrapper script to run the SOC QA Agent

# Set environment variables
export PYTHONPATH=/opt/soc_qa_agent
cd /opt/soc_qa_agent

# Load environment variables from .env if it exists
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
fi

# Run the agent
/usr/bin/python3 /opt/soc_qa_agent/scripts/soc_qa_agent.py >> /var/log/soc_qa_agent.log 2>&1

# Check exit status
if [ $? -eq 0 ]; then
    echo "$(date): QA Agent completed successfully" >> /var/log/soc_qa_agent.log
else
    echo "$(date): QA Agent failed" >> /var/log/soc_qa_agent.log
fi