# AI-Driven Honeypot Project

## Overview  
This project implements a smart honeypot designed to attract attackers, log their actions, and dynamically adapt its behavior using AI to confuse them. The honeypot mimics a vulnerable system and tracks attack attempts while utilizing AI (via Hugging Face API) for real-time analysis and deception. Additionally, real-time alerts are sent using Gmail when attacks are detected.

### Key Features  
- **Deceptive Services**: Fake SSH, HTTP, or FTP servers that attract attackers.  
- **AI-Based Attack Analysis**: Leverages Hugging Face's API to analyze attack logs and understand attack strategies.  
- **Adaptive Responses**: Dynamically adjusts the honeypot's behavior to confuse attackers.  
- **Logs and Visualizations**: Tracks and visualizes attacker activity using Kibana and Elasticsearch.  
- **Real-Time Alerts**: Sends email alerts via Gmail when an attack occurs.

## Prerequisites  
Ensure you have the following installed and configured:
- **Python 3.x**
- **Docker** (for containerized honeypot and services)
- **Elasticsearch & Kibana** (for monitoring and visualizing logs)
- **Flask** (for API to expose logs)
- **Hugging Face API** (for AI-driven analysis)
- **Gmail API** (for sending email alerts)

## Tools and Technologies  
- **Cowrie**: SSH honeypot framework  
- **Flask**: Lightweight Python framework for building APIs  
- **Hugging Face API**: AI-driven analysis for attack pattern detection and dynamic responses  
- **ELK Stack** (Elasticsearch, Logstash, Kibana): For logging and visualizations of attack data  
- **Gmail API**: For email alerts when an attack is detected

## Installation  

**Install Dependencies**

pip install flask openai requests cowrie elasticsearch

## Files for the Project
- **adaptive_honeypot.py**: Handles the AI-driven deception and dynamic response generation based on attack patterns. 
- **ai_attack_analyzer.py**: Analyzes attack logs using Hugging Face's API to detect and explain attack strategies.
- **email_alerts.py**: Sends email alerts using the Gmail API when an attack occurs.
- **requirements-dev.txt**: Lists the dependencies required for development and running the project.

## Set Up Docker: 
Ensure that Docker is installed for running Elasticsearch and Kibana in containers.

## Clone the Repository: 
git clone https://github.com/senaalanur/ai-honeypot.git  
cd ai-honeypot

## Start Elasticsearch and Kibana: 
docker-compose up -d

## How to Run
Start the Honeypot: Run Cowrie to simulate the honeypot's fake SSH service.
cd cowrie  
bin/cowrie start

## Run AI Analysis and Adaptive Honeypot:
python ai_attack_analyzer.py  
python adaptive_honeypot.py  

## Check for Logs and Attack Visualizations: 
Access Kibana at http://localhost:5601 to visualize and analyze logs.

## Receive Email Alerts: 
When an attack is detected, email alerts will be sent via Gmail.


