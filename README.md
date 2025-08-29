# 🛡️ AI-Driven Honeypot Project  

An intelligent honeypot system that mimics vulnerable services, logs attacker activity, and leverages **AI (Hugging Face API)** to analyze and dynamically adapt responses in real-time. The system also sends **email alerts via Gmail** when attacks are detected.  

## 🔎 Overview  
This project implements a smart honeypot designed to:  
- Attract attackers and log their actions.  
- Dynamically adapt its behavior using AI to confuse attackers.  
- Provide real-time alerts and visualizations for security monitoring.  

## 🎯 Purpose & Motivation
  
### 1. Research & Learning  

- Understand attacker behavior and tactics in a controlled environment.  
- Experiment with AI-driven techniques for analyzing and responding to cyber threats.  
- Assess the effectiveness of honeypots as an **active defense mechanism**.  

### 2. Active Defense & Deception  

- Detect, log, and **actively confound attackers** by adapting responses.  
- Collect and analyze attack data for stronger future defense strategies.  
- Demonstrate how AI can **enhance traditional cybersecurity tools**.  

## ✨ Key Features
  
- **Deceptive Services**: Fake SSH, HTTP, or FTP servers to attract attackers.  
- **AI-Based Analysis**: Uses Hugging Face API to analyze attack logs and strategies.  
- **Adaptive Responses**: Dynamically adjusts honeypot behavior to mislead attackers.  
- **Visualization**: Monitor attacker activity with **Elasticsearch & Kibana** dashboards.  
- **Real-Time Alerts**: Sends Gmail notifications when attacks occur.  

## 📋 Prerequisites  
Make sure you have the following installed:  
- **Python 3.x**  
- **Docker** (for containerized honeypot + ELK stack)  
- **Elasticsearch & Kibana** (log storage + visualization)  
- **Flask** (REST API for logs)  
- **Hugging Face API key**  
- **Gmail API credentials** (for email alerts)  

## 🛠️ Tools & Technologies  
- **Cowrie** – SSH honeypot framework  
- **Flask** – API backend  
- **Hugging Face API** – AI-based log analysis and deception logic  
- **ELK Stack** – Elasticsearch, Logstash, Kibana for log monitoring  
- **Gmail API** – Sends email alerts  

## ⚙️ Installation  

1- Clone the repository:
git clone https://github.com/senaalanur/ai-honeypot.git
cd ai-honeypot

2- Install dependencies:
pip install -r requirements-dev.txt

3- Set up Docker for Elasticsearch & Kibana

4- Ensure Docker is running, then start the ELK services.

5- Configure environment variables


6- Set your Hugging Face API key and Gmail credentials inside a .env file.

7- Run the honeypot:
python adaptive_honeypot.py


## 📂 Project Structure

- adaptive_honeypot.py – Core honeypot with AI-driven deception logic

- ai_attack_analyzer.py – Analyzes logs using Hugging Face API

- email_alerts.py – Sends Gmail alerts on detected attacks

- requirements-dev.txt – Dependencies list

## 🚀 Usage

- Start the honeypot and let it listen for incoming connections.

- Monitor logs in Kibana dashboards.

- Receive real-time Gmail alerts when attackers interact with the honeypot.

- Analyze attacker behavior using AI-driven insights.

### 📜 License
This project is open-source and available under the MIT License.


