"""
Autonomous Incident Responder
This module automates containment and mitigation actions based on decisions from the LangChain agent.
"""
import requests
import paramiko
from loguru import logger
from src.agents.langchain_agent import LangChainAgent

class IncidentResponder:
    def __init__(self, vector_db_path):
        """Initialize the incident responder with a LangChain agent."""
        self.agent = LangChainAgent(vector_db_path)

    def block_ip(self, ip_address):
        """Block a malicious IP address using a firewall API."""
        try:
            firewall_api_url = "http://firewall.local/api/block"
            response = requests.post(firewall_api_url, json={"ip": ip_address})
            if response.status_code == 200:
                logger.info(f"Successfully blocked IP: {ip_address}")
            else:
                logger.error(f"Failed to block IP: {ip_address}, Status Code: {response.status_code}")
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")

    def quarantine_endpoint(self, endpoint):
        """Quarantine an infected endpoint using SSH commands."""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(endpoint, username="admin", password="password")
            stdin, stdout, stderr = ssh.exec_command("sudo systemctl stop network")
            logger.info(f"Quarantined endpoint: {endpoint}")
            ssh.close()
        except Exception as e:
            logger.error(f"Error quarantining endpoint {endpoint}: {e}")

    def apply_patch(self, patch_url):
        """Apply a software patch by downloading and executing it."""
        try:
            response = requests.get(patch_url)
            if response.status_code == 200:
                with open("/tmp/patch.sh", "wb") as patch_file:
                    patch_file.write(response.content)
                logger.info("Patch downloaded successfully. Applying patch...")
                # Execute the patch script
                os.system("bash /tmp/patch.sh")
            else:
                logger.error(f"Failed to download patch from {patch_url}, Status Code: {response.status_code}")
        except Exception as e:
            logger.error(f"Error applying patch from {patch_url}: {e}")

    def respond_to_alert(self, alert):
        """Respond to a threat alert by executing the recommended action."""
        decision = self.agent.process_alert(alert)
        logger.info(f"Decision from LangChain Agent: {decision}")

        # Example decision parsing (this should be adapted to your decision format)
        if "block IP" in decision:
            ip_address = decision.split(":")[-1].strip()
            self.block_ip(ip_address)
        elif "quarantine endpoint" in decision:
            endpoint = decision.split(":")[-1].strip()
            self.quarantine_endpoint(endpoint)
        elif "apply patch" in decision:
            patch_url = decision.split(":")[-1].strip()
            self.apply_patch(patch_url)
        else:
            logger.warning("No actionable decision found in the response.")

if __name__ == "__main__":
    # Example usage
    vector_db_path = "./vector_db"
    responder = IncidentResponder(vector_db_path)

    # Example alert
    alert = "Suspicious login attempt detected from IP 192.168.1.100."
    responder.respond_to_alert(alert)