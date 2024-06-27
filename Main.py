import argparse
import requests
import psutil
import logging

# Setup logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_active_connections():
    try:
        connections = psutil.net_connections()
        active_connections = []
        for conn in connections:
            if conn.raddr:
                active_connections.append({
                    'local_address': conn.laddr,
                    'remote_address': conn.raddr,
                    'status': conn.status
                })

        logging.debug(f"Active connections: {active_connections}")
        return active_connections
    except Exception as e:
        logging.error(f"Error getting active connections: {e}")
        return []

def check_ip_with_abuseipdb(ip):
    try:
        API_KEY = '55ff5544e31e26b3c3e0b1f14347fd385c5aad81b49f0782ceadda507b998c53d07f25e237327cf9'
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
        headers = {
            'Accept': 'application/json',
            'Key': API_KEY
        }
        response = requests.get(url, headers=headers)
        logging.debug(f"AbuseIPDB response for {ip}: {response.json()}")
        return response.json()
    except Exception as e:
        logging.error(f"Error checking IP with AbuseIPDB: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Check active network connections against threat intelligence databases.')
    args = parser.parse_args()
    
    # Simulate active connections with known malicious IPs for testing
    malicious_ips = [
        '92.246.139.107',  # Known malicious IPs from abuseipdb
        '167.99.70.85',
        '200.122.249.203'
    ]
    simulated_connections = [{
        'local_address': ('127.0.0.1', 12345),  # Simulated local address
        'remote_address': (ip, 80),  # Simulated remote address with malicious IP
        'status': 'ESTABLISHED'
    } for ip in malicious_ips]
    
    # Combine simulated connections with active connections
    all_connections = simulated_connections + get_active_connections()

    if not all_connections:
        logging.info("No active connections found.")
        print("No active connections found.")
    else:
        # Process all IPs
        for conn in all_connections:
            remote_ip = conn['remote_address'][0]
            print(f'Checking IP: {remote_ip}')
            abuseipdb_result = check_ip_with_abuseipdb(remote_ip)
            if abuseipdb_result:
                print(f'AbuseIPDB result for {remote_ip}: {abuseipdb_result}')
            else:
                print(f'Error checking IP: {remote_ip}')
    
    input("Press Enter to exit...")  # Keeps the window open until Enter is pressed

if __name__ == '__main__':
    main()
