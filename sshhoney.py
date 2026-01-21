import socket
import threading
import datetime
import json
import os
from pathlib import Path

class SSHHoneypot:
    """
    Simple SSH honeypot that logs connection attempts and credentials.
    WARNING: Run this only in isolated/controlled environments for educational purposes.
    """
    
    def __init__(self, host='0.0.0.0', port=2222, log_file='honeypot_logs.json'):
        self.host = host
        self.port = port
        self.log_file = log_file
        self.banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        
        # Ensure log file exists
        Path(self.log_file).touch(exist_ok=True)
    
    def log_attempt(self, data):
        """Log connection attempt to JSON file"""
        try:
            # Read existing logs
            if os.path.getsize(self.log_file) > 0:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            # Add new log entry
            logs.append(data)
            
            # Write back
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            # Console output
            print(f"\n[{data['timestamp']}] New attempt from {data['ip']}:{data['port']}")
            if 'username' in data:
                print(f"  Username: {data.get('username', 'N/A')}")
                print(f"  Password: {data.get('password', 'N/A')}")
                
        except Exception as e:
            print(f"Error logging: {e}")
    
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        ip, port = addr
        timestamp = datetime.datetime.now().isoformat()
        
        log_data = {
            'timestamp': timestamp,
            'ip': ip,
            'port': port,
            'type': 'connection'
        }
        
        try:
            # Send SSH banner
            client_socket.send(self.banner)
            
            # Receive client banner
            client_banner = client_socket.recv(1024)
            log_data['client_banner'] = client_banner.decode('utf-8', errors='ignore').strip()
            
            # Simple credential capture simulation
            # In real SSH, this would be key exchange, but we simplify for demonstration
            client_socket.send(b"Password: ")
            
            # Try to capture credentials
            data = client_socket.recv(1024)
            if data:
                received = data.decode('utf-8', errors='ignore').strip()
                
                # Parse potential username:password
                if ':' in received:
                    parts = received.split(':', 1)
                    log_data['username'] = parts[0]
                    log_data['password'] = parts[1]
                else:
                    log_data['data'] = received
            
            # Send fake authentication failure
            client_socket.send(b"Permission denied (publickey,password).\r\n")
            
        except Exception as e:
            log_data['error'] = str(e)
        finally:
            self.log_attempt(log_data)
            client_socket.close()
    
    def start(self):
        """Start the honeypot server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            print(f"[*] SSH Honeypot listening on {self.host}:{self.port}")
            print(f"[*] Logs will be saved to {self.log_file}")
            print("[*] Press Ctrl+C to stop\n")
            
            while True:
                client, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            server.close()


class HTTPHoneypot:
    """
    Simple HTTP honeypot to detect web scanners and attack attempts.
    """
    
    def __init__(self, host='0.0.0.0', port=8080, log_file='http_honeypot_logs.json'):
        self.host = host
        self.port = port
        self.log_file = log_file
        Path(self.log_file).touch(exist_ok=True)
    
    def log_request(self, data):
        """Log HTTP request"""
        try:
            if os.path.getsize(self.log_file) > 0:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            else:
                logs = []
            
            logs.append(data)
            
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            print(f"\n[{data['timestamp']}] {data['method']} {data['path']} from {data['ip']}")
            if data.get('user_agent'):
                print(f"  User-Agent: {data['user_agent']}")
                
        except Exception as e:
            print(f"Error logging: {e}")
    
    def handle_client(self, client_socket, addr):
        """Handle HTTP request"""
        ip, port = addr
        timestamp = datetime.datetime.now().isoformat()
        
        try:
            request = client_socket.recv(4096).decode('utf-8', errors='ignore')
            
            if not request:
                return
            
            lines = request.split('\r\n')
            if lines:
                # Parse request line
                parts = lines[0].split()
                method = parts[0] if len(parts) > 0 else 'UNKNOWN'
                path = parts[1] if len(parts) > 1 else '/'
                
                # Parse headers
                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                
                log_data = {
                    'timestamp': timestamp,
                    'ip': ip,
                    'port': port,
                    'method': method,
                    'path': path,
                    'user_agent': headers.get('User-Agent', 'Unknown'),
                    'headers': headers,
                    'full_request': request[:500]  # First 500 chars
                }
                
                self.log_request(log_data)
                
                # Send fake response
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Server: Apache/2.4.41 (Ubuntu)\r\n"
                    "Content-Type: text/html\r\n"
                    "\r\n"
                    "<html><body><h1>It works!</h1></body></html>"
                )
                client_socket.send(response.encode())
                
        except Exception as e:
            print(f"Error handling request: {e}")
        finally:
            client_socket.close()
    
    def start(self):
        """Start HTTP honeypot"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            print(f"[*] HTTP Honeypot listening on {self.host}:{self.port}")
            print(f"[*] Logs will be saved to {self.log_file}")
            print("[*] Press Ctrl+C to stop\n")
            
            while True:
                client, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            server.close()


def main():
    """Main function to run honeypots"""
    print("=" * 60)
    print("           HONEYPOT SYSTEM")
    print("=" * 60)
    print("\nSelect honeypot type:")
    print("1. SSH Honeypot (Port 2222)")
    print("2. HTTP Honeypot (Port 8080)")
    print("3. Both")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == '1':
        honeypot = SSHHoneypot()
        honeypot.start()
    elif choice == '2':
        honeypot = HTTPHoneypot()
        honeypot.start()
    elif choice == '3':
        print("\n[*] Starting both honeypots...")
        ssh_thread = threading.Thread(target=lambda: SSHHoneypot().start())
        ssh_thread.daemon = True
        ssh_thread.start()
        
        # Run HTTP in main thread
        HTTPHoneypot().start()
    else:
        print("Invalid choice!")


if __name__ == "__main__":
    main()