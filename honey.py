import json
import collections
from datetime import datetime
from pathlib import Path

class HoneypotAnalyzer:
    """Analyze honeypot logs to extract threat intelligence"""
    
    def __init__(self, log_file):
        self.log_file = log_file
        self.logs = self.load_logs()
    
    def load_logs(self):
        """Load logs from JSON file"""
        try:
            with open(self.log_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Log file {self.log_file} not found!")
            return []
        except json.JSONDecodeError:
            print(f"Error parsing {self.log_file}")
            return []
    
    def get_top_attackers(self, n=10):
        """Get top N attacking IP addresses"""
        ip_counts = collections.Counter()
        for log in self.logs:
            ip_counts[log.get('ip', 'Unknown')] += 1
        return ip_counts.most_common(n)
    
    def get_credential_attempts(self):
        """Extract all credential attempts"""
        attempts = []
        for log in self.logs:
            if 'username' in log and 'password' in log:
                attempts.append({
                    'timestamp': log['timestamp'],
                    'ip': log['ip'],
                    'username': log['username'],
                    'password': log['password']
                })
        return attempts
    
    def get_common_credentials(self, n=10):
        """Get most commonly attempted credentials"""
        cred_counts = collections.Counter()
        for log in self.logs:
            if 'username' in log and 'password' in log:
                cred = f"{log['username']}:{log['password']}"
                cred_counts[cred] += 1
        return cred_counts.most_common(n)
    
    def get_attack_timeline(self):
        """Generate timeline of attacks by hour"""
        timeline = collections.Counter()
        for log in self.logs:
            try:
                dt = datetime.fromisoformat(log['timestamp'])
                hour_key = dt.strftime('%Y-%m-%d %H:00')
                timeline[hour_key] += 1
            except:
                continue
        return sorted(timeline.items())
    
    def get_user_agents(self):
        """Get all unique user agents (for HTTP logs)"""
        agents = set()
        for log in self.logs:
            if 'user_agent' in log:
                agents.add(log['user_agent'])
        return sorted(agents)
    
    def get_requested_paths(self):
        """Get all requested paths (for HTTP logs)"""
        path_counts = collections.Counter()
        for log in self.logs:
            if 'path' in log:
                path_counts[log['path']] += 1
        return path_counts.most_common(20)
    
    def detect_scanning_patterns(self):
        """Detect potential scanning behavior"""
        ip_requests = collections.defaultdict(list)
        
        for log in self.logs:
            ip = log.get('ip', 'Unknown')
            timestamp = log.get('timestamp', '')
            ip_requests[ip].append({
                'timestamp': timestamp,
                'type': log.get('type', 'unknown')
            })
        
        scanners = {}
        for ip, requests in ip_requests.items():
            if len(requests) > 5:  # More than 5 requests might indicate scanning
                scanners[ip] = {
                    'request_count': len(requests),
                    'first_seen': requests[0]['timestamp'],
                    'last_seen': requests[-1]['timestamp']
                }
        
        return scanners
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("=" * 70)
        print("                    HONEYPOT ANALYSIS REPORT")
        print("=" * 70)
        print(f"\nTotal Events: {len(self.logs)}")
        print(f"Log File: {self.log_file}\n")
        
        # Top attackers
        print("\n" + "="*70)
        print("TOP 10 ATTACKING IPs")
        print("="*70)
        top_ips = self.get_top_attackers(10)
        for ip, count in top_ips:
            print(f"{ip:20s} - {count:4d} attempts")
        
        # Credential attempts
        attempts = self.get_credential_attempts()
        if attempts:
            print("\n" + "="*70)
            print(f"CREDENTIAL ATTEMPTS ({len(attempts)} total)")
            print("="*70)
            
            common_creds = self.get_common_credentials(10)
            print("\nMost Common Credentials:")
            for cred, count in common_creds:
                print(f"  {cred:40s} - {count:3d} times")
            
            print("\nRecent Attempts:")
            for attempt in attempts[-5:]:
                print(f"  [{attempt['timestamp']}] {attempt['ip']}")
                print(f"    -> {attempt['username']}:{attempt['password']}")
        
        # HTTP specific analysis
        paths = self.get_requested_paths()
        if paths:
            print("\n" + "="*70)
            print("MOST REQUESTED PATHS")
            print("="*70)
            for path, count in paths[:15]:
                print(f"{path:50s} - {count:3d} requests")
        
        user_agents = self.get_user_agents()
        if user_agents:
            print("\n" + "="*70)
            print(f"USER AGENTS ({len(user_agents)} unique)")
            print("="*70)
            for ua in user_agents[:10]:
                print(f"  {ua}")
        
        # Scanning detection
        print("\n" + "="*70)
        print("POTENTIAL SCANNERS (>5 requests)")
        print("="*70)
        scanners = self.detect_scanning_patterns()
        for ip, info in sorted(scanners.items(), 
                              key=lambda x: x[1]['request_count'], 
                              reverse=True)[:10]:
            print(f"{ip:20s} - {info['request_count']:4d} requests")
            print(f"  First: {info['first_seen']}")
            print(f"  Last:  {info['last_seen']}")
        
        # Timeline
        print("\n" + "="*70)
        print("ATTACK TIMELINE (by hour)")
        print("="*70)
        timeline = self.get_attack_timeline()
        for time, count in timeline[-10:]:  # Last 10 hours with activity
            bar = '█' * min(count, 50)
            print(f"{time} | {bar} {count}")
        
        print("\n" + "="*70)
        print("END OF REPORT")
        print("="*70)
    
    def export_iocs(self, output_file='iocs.txt'):
        """Export Indicators of Compromise"""
        with open(output_file, 'w') as f:
            f.write("# Indicators of Compromise from Honeypot\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n\n")
            
            f.write("## Malicious IPs\n")
            for ip, count in self.get_top_attackers(100):
                f.write(f"{ip}\n")
            
            f.write("\n## Attempted Credentials\n")
            for cred, count in self.get_common_credentials(50):
                f.write(f"{cred}\n")
        
        print(f"[+] IOCs exported to {output_file}")


def main():
    """Main analysis function"""
    import sys
    
    print("Honeypot Log Analyzer")
    print("=" * 70)
    
    # Check for command line argument
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        print("\nAvailable log files:")
        log_files = list(Path('.').glob('*honeypot*.json'))
        
        if not log_files:
            print("No honeypot log files found in current directory!")
            print("\nUsage: python analyzer.py <log_file>")
            return
        
        for i, f in enumerate(log_files, 1):
            print(f"{i}. {f.name}")
        
        choice = input("\nSelect log file (1-{}): ".format(len(log_files)))
        try:
            log_file = log_files[int(choice) - 1]
        except (ValueError, IndexError):
            print("Invalid choice!")
            return
    
    # Analyze logs
    analyzer = HoneypotAnalyzer(log_file)
    analyzer.generate_report()
    
    # Ask to export IOCs
    export = input("\n\nExport IOCs to file? (y/n): ").strip().lower()
    if export == 'y':
        analyzer.export_iocs()


if __name__ == "__main__":
    main()