import nmap
import ipaddress
import sys
import socket

class NetRecon:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print('Error: nmap binary not found. Please install nmap')
            sys.exit(1)
        except Exception as e:
            print(f'Unexpected error: {e}')
            sys.exit(1)
    
    def validate_target(self, target_ip):
        '''Ensures the IP address is valid before scanning'''
        try:
            ipaddress.ip_address(target_ip)
            return True
        except ValueError:
            print(f'Error: {target_ip} is not a valid IP address.')
            return False
    
    def scan_ipsec(self, target_ip):
        '''
        Scans specific IPSec ports (UDP 500, 4500).
        Note: UDP scanning (-sU) requires root/admin privileges.
        '''
        if not self.validate_target(target_ip):
            return
        
        print(f'["] NetRecon: Initializing IPSec scan on {target_ip}...')
        print(f'["] Targetting IKE (UDP/500) and NAT-T (UDP/4500)...')
    
        try:
            # -sU: UDP Scan
            # - Pn: Treat host as online (skip ping)
            # -p 500,4500: Specific IPSec ports
            self.nm.scan(target_ip, arguments='-sU -Pn -p 500,4500')
        except Exception as e:
            print(f'CRITICAL: Scan failed. Are you running as root/sudo? \nError: {e}')
            return

            # Check if host exists in scan results
            if target_ip not in self.nm.all_hosts():
                print('[-] ConnectionAborted: Host is down or blocking probes')
                return
            # Analyze UDP ports
            if 'udp' in self.nm[target_ip]:
                self._analyze_ports(target_ip, self.nm[target_ip]['udp'])
            else:
                print('[-] No UDP response receives. Ports may be or filtered.')
    def _analyze_ports(self, ip, ports):
        '''Internal method to interpret scan results.'''
        ipsec_detected = False

        for port in [500, 4500]:
            if port in ports:
                state = ports[port]['state']
                service = ports[port]['name']
                print(f'[+] Port {port}/udp ({service}: {state.upper()}')

                if state == 'open' or state == 'open|filtered':
                    ipsec_detected = True
                


            if ipsec_detected:
                print('\n[!] TARGET ACQUIRED: IPSec Services Detected.')
                print('[!] Recommendation: Run IKE-scan or aggressive mode analysis.')
            else:
                print('\n[-] Target does not appear to have active IPSec endpoints.')

# --- Execution ---
if __name__ == '__main__':
    print('--- NetRecon v1.0 (IPSec Edition) ---')

    # Replace this with your actual target IP
    target = '192.168.1.1'

    recon = NetRecon()
    recon.scan_ipsec(target)
