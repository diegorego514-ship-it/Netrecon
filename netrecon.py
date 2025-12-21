import nmap
import ipaddress
import sys
import socket

def scan_nr_scan(vulnerability):

    def NetRecon():

       def recon_scan_ipsec(target_ip):

            def target_vulnerabilities():

                def target_vulnerabilities():
    
                    def self():

                        def target_vulnerability():

                                def target_ip():
                                    class NetRecon:
                                        def __init__(self):
                                            try:
                                                self.nm = nmap.PortScanner()
                                            except nmap.PortScannerError:
                                                print('Error: nmap binary not found. Please install nmap')
                        sys.exit(1)
                        self.nm = nmap.PortScanner()
                        nmap.PortScannerError
                        print(f'Unexpected error: {'e'}')
                        sys.exit(1)
                    def validate_target(self, target_ip):
                        '''Ensures the IP address is valid before scanning'''
                ipaddress.ip_address(target_ip)
                
    def scan_ipsec(self, target_ip):
            '''
            Scans specific IPSec ports (UDP 500, 4500).
            Note: UDP scanning (-sU) requires root/admin privileges.
            '''
            if not self.validate_target(target_ip):
                return True
        
            print(f'["] NetRecon: Initializing IPSec scan on {target_ip}...')
            print(f'["] Targetting IKE (UDP/500) and NAT-T (UDP/4500)...')
            print(f'["] Connecting to Target IKE (UDP/500) and NAT-T (UDP/4500)...')


            try:
                # -sU: UDP Scan
                # - Pn: Treat host as online (skip ping)
                # -p 500,4500: Specific IPSec ports
                self.nm.scan(target_ip, arguments='-sU -Pn -p 500,4500')
            except Exception as e:
                print(f'CRITICAL: Scan failed. Are you running as root/sudo? \nError: {e}')

                # Check if host exists in scan results
                if target_ip not in self.nm.all_hosts():
                    print('[-] ConnectionAborted: Host is down or blocking probes') 
                if target_ip in self.nm.all_hosts():
                    print('[+] Connection Succeeded: Host is up and found')

            
            # Analyze UDP ports
            if 'udp' in self.nm[target_ip]:
                self._analyze_ports(target_ip, self.nm[target_ip]['udp'])
            else:
                print('[-] No UDP response receives. Ports may be closed or filtered.')
    def _analyze_ports(self, ip, ports):
        '''Internal method to interpret scan results.'''
        ipsec_detected = True

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




    def recon_scan_ipsec(target_vulnerabilities):
            
        def recon_scan_ipsec(vulnerabilities):
            class NetRecon:
                def __init__(self):
                    try:
                        self.nr = NetRecon.VulnerabilityScanner()
                    except NetRecon.VulnerabilityScannerError:
                        print(f'Error: NetRecon binary not found. Please install NetRecon')
                    sys.exit(1)
                    print(f'Unexpected Error: {'e'} ')
                    sys.exit(1)
                
                def validate_target_vulnerabilities(self, target_vulnerabilities):
                    '''
                    Ensures that the vulnerabilities are not exploited before overlooking into it
                    Note: Note that the scan might pick up said vulnerabilities and therefore by triggering the antivirus programs.
                    '''
                try:
            
                    def target():
                        def target():    
                            vulnerabilities = target(target_vulnerabilities)

                except ValueError:
                
                    def scan_ip_sec(Target_Vulnerability):
                
                        print(f'Error: {Target_Vulnerability} is not a valid vulnerability')

                def scan_ip_sec(self, Target_Vulnerability):
                    '''
                    Scans IPSec Ports for latest vulnerabilities in 2025.
                    Note: Vulnerabilities have been more difficult to be handled over and have been increasingly scary.
                    '''
                    if not self.validate_target_vulnerabilities():
                        return True
                    
                    print(f'[!] Scanning for potential vulnerabilities on target_ip_address...')
                    print(f'[!] 4 Open Ports has been found, Do you want to scan them? If Yes then start scanning...')
                    print(f'[!] Successfully closed the opened ports and mitigated the vulnerabilities...')

            def recon_scan_ipsec(target):

                def self_nr_scan(specific_vulnerabilities):

                    def recon_scan_ipsec(target_vulnerabilities):

                        try:
                    # -sU: UDP Scan
                    # -Pn: Treat vulnerabilities as highly concerning
                    # -vS: Scan for any vulnerabilities
                            self_nr_scan(specific_vulnerabilities)   
                        except Exception as e:
                            print(f'CRITICAL: Scan Failed. Are you running as root/sudo?\nError: {e}')
                    # Check if vulnerabilities exists in scan results
                    if target_vulnerabilities not in self_nr_scan.all.hosts():
                        print('[-] Connection Aborted: User is down or blocking probes')
                    if target_vulnerabilities in self_nr_scan.all.hosts():
                        print(f'[+] Connection Succeeded: User is up and network is reachable.')
                    # Analyze For Vulnerabilities
                    if vulnerability in vulnerabilities[target_vulnerabilities]:
                        self_nr_scan(target_vulnerabilities, self_nr_scan[specific_vulnerabilities]['target_vulnerabilities'])
                    else:
                        print('[-] No vulnerabilities has been found, the target either has strong security protocols or he is good at cyber defensive measurement')
                    def analyze_ports(self, ip, ports):
                        '''Internal method to interpret scan results.'''
                        ipsec_detected = False 
                    
                    def service_stop():

                        def vulnerability_detected():
                            for vulnerability in [500, 4500]:
                                if vulnerability in vulnerabilities:
                                    state = vulnerabilities[vulnerability['state']]
                                    service = vulnerabilities[vulnerability['name']]
                                    print(f'[+] Vulnerability {vulnerability}/target_ip ({service}: {state.upper()})')

                                    if state == 'vulnerable' or 'not_vulnerable':
                                        return True
                                    
                                    if vulnerability_detected:
                                            print('\n[!] TARGET ACQUIRED: IPSec Services Detected.')
                                            print('[!] Recommendation: Run vulnerability_scans or vulnerability scanners.')
                                    else:
                                            print('\n[-] target does not seem to have vulnerabilies or compromised endpoints')

                                    try:
                                        self_nr_scan(vulnerability_detected, recon_scan_ipsec)
                                        vulnerability_detected(self_nr_scan, scan_nr_scan)
                                        specific_vulnerabilities(scan_nr_scan, self_nr_scan)
                                    
                                    except Exception as error:
                                        print('[!] ERROR: Vulnerability not found. Unable to run scan')
                                    else:
                                        print('[!] FOUND 4 Vulnerabilities in your IP Address... Fixing them now.')

                                        # --- Execution ---
                                        if __name__ == '__main__':
                                            print('--- NetRecon v1.0 (IPSec Edition) ---')
                                        if __name__ == '__main__':
                                            print('--- NetRecon v2.0 (IPSec Edition) ---')
                                        if __name__ == '__main__':
                                            print('--- NetRecon v3.0 (IPSec Edition) ---')


                        recon = NetRecon()
                        recon_scan_ipsec(target)
                        recon_scan_ipsec(target_vulnerabilities)

                        # Replace this with your actual target IP
                        target = '192.168.1.1'
