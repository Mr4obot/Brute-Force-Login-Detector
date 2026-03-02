class BruteForceDetector:
    def __init__(self, log_file,threshold):
        self.log_file = log_file
        self.threshold = threshold
        self.ip_fail_count= {}
    
    def process_logs(self):
        with open(self.log_file) as f:
            for line in f:
                parts= line.strip().split()
                if len(parts)<2:
                    continue
            
                status,ip = parts[0], parts[1]

                if status.lower() == "fail":
                    self.ip_fail_count[ip] = self.ip_fail_count.get(ip, 0) + 1
                
    def detect_attack(self):
        attack_found = False
        for ip,count in self.ip_fail_count.items():
            if count>=self.threshold:
                print(f"Brute force detected from : {ip}")
                attack_found=True
        
        if not attack_found:
            print("No brute force detected")

if __name__ == "__main__":
    brute_force_detector = BruteForceDetector("log.txt",3)
    brute_force_detector.process_logs()
    brute_force_detector.detect_attack()
