import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import ipaddress
import hashlib
import uuid
import faker

fake = faker.Faker()

def generate_malicious_content():
    malicious_patterns = [
        "Click here to claim your prize: bit.ly/malicious-link",
        "URGENT: Your account will be suspended. Verify now: secure-verify.net",
        "Download this attachment to view your invoice.exe",
        "SELECT * FROM users WHERE username='admin'--",
        "<script>alert('Your system is infected')</script>",
        "Password reset required: enter credentials here",
        "Congratulations! You've won $1000000. Click now!",
        "Your system has been compromised. Call +1-555-0123",
        "Free Bitcoin! Transfer 0.1 BTC to wallet: 1A1zP1..."
    ]
    return random.choice(malicious_patterns)

def generate_normal_content():
    normal_patterns = [
        "Just updated our cybersecurity protocols! #InfoSec",
        "Remember to use strong passwords and 2FA everyone!",
        "Great article about zero-trust architecture",
        "Attending the cybersecurity conference next week",
        "New blog post about secure coding practices",
        "Important: Keep your systems updated",
        "Implementing new firewall rules today",
        "Security awareness training scheduled for next week"
    ]
    return random.choice(normal_patterns)

def generate_attack_signature():
    attack_types = {
        'SQLi': ['UNION SELECT', 'OR 1=1', 'DROP TABLE', 'admin\'--'],
        'XSS': ['<script>', 'javascript:', 'onerror=', 'alert('],
        'PhishingAttempt': ['verify account', 'password reset', 'urgent action'],
        'MalwareDistribution': ['.exe download', 'malicious.zip', 'trojan.dll'],
        'DataExfiltration': ['password dump', 'credit card', 'social security'],
        'BruteForce': ['repeated login', 'password attempt', 'account lockout'],
        'DDoS': ['high frequency', 'traffic spike', 'service flood']
    }
    return random.choice(list(attack_types.keys()))

def enhance_dataset():
    # Base data generation
    num_records = 500  # Increased number of records
    data = {
        'event_id': [str(uuid.uuid4()) for _ in range(num_records)],
        'timestamp': [
            datetime.now() - timedelta(
                days=random.randint(0, 30),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            ) for _ in range(num_records)
        ],
        'username': [fake.user_name() for _ in range(num_records)],
        'ip_address': [fake.ipv4() for _ in range(num_records)],
        'user_agent': [fake.user_agent() for _ in range(num_records)]
    }
    
    df = pd.DataFrame(data)
    
    # Add security-specific fields
    df['is_malicious'] = [random.choice([True, False]) for _ in range(num_records)]
    df['content'] = [generate_malicious_content() if is_mal else generate_normal_content() 
                    for is_mal in df['is_malicious']]
    
    # Add attack signatures
    df['attack_type'] = [generate_attack_signature() if is_mal else 'Normal' 
                        for is_mal in df['is_malicious']]
    
    # Add risk scores (0-100)
    df['risk_score'] = [random.randint(70, 100) if is_mal else random.randint(0, 30) 
                       for is_mal in df['is_malicious']]
    
    # Add network data
    df['port'] = [random.choice([80, 443, 8080, 22, 3389, 445]) for _ in range(num_records)]
    df['protocol'] = [random.choice(['HTTP', 'HTTPS', 'SSH', 'RDP', 'SMB']) for _ in range(num_records)]
    
    # Add geolocation data
    df['country'] = [fake.country() for _ in range(num_records)]
    df['city'] = [fake.city() for _ in range(num_records)]
    
    # Add system details
    df['os'] = [random.choice(['Windows 10', 'Ubuntu 20.04', 'macOS 12', 'Android 12', 'iOS 15']) 
                for _ in range(num_records)]
    
    # Add authentication data
    df['auth_status'] = [random.choice(['Success', 'Failed', 'Blocked']) for _ in range(num_records)]
    df['auth_method'] = [random.choice(['Password', '2FA', 'SSO', 'API Key']) for _ in range(num_records)]
    
    # Add threat intelligence
    df['known_bad_actor'] = [random.choice([True, False]) for _ in range(num_records)]
    df['threat_feed_matches'] = [random.randint(0, 5) if is_mal else 0 
                                for is_mal in df['is_malicious']]
    
    # Add payload data
    df['payload_size'] = [random.randint(100, 10000) for _ in range(num_records)]
    df['payload_hash'] = [hashlib.md5(str(random.random()).encode()).hexdigest() 
                         for _ in range(num_records)]
    
    # Add response actions
    df['action_taken'] = [random.choice(['Blocked', 'Flagged', 'Monitored', 'Allowed']) 
                         for _ in range(num_records)]
    
    # Add MITRE ATT&CK mapping
    attack_techniques = ['T1566', 'T1110', 'T1189', 'T1204', 'T1027']
    df['mitre_technique'] = [random.choice(attack_techniques) if is_mal else 'None' 
                            for is_mal in df['is_malicious']]
    
    return df

if __name__ == "__main__":
    print("Generating enhanced cybersecurity dataset...")
    df = enhance_dataset()
    
    # Save to CSV
    output_file = 'forensic_tweets.csv'
    df.to_csv(output_file, index=False)
    print(f"Dataset saved as {output_file}")
    print(f"Total records: {len(df)}")
    print("\nColumns in the dataset:")
    for col in df.columns:
        print(f"- {col}")
