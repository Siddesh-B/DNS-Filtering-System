import requests
import pandas as pd
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

def fetch_threat_intelligence():

# Sample Threat Keywords
    threat_list = [
        "malware", "phishing", "ransomware", "botnet",
        "trojan", "keylogger", "exploit", "adware", "crypto scam"
    ]
    return threat_list


threat_keywords = fetch_threat_intelligence()
print("Loaded Threat Intelligence Keywords:", threat_keywords)



# Sample DNS queries
dns_queries = [
    "secure-login.com", "paypal-verification.net", "free-bitcoin.xyz",
    "malware-update.com", "mybank-secure.org", "social-media-login.info"
]

df = pd.DataFrame(dns_queries, columns=["DNS Query"])
print(df)

model = SentenceTransformer('all-mpnet-base-v2')

def calculate_similarity(dns_queries, threat_keywords):

    query_embeddings = model.encode(dns_queries)
    threat_embeddings = model.encode(threat_keywords)
    similarity_scores = cosine_similarity(query_embeddings, threat_embeddings)
    max_similarity_per_query = similarity_scores.max(axis=1)

    return max_similarity_per_query

df["Threat Similarity Score"] = calculate_similarity(df["DNS Query"].tolist(), threat_keywords)

# Displaying the DataFrame with Similarity
print(df)

THRESHOLD = 0.5  # Threshold Value

df["Malicious"] = df["Threat Similarity Score"] > THRESHOLD
print(df)

def dns_filtering_system(new_query):

    similarity_score = calculate_similarity([new_query], threat_keywords)[0]
    is_malicious = similarity_score > THRESHOLD
    return new_query, similarity_score, is_malicious

# Testing with a new DNS query
test_domain = "bank-login-verification.com"
result = dns_filtering_system(test_domain)

print(f"Domain: {result[0]} | Similarity Score: {result[1]:.4f} | Malicious: {result[2]}")

