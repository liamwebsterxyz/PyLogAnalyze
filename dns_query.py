# iterate through the log file
#     get all the DNS:getaddrinfo queries

# iterate through the net_log
#     cross off domains in the dns list if we see traffic to it
import pandas as pd

dns_set = set() 
with open("APP_PATH/log", "r", errors='ignore') as f:
    for line in f:
        if "DNS:getAddrInfo:" in line:
            domain = (line.split(":")[-1]).strip()
            dns_set.add(domain)

df = pd.read_csv("APP_PATH/net_log")

traffic_set = set(df.iloc[:,6])

print(dns_set - traffic_set)
        
