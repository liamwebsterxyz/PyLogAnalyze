import pandas as pd


domainInfo_prev = pd.read_csv('DomainInfo - Domain Info (3).csv')
domains = domainInfo_prev['domain'].values

df = pd.DataFrame(columns=['domain', 'third_party', 'us_ip', 'hipaa_compliant'])

with open('domains.txt', 'r') as file:
    for line in file:
        domain = line.strip()
        if domain != '':
            if domain not in domains:
                df.loc[len(df)] = [domain, None, None, None]
            else:
                info = domainInfo_prev.loc[domainInfo_prev['domain'] == domain]
                df.loc[len(df)] = [domain, info['third_party'].values[0], info['us_ip'].values[0], info['hipaa_compliant'].values[0]]


df.to_csv('test.csv', index=False)