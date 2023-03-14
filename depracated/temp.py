import pandas as pd


df = pd.DataFrame(columns=['domain', 'third_party', 'hipaa_compliant', 'us_registrant'])

with open("domains.txt", 'r') as file:
    for line in file:
        line = line.strip()
        df.loc[len(df)] = [line, None, None, None]


df.to_csv("exp.csv", index=False)