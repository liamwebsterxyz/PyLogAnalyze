import pandas as pd
import numpy as np

appsInfo = pd.read_csv("appInfo.csv")
#print(appsInfo.head())

US_full = []
US_nonfull = []
nonUS_full = []
nonUS_nonfull = []

with open("apps") as f:
    for line in f:
        appID = line.split("/")[-1]
        appInfo = appsInfo[appsInfo["app_id"] == appID.strip()]
        if  len(appInfo) == 0:
            print("app not found")
            continue
        if appInfo['US'].values[0] == 1 & appInfo['testing_stage'].values[0] == 3:
            US_full.append(line)
        elif appInfo['US'].values[0] == 1:
            US_nonfull.append(line)
        elif appInfo['testing_stage'].values[0] == 3:
            nonUS_full.append(line)
        else:
            nonUS_nonfull.append(line)

f.close()
with open("appfiles/US_full", "w") as f:
    f.writelines(US_full)
f.close()
with open("appfiles/US_nonfull", "w") as f:
    f.writelines(US_nonfull)
f.close()
with open("appfiles/nonUS_full", "w") as f:
    f.writelines(nonUS_full)
f.close()
with open("appfiles/nonUS_nonfull", "w") as f:
    f.writelines(nonUS_nonfull)
f.close()
