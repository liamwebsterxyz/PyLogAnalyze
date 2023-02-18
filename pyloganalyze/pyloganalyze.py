#############################################################################################################################
#
# for each app create an app object:
# the app object has a two sets for each hippa identifier and a first party and third domain list
#     if domain which receives identifier X is first party add it to identifiers X's first party list
#     else domain which receives identifier X is added to identifier X's third party list
#
# from this...
# 1) we know the total number of apps which shared identifier X
# 2) we can calculate a "share" likelihood average for each app
# 3) we know the total number of third party domains the app shared identfiers to
# 4) we know for all the domains receiving X hipaa identier what percent where third party
#
# How to...
# 1) iterate through each app folder sniffing the chrome_packet and net_log file
# 2) for each app create an app object
# 3) for each domain delineate if it is first or third party domain and add it to the repspective list
# 4) for each domain search line by line for identifiers if found add to the corresponding identifier bucket
# 5) add the app to overall app analysis dataframe
#
#############################################################################################################################
#
# for each domain create a domain object:
# the domain object has a first party bool, an app list, identifier list,
#     if domain communicates with app X add it to the app list
#     if domain receives X identifier add it to the identifier list
#
# from this...
# 1) we know the average number of apps each domain communicates with we also can delinneat this fact between first party and third party ie first party should be 1?
# 2) we know the average number of identifiers each domain receivers we can delineate between first and third party
#
# How to...
# 1) while iterating each app folder...
# 2) upon a new domain create a domain object we check if the domain exists in the domain set already
# 3) check if the domain is first party or third party
# 4) add the app to the domains app list and add corresponding identifiers
#
#############################################################################################################################



from pathlib import Path
from typing import List, Optional
from pyloganalyze import app
import pandas as pd


class PyLogAnalyze:
    """
    Main class for PyLogAnalyze.
    """
    
    def __init__(
        self, 
        appfile: List[Path], 
        identifierdict: dict,
        inputfile: Optional[Path],
        outputdir: Optional[Path],
    ) -> None:
        self.appPaths = [x.absolute() for x in appfile]
        self.identifiers = identifierdict
        self.inputFile = inputfile
        self.outputDir = outputdir
        self.appList = []
    
    def Analyze(self) -> None:
        for appPath in self.appPaths:

            # create an app object
            currentApp = app.App(str(appPath).split('/')[-1], self.identifiers.keys())

            # Analyze the app's chrome_packet and net_log files
            currentApp.Analyze_PlainLog(str(appPath), self.identifiers)
            currentApp.Analyze_NetLog(str(appPath), self.identifiers)

            # add app to appList
            self.appList.append(currentApp)


    def GetStats(self) -> None:
        dictStats = {}
        for identifierKey in self.identifiers.keys():
            FirstPartyCount = 0
            ThirdPartyCount = 0
            for app in self.appList:
                FirstPartyCount += app.FirstPartyCount(identifierKey)
                ThirdPartyCount += app.ThirdPartyCount(identifierKey)
            total = FirstPartyCount + ThirdPartyCount
            if total == 0:
                dictStats[identifierKey] = 0
            else:
                dictStats[identifierKey] = ThirdPartyCount / total
        print(dictStats)


    def Save(self) -> None:
        if self.inputFile is not None:
            # read app from input file
            print("Reading results from file...")
            try:
                with open(self.inputFile, 'r') as f:
                    df = pd.read_csv(f, index_col=0)
            except:
                print("Error reading input file to save df")
                return
        else:
            #TODO change this? shouldn't be hardcoded
            df = pd.DataFrame(columns=['AppID', 'FullName_FirstPart', 'FullName_ThirdParty', 'Email_FirstParty', 'Email_ThirdParty', 'DOB_FirstParty', 'DOB_ThirdParty', 'DeviceID_FirstParty', 'DeviceID_ThirdParty', 'Gender_FirstParty', 'Gender_ThirdParty', 'Phone_FirstParty', 'Phone_ThirdParty', 'IPAddress_FirstParty', 'IPAddress_ThirdParty', 'Fingerprint_FirstParty', 'Fingerprint_ThirdParty', 'Location_FirstParty', 'Location_ThirdParty'])

        for app in self.appList:
            appData = app.GetAppData()
            # TODO decide if i want to update or add duplicates?
            if app.AppID in df.AppID.values:
                # update app in output file
                df.loc[df['AppID'] == app.AppID] = appData
            else:
                df.loc[len(df)] = appData
        if self.outputDir is not None:
            #  write app analysis to output file
            print("Writing results to file...")
            try:
                df.to_csv(self.outputDir, index=0)
            except:
                print("Error writing output file")
        else:
            print(df)