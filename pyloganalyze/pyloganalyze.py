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
from typing import List, Optional, Tuple
from pyloganalyze import app, domain
import pandas as pd
import logging, tldextract



def _IdentifierSearch(identifierKey: str, identifiers: List[str], line: str) -> bool:
    """
    Returns true if the line contains the identifier.
    """
    # TODO improve search process to not be so naive REGEX? 
    # TODO add search until next domain... e.g. to search for first and last name then combine to determine full name 
    line = line.lower()
    success = False
    if identifierKey == "FullName":
        for identity in identifiers:
            full_name = identity.split(' ')
            if full_name[0] in line and full_name[1] in line:
                success = True
    elif identifierKey == "Email":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == "DOB":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == "DeviceID":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == 'Gender':
        for identity in identifiers:
            if identity in line and ('gender' in line or 'sex' in line):
                success = True
    elif identifierKey == "Phone":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == "IPAddress":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == "Fingerprint":
        for identity in identifiers:
            if identity in line:
                success = True
    elif identifierKey == "Location":
        for identity in identifiers:
            if identity in line:
                success = True
    return success


class PyLogAnalyze:
    """
    Main class for PyLogAnalyze.
    """

    def __init__(self, appfile: List[Path], identifierdict: dict, appinfo: pd.DataFrame, domaininfo: pd.DataFrame) -> None:
        self.appPaths = [x.absolute() for x in appfile]
        self.identifiers = identifierdict
        self.appList = {}
        self.domainList = {}
        self.appInfo = appinfo
        self.domainInfo = domaininfo
    
    def Analyze(self) -> None:
        """
        Analyze the chrome_packet and net_log files for each specified app. Producing a PyLogAnalyze object containing the results.
        """
        for appPath in self.appPaths:
            
            appID = str(appPath).split('/')[-1]
            appInfo = self.appInfo.loc[self.appInfo['app_id'] == appID.strip()]

            # create an app object
            if appID in self.appList.keys():
                currentApp_obj = self.appList[appID]
            else:
                currentApp_obj = app.App(appID, appInfo['testing_stage'].values[0], appInfo['hipaa_compliant'].values[0], appInfo['us_audience'].values[0], self.identifiers.keys())
                # add app to appList
                self.appList[appID] = currentApp_obj

            # # Analyze the app's log, plain_log and chrome_packet files
            self._Analyze_Log(appPath, currentApp_obj)
            self._Analyze_PlainLog(appPath, self.identifiers, currentApp_obj)
            self._Analyze_ChromePacket(appPath, self.identifiers, currentApp_obj)

            print(f"App {currentApp_obj.AppID} analyzed.")
            logging.debug(f"App {currentApp_obj.AppID} analyzed.")

    def _Analyze_Log(self, appPath: Path, app_obj: app) -> None:
        """
        Analyze the log file for identifiers.
        """
        try:
            with open(appPath / "log", "r") as file:
                for line in file:
                    if "DNS:" in line:
                        currentDomain = line.split("DNS:")[1]
                        if currentDomain != "":
                            currentDomain_tld = tldextract.extract(currentDomain.strip())
                            currentDomain = currentDomain_tld.domain + '.' + currentDomain_tld.suffix
                            app_obj.DNSList.add(currentDomain)
                    
        except FileNotFoundError:
            logging.warning(f"File {appPath / 'log'} not found.")

    def _Analyze_PlainLog(self, appPath: Path, identifiers: dict, app_obj: app) -> None:
        """
        Analyze the plain log file for identifiers.
        """
        try:
            with open(appPath / "plain_log", "r") as file:
                for line in file:
                    if ('(packet)' in line):
                        currentDomain_full = line
                        if "inbound" in currentDomain_full:
                            currentDomain_full = currentDomain_full.split('inbound to ')[1]
                        elif "outbound" in currentDomain_full:
                            currentDomain_full = currentDomain_full.split('outbound to ')[1]
                        
                        # # split app ID
                        # appID_tld = tldextract.extract(self.AppID)

                        # split domain
                        currentDomain_tld = tldextract.extract(currentDomain_full.strip())
                        currentDomain_full = currentDomain_tld.subdomain + '.' + currentDomain_tld.domain + '.' + currentDomain_tld.suffix
                        currentDomain = currentDomain_tld.domain + '.' + currentDomain_tld.suffix
                        if currentDomain not in app_obj.DNSList:
                            print(currentDomain)

                        # get domain info
                        currentDomainInfo = self.domainInfo.loc[self.domainInfo['domain'] == currentDomain]
                        
                        if currentDomainInfo.empty:
                            # TODO add loging
                            print(f"Curr {currentDomain} not found in domain info")
                            print(f"Domain {currentDomain_full} not found in domain info")
                            
                        else:
                            # create domain object and add it to self.domains
                            if currentDomain in self.domainList:
                                currentDomain_obj = self.domainList[currentDomain]
                            else:
                                # create domain object
                                currentDomain_obj = domain.Domain(currentDomain, currentDomainInfo['third_party'].values[0], currentDomainInfo['hipaa_compliant'].values[0], currentDomainInfo['us_ip'].values[0], self.identifiers.keys())
                                self.domainList[currentDomain] = currentDomain_obj
                    else:
                        for identifierKey in identifiers.keys():
                            if _IdentifierSearch(identifierKey, identifiers[identifierKey], line):
                                try:
                                    app_obj.AddDomain(identifierKey, currentDomain_full, currentDomain_obj.thirdParty)
                                    currentDomain_obj.AddApp(app_obj.AppID, identifierKey)
                                except Exception as e:
                                    logging.error(f"Error Adding Domain: {e}")
        except Exception as e:
            logging.error(f"Error Analyzing {app_obj.AppID} Plain Log File: {e}")

    def _Analyze_ChromePacket(self, appPath: Path, identifiers: dict, app_obj: app) -> None:
        """
        Analyze the NetLog file for identifiers.
        """
        try:
            with open(appPath / "chrome_packet", "r") as file:
                for line in file:
                    if domainNext == True:
                        
                        # split domain
                        currentDomain_full = line.split(':')[1]
                        currentDomain_tld = tldextract.extract(currentDomain_full.strip())
                        currentDomain_full = currentDomain_tld.subdomain + '.' + currentDomain_tld.domain + '.' + currentDomain_tld.suffix
                        currentDomain = currentDomain_tld.domain + '.' + currentDomain_tld.suffix
                                             
                        # get domain info
                        currentDomainInfo = self.domainInfo.loc[self.domainInfo['domain'] == currentDomain]
                        
                        if currentDomainInfo.empty:
                            # TODO add loging
                            print(f"Domain {currentDomain} not found in domain info")
                            print(f"Domain {currentDomain_full} not found in domain info")
                        else:
                            # create domain object and add it to self.domains
                            if currentDomain in self.domainList:
                                currentDomain_obj = self.domainList[currentDomain]
                            else:
                                # create domain object
                                currentDomain_obj = domain.Domain(currentDomain, currentDomainInfo['third_party'].values[0], currentDomainInfo['hipaa_compliant'].values[0], currentDomainInfo['us_ip'].values[0], self.identifiers.keys())
                                self.domainList[currentDomain] = currentDomain_obj
                            
                        domainNext = False
                    elif "---------------- new packet ----------------" in line:
                        domainNext = True
                    else:
                        for identifierKey in identifiers.keys():
                            if _IdentifierSearch(identifierKey, identifiers[identifierKey], line):
                                try:
                                    app_obj.AddDomain(identifierKey, currentDomain_full, currentDomain_obj.thirdParty)
                                    currentDomain_obj.AddApp(app_obj.AppID, identifierKey)
                                except Exception as e:
                                    logging.error(f"Error Adding Domain: {e}")
        except Exception as e:
            logging.error(f"Error Analyzing {app_obj.AppID} NetLog File: {e}")

    def ToDataFrame(self) -> pd.DataFrame:
        """
        Convert the PyLogAnalyze object to a pandas DataFrame.
        """
        # if self.inputFile is not None:
        #     # read app from input file
        #     print("Reading results from file...")
        #     try:
        #         with open(self.inputFile, 'r') as f:
        #             df = pd.read_csv(f, index_col=0)
        #     except:
        #         print("Error reading input file to save df")
        #         return
        # else:
        #     #TODO change this? shouldn't be hardcoded
        #     df = pd.DataFrame(columns=['AppID', 'FullName_FirstPart', 'FullName_ThirdParty', 'Email_FirstParty', 'Email_ThirdParty', 'DOB_FirstParty', 'DOB_ThirdParty', 'DeviceID_FirstParty', 'DeviceID_ThirdParty', 'Gender_FirstParty', 'Gender_ThirdParty', 'Phone_FirstParty', 'Phone_ThirdParty', 'IPAddress_FirstParty', 'IPAddress_ThirdParty', 'Fingerprint_FirstParty', 'Fingerprint_ThirdParty', 'Location_FirstParty', 'Location_ThirdParty'])
        appIDs = list(self.appList.keys())

        appDF = pd.DataFrame(columns=self.appList[appIDs[0]].__dict__.keys())

        for appID in appIDs:
            appData = self.appList[appID].GetAppData()
            appDF.loc[len(appDF)] = appData
        
        domainIDs = list(self.domainList.keys())

        domainDF = pd.DataFrame(columns=self.domainList[domainIDs[0]].__dict__.keys())

        for domainID in domainIDs:
            domainData = self.domainList[domainID].GetDomainData()
            domainDF.loc[len(domainDF)] = domainData
    
        return appDF, domainDF

    def ThirdParty(self) -> Tuple[dict, dict, dict, dict]:
        """
        For each identifier key calculate the percentage of third party domains which received the identifier.
        That is, of the domains which received X identifier, what percentage were third party domains?
        """
        us_full = {}
        us_nonfull = {}
        nonus_full = {}
        nonus_nonfull = {}

        for identifierKey in self.identifiers.keys():
            FirstPartyCount = [0]*4
            ThirdPartyCount = [0]*4

            for appID, app in self.appList.items():
                if app.usBased == 1 and app.testStage == 1:
                    FirstPartyCount[0] += app.FirstPartyCount(identifierKey)
                    ThirdPartyCount[0] += app.ThirdPartyCount(identifierKey)
                elif app.usBased == 1 and app.testStage != 1:
                    FirstPartyCount[1] += app.FirstPartyCount(identifierKey)
                    ThirdPartyCount[1] += app.ThirdPartyCount(identifierKey)
                elif app.usBased != 1 and app.testStage == 1:
                    FirstPartyCount[2] += app.FirstPartyCount(identifierKey)
                    ThirdPartyCount[2] += app.ThirdPartyCount(identifierKey)
                else:
                    FirstPartyCount[3] += app.FirstPartyCount(identifierKey)
                    ThirdPartyCount[3] += app.ThirdPartyCount(identifierKey)
            
            us_full[identifierKey] = (ThirdPartyCount[0] / (FirstPartyCount[0] + ThirdPartyCount[0])) if FirstPartyCount[0] + ThirdPartyCount[0] > 0 else 0
            us_nonfull[identifierKey] = (ThirdPartyCount[1] / (FirstPartyCount[1] + ThirdPartyCount[1])) if FirstPartyCount[1] + ThirdPartyCount[1] > 0 else 0
            nonus_full[identifierKey] = (ThirdPartyCount[2] / (FirstPartyCount[2] + ThirdPartyCount[2])) if FirstPartyCount[2] + ThirdPartyCount[2] > 0 else 0
            nonus_nonfull[identifierKey] = (ThirdPartyCount[3] / (FirstPartyCount[3] + ThirdPartyCount[3])) if FirstPartyCount[3] + ThirdPartyCount[3] > 0 else 0

        return us_full, us_nonfull, nonus_full, nonus_nonfull

    def HIPAA(self) -> Tuple[dict, dict, dict, dict]:
        """
        Calculate the percentage of apps that claim HIPAA compliance that share identifiers.
        That is, of the apps that shared ID, what percentage claim HIPAA compliance?
        That is, of the apps that shared medical info, what percentage claim HIPAA compliance?
        """

        # US subset
        us_hipaa_sharedID = 0
        us_nonhipaa_sharedID = 0

        # Totol subset
        hipaa_sharedID = 0
        nonhipaa_sharedID = 0

        for app in self.appList:
            if app.SharedID(['FullName', 'Email', 'DOB', 'DeviceID', 'Gender', 'Phone', 'IPAddress', 'Fingerprint', 'Location']):
                # check if US subset
                if app.usBased == 1:
                    if app.hipaaCompliant == 1:
                        us_hipaa_sharedID += 1
                    else:
                        us_nonhipaa_sharedID += 1
                # total subset
                if app.hipaaCompliant == 1:
                    hipaa_sharedID += 1
                else:
                    nonhipaa_sharedID += 1

        dict = {}
        dict['of the US apps that shared ID this percent claim hipaa compliance'] = us_hipaa_sharedID / (us_hipaa_sharedID + us_nonhipaa_sharedID) if us_hipaa_sharedID + us_nonhipaa_sharedID > 0 else 0
        dict['of the apps that shared ID this percent claim hipaa compliance'] = hipaa_sharedID / (hipaa_sharedID + nonhipaa_sharedID) if hipaa_sharedID + nonhipaa_sharedID > 0 else 0
        print(dict)

        # # US subset
        # us_hipaa_sharedMedical = 0
        # us_nonhipaa_sharedMedical = 0

        # # Totol subset
        # hipaa_sharedMedical = 0
        # nonhipaa_sharedMedical = 0

        # for app in self.appList:
        #     if app.SharedMedical(['MedicalInfo']):
        #         # check if US subset
        #         if app.usBased == 1:
        #             if app.hipaaCompliant == 1:
        #                 us_hipaa_sharedMedical += 1
        #             else:
        #                 us_nonhipaa_sharedMedical += 1
        #         # total subset
        #         if app.hipaaCompliant == 1:
        #             hipaa_sharedMedical += 1
        #         else:
        #             nonhipaa_sharedMedical += 1

        # dict2 = {}
        # dict2['percent of US apps that are HIPAA compliant that shared Medical Info'] = us_hipaa_sharedMedical / (us_hipaa_sharedMedical + us_nonhipaa_sharedMedical) if us_hipaa_sharedMedical + us_nonhipaa_sharedMedical > 0 else 0
        # dict2['percent of apps that are HIPAA compliant that shared Medical Info'] = hipaa_sharedMedical / (hipaa_sharedMedical + nonhipaa_sharedMedical) if hipaa_sharedMedical + nonhipaa_sharedMedical > 0 else 0
        # print(dict2)

    def Domain(self) -> None:
        """
        What percentage of third party domains received 
        """

# US APPs:
# percent of hipaa compliant apps that shared ID vs percent of non hipaa compliant apps that shared ID

# percent of hipaa compliant apps that shared medical info vs percent of non hipaa compliant apps that shared medical info

# All APPs:
# percent of hipaa compliant apps that shared ID vs percent of non hipaa compliant apps that shared ID

# percent of hipaa compliant apps that shared medical info vs percent of non hipaa compliant apps that shared medical info


