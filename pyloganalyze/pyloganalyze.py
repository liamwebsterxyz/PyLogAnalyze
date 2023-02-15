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


class PyLogAnalyze:
    """
    Main class for PyLogAnalyze.
    """
    
    def __init__(
        self, 
        appfile: List[Path], 
        identifierdict: dict,
        outputdir: Optional[Path],
    ) -> None:
        self.appPaths = [x.absolute() for x in appfile]
        self.identifiers = identifierdict
        self.outputDir = outputdir
        self.appList = []
    
    def Analyze(self) -> None:
        for appPath in self.appPaths:

            # create an app object
            currentApp = app.App(str(appPath).split('/')[-1])

            # Analyze the app's chrome_packet and net_log files
            currentApp.Analyze_PlainLog(str(appPath), self.identifiers)
            currentApp.Analyze_NetLog(str(appPath), self.identifiers)

            # add app to appList
            self.appList.append(currentApp)

    def Save(self) -> None:
        if self.outputDir is not None:
            # TODO write app to output file
            pass
        else:
            print(self.appList[0].fullName_FirstParty)