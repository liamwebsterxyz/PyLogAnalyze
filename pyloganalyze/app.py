
from pathlib import Path


class App:
    """
    Initialize the app object.
    """

    def __init__(self, appId: str, identifiers: list[str]) -> None:
        self.AppID = appId
        for identifier in identifiers:
            setattr(self, identifier + "_FirstParty", set())
            setattr(self, identifier + "_ThirdParty", set())


    def PercentThirdParty(self, identifierKey: str) -> float:
        """
        Calculate the percentage of third party domains that the app has identified.
        """
        total = len(getattr(self, identifierKey + "_FirstParty")) + len(getattr(self, identifierKey + "_ThirdParty"))
        if total == 0:
            return 0
        return len(getattr(self, identifierKey + "_ThirdParty")) // total

    def GetAppData(self) -> list:
        # TODO: not the best way to do this ie hardcode the order possible?
        ret = []
        for identifiers in self.__dict__.values():
            ret.append(identifiers)
        return ret

    def AddDomain(self, identifierKey: str, domain: str, firstParty: bool,) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty set corresponding to the given identifier key.
        """
        if firstParty:
            getattr(self, identifierKey + "_FirstParty").add(domain)
        else:
            getattr(self, identifierKey + "_ThirdParty").add(domain)


    def IdentifierSearch(self, identifierKey: str, identifiers: list[str], line: str) -> bool:
        # TODO improve search process to not be so naive REGEX? 
        # TODO add search until next domain... e.g. to search for first and last name then combine to determine full name 
        line = line.lower()
        success = False
        if identifierKey == "FullName":
            for identity in identifiers:
                full_name = identity.split(' ')
                for namepart in full_name:
                    if namepart in line:
                        success = True
                    else:
                        success = False
                        break
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
   
    def Analyze_PlainLog(self, appPath: Path, identifiers: dict) -> None:
        """
        Analyze the plain log file for identifiers.
        """
        try:
            with open(appPath + "/plain_log", "r") as file:
                currentDomain = None
                currentParty = None
                for line in file:
                    if ('(packet)' in line):
                        currentDomain = line
                        if self.AppID in currentDomain:
                            currentParty = True
                        else:
                            currentParty = False
                    else:
                        for identifierKey in identifiers.keys():
                            if self.IdentifierSearch(identifierKey, identifiers[identifierKey], line):
                                try:
                                    self.AddDomain(identifierKey, str(currentDomain).split(':')[0], currentParty)
                                except Exception as e:
                                    print(f"Error Adding Domain: {e}")
        except Exception as e:
            print(f"Error Opening App File: {e}")

    def Analyze_NetLog(self, appPath: Path, identifiers: dict) -> None:
        """
        Analyze the NetLog file for identifiers.
        """
        try:
            with open(appPath + "/chrome_packet", "r") as file:
                domainNext = False
                currentDomain = None
                currentParty = None
                for line in file:
                    if domainNext == True:
                        currentDomain = line
                        if self.AppID in currentDomain:
                            currentParty = True
                        else:
                            currentParty = False
                        domainNext = False
                    elif "---------------- new packet ----------------" in line:
                        domainNext = True
                    else:
                        for identifierKey in identifiers.keys():
                            if self.IdentifierSearch(identifierKey, identifiers[identifierKey], line):
                                try:
                                    self.AddDomain(identifierKey, currentDomain, currentParty)
                                except Exception as e:
                                    print(f"Error Adding Domain: {e}")
        except Exception as e:
            print(f"Error Opening App File: {e}")
