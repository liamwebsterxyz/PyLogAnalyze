
from pathlib import Path


class App:
    """
    Initialize the app object.
    """

    def __init__(self, title: str) -> None:

        self.title = title
        self.fullName_FirstParty = set()
        self.fullName_ThirdParty = set()
        self.email_FirstParty = set()
        self.email_ThirdParty = set()
        self.dob_FirstParty = set()
        self.dob_ThirdParty = set()
        self.deviceID_FirstParty = set()
        self.deviceID_ThirdParty = set()
        self.gender_FirstParty = set()
        self.gender_ThirdParty = set()
        self.phone_FirstParty = set()
        self.phone_ThirdParty = set()
        self.ipAddress_FirstParty = set()
        self.ipAddress_ThirdParty = set()
        self.fingerprint_FirstParty = set()
        self.fingerprint_ThirdParty = set()
        self.location_FirstParty = set()
        self.location_ThirdParty = set()


    def AddFullName(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty FullName set.
        """
        if firstParty:
            self.fullName_FirstParty.add(domain)
        else:
            self.fullName_ThirdParty.add(domain)

    def AddEmail(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty Email set.
        """
        if firstParty:
            self.email_FirstParty.add(domain)
        else:
            self.email_ThirdParty.add(domain)
    
    def AddDOB(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty DOB set.
        """
        if firstParty:
            self.dob_FirstParty.add(domain)
        else:
            self.dob_ThirdParty.add(domain)
    
    def AddDeviceID(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty DeviceID set.
        """
        if firstParty:
            self.deviceID_FirstParty.add(domain)
        else:
            self.deviceID_ThirdParty.add(domain)
    
    def AddGender(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty of ThirdParty Gender set.
        """
        if firstParty:
            self.gender_FirstParty.add(domain)
        else:
            self.gender_ThirdParty.add(domain)

    def AddPhone(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty Phone set.
        """
        if firstParty:
            self.phone_FirstParty.add(domain)
        else:
            self.phone_ThirdParty.add(domain)

    def AddIPAddress(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty IPAddress set.
        """
        if firstParty:
            self.ipAddress_FirstParty.add(domain)
        else:
            self.ipAddress_ThirdParty.add(domain)

    def AddFingerprint(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty Fingerprint set.
        """
        if firstParty:
            self.fingerprint_FirstParty.add(domain)
        else:
            self.fingerprint_ThirdParty.add(domain)

    def AddLocation(self, domain: str, firstParty: bool) -> None:
        """
        Add the domain to either the App's FirstParty or ThirdParty Location set.
        """
        if firstParty:
            self.location_FirstParty.add(domain)
        else:
            self.location_ThirdParty.add(domain)

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
                        if self.title in currentDomain:
                            currentParty = True
                        else:
                            currentParty = False
                    else:
                        for identifierKey in identifiers.keys():
                            # TODO improve search process to not be so naive REGEX?
                            if identifiers[identifierKey] in line:
                                if identifierKey == "FullName":
                                    self.AddFullName(currentDomain, currentParty)
                                elif identifierKey == "Email":
                                    self.AddEmail(currentDomain, currentParty)
                                elif identifierKey == "DOB":
                                    self.AddDeviceID(currentDomain, currentParty)
                                elif identifierKey == "DeviceID":
                                    self.AddDeviceID(currentDomain, currentParty)
                                elif identifierKey == "Gender":
                                    self.AddGender(currentDomain, currentParty)
                                elif identifierKey == "Phone":
                                    self.AddPhone(currentDomain, currentParty)
                                elif identifierKey == "IPAddress":
                                    self.AddIPAddress(currentDomain, currentParty)
                                elif identifierKey == "Fingerprint":
                                    self.AddFingerprint(currentDomain, currentParty)
                                elif identifierKey == "Location":
                                    self.AddLocation(currentDomain, currentParty)
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
                        if self.title in currentDomain:
                            currentParty = True
                        else:
                            currentParty = False
                        domainNext = False
                    elif "---------------- new packet ----------------" in line:
                        domainNext = True
                    else:
                        for identifierKey in identifiers.keys():
                            # TODO improve search process to not be so naive REGEX? 
                            # TODO add search until next domain... e.g. to search for first and last name then combine to determine full name 
                            if identifiers[identifierKey] in line:
                                if identifierKey == "FullName":
                                    self.AddFullName(currentDomain, currentParty)
                                elif identifierKey == "Email":
                                    self.AddEmail(currentDomain, currentParty)
                                elif identifierKey == "DOB":
                                    self.AddDeviceID(currentDomain, currentParty)
                                elif identifierKey == "DeviceID":
                                    self.AddDeviceID(currentDomain, currentParty)
                                elif identifierKey == "Gender":
                                    self.AddGender(currentDomain, currentParty)
                                elif identifierKey == "Phone":
                                    self.AddPhone(currentDomain, currentParty)
                                elif identifierKey == "IPAddress":
                                    self.AddIPAddress(currentDomain, currentParty)
                                elif identifierKey == "Fingerprint":
                                    self.AddFingerprint(currentDomain, currentParty)
                                elif identifierKey == "Location":
                                    self.AddLocation(currentDomain, currentParty)
        except Exception as e:
            print(f"Error Opening App File: {e}")



