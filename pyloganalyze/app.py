
from pathlib import Path
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import List
import logging
import tldextract
import pandas as pd


class App:
    """
    Initialize the app object.
    """

    def __init__(self, appId: str, procId: int, test_stage: int, hipaa_compliant: int, us_based: int, identifiers: List[str]) -> None:
        self.AppID = appId
        self.ProcID = procId
        self.testStage = 1 if test_stage == 3 else 0
        self.hipaaCompliant = hipaa_compliant
        self.usBased = us_based
        for identifier in identifiers:
            setattr(self, identifier + "_FirstParty", set())
            setattr(self, identifier + "_ThirdParty", set())
        self.DNSproccessIDs = set()
        self.DNSList = set()
        self.trafficList = set()

    def SharedID(self, identifiers) -> bool:
        """
        Return true if the app shares identifiers with other apps.
        """
        for identifier in identifiers:
            if self.ThirdPartyCount(identifier) > 0:
                return True
        return False

    def SharedMedical(self, identifiers) -> bool:
        """
        Return true if the app shares medical identifiers with other apps.
        """
        for identifier in identifiers:
            if self.ThirdPartyCount(identifier) > 0:
                return True
        return False

    def ThirdPartyCount(self, identifierKey: str) -> int:
        """
        Return the number of third party domains that received the given identifier.
        """
        return len(getattr(self, identifierKey + "_ThirdParty"))
    
    def FirstPartyCount(self, identifierKey: str) -> int:
        """
        Return the number of first party domains that received the given identifier.
        """
        return len(getattr(self, identifierKey + "_FirstParty"))

    def GetAppData(self) -> list:
        """
        Return the app data in a list.
        """
        # TODO: not the best way to do this ie hardcode the order possible?
        ret = []
        for identifiers in self.__dict__.values():
            ret.append(identifiers)
        return ret

    def AddDomain(self, identifierKey: str, domain: str, thirdParty: bool,) -> None:
        """
        Add the domain to either the App's first party or third party set corresponding to the given identifier key.
        """
        if not thirdParty:
            getattr(self, identifierKey + "_FirstParty").add(domain)
        else:
            getattr(self, identifierKey + "_ThirdParty").add(domain)
   