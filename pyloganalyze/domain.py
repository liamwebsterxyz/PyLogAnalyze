
from pathlib import Path
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import List
import logging
import tldextract
import pandas as pd


class Domain:
    """
    Initialize the domain object.
    """

    def __init__(self, domainId: str, third_party: int, hipaa_compliant: int, us_based: int, identifiers: List[str]) -> None:
        self.domainID = domainId
        self.thirdParty = third_party
        self.hipaaCompliant = 1 if hipaa_compliant == 2 or hipaa_compliant == 3 else 0
        self.usBased = us_based
        for identifier in identifiers:
            setattr(self, identifier, set())

    def AddApp(self, appID: str, identifier: str) -> None:
        getattr(self, identifier).add(appID)

    def GetDomainData(self) -> list:
        """
        Return the domain data in a list.
        """
        # TODO: not the best way to do this ie hardcode the order possible?
        ret = []
        for identifiers in self.__dict__.values():
            ret.append(identifiers.values())
        return ret