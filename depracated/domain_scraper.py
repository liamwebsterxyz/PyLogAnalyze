# # answer third party:
# - compare domain with appID?
# - if domain in appID then 1
# - else None

# # asnwer us_ip:
# - get ip from domain and check if it is a us ip address
# - if us ip then 1
# - else None

# # answer hipaa:
# - query google site:domain hipaa 
# - if no results 0
# - else None

import pandas as pd, tldextract

import socket, ipaddress

from selenium import webdriver

from bs4 import BeautifulSoup
    
def first_party(domain, appIDs):
    curr_domain = tldextract.extract(domain).domain
    for appID in appIDs:
        if curr_domain in appID:
            return True
    return False

dr = webdriver.Chrome()

domainInfo = pd.read_csv("DomainInfo - Domain Info (2).csv")

appInfo = pd.read_csv("AppInfo - AppInfo (4).csv")

appIDs = appInfo["app_id"].values

for i in range(5):
    domainID = domainInfo.loc[i, 'domain']
    
    # third party
    if first_party(domainID, appIDs):
        domainInfo.loc[i, 'third_party'] = 0
    else:
        domainInfo.loc[i, 'third_party'] = None

    # us_ip
    # look up the IP addresses for the domain name
    try:
        # look up the IP addresses for the domain name
        addresses = socket.getaddrinfo(domainID, None)

        # loop over the IP addresses and check if they are US IP addresses
        for address in addresses:
            ip_address = address[4][0]
            try:
                ip_address_obj = ipaddress.ip_address(ip_address)
                if ip_address_obj.is_private:
                    domainInfo.loc[i, 'us_ip'] = None
                country_code = ip_address_obj.country_code
                if country_code == 'US':
                    domainInfo.loc[i, 'us_ip'] = 1
                    break
            except ValueError:
                domainInfo.loc[i, 'us_ip'] = None
    except:
        domainInfo.loc[i, 'us_ip'] = None

    # hipaa
    # construct the search query
    query = f'site:{domainID} hipaa'

    # send the search request to Google
    response = dr.get(f'https://www.google.com/search?q={query}')
    # parse the search results using BeautifulSoup
    soup = BeautifulSoup(dr.page_source,"lxml")

    # look for the search result count
    result_stats = soup.find(id='result-stats')
    if result_stats is None:
        # no results were found
        domainInfo.loc[i, 'hipaa_compliant'] = 0
    else:
        # extract the number of search results
        domainInfo.loc[i, 'hipaa_compliant'] = None


domainInfo.to_csv("test.csv", index=False)


