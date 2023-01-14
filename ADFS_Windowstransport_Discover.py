### MAIN ###
# Name:         ADFS_Windowstransport_Discover
# Description:  Searching for vulnerable ADFS endpoints that are exposed to the Internet
# Version:      1.0 | Date: 16.02.2022
# GitHub:       https://github.com/ruschestor/ADFS_Windowstransport_Discover

# Modules
import socket
import requests

# The source list of domains to check
g_originaldomains = ["google.com"]                  # <<<<<<<<<<<<< POPULATE THIS ARRAY <<<<<<<<<<<<<

# Zerroing
g_resultdomains = []
g_resulturls = []

# The list of possible subdomains of ADFS
g_subdomains = ["adfs","sso","sts","ad","fs","federation","stsprod","federationad","eadadfs","auth","fs.sts","adfs.sts","oauth","login","fed","signon","wap","fsauth","stsfed","idp","ldap"]

# The list of vulnerable ADFS endpoints
g_urls = ["/adfs/services/trust/2005/windowstransport","/adfs/services/trust/13/windowstransport","/sts/services/trust/2005/windowstransport","/sts/services/trust/13/windowstransport"]


# Function #1 - Searching subdomains for ADFS
def f1subdomains():
    global g_originaldomains
    global g_subdomains
    global g_resultdomains
    t_domainlist1 = []
    t_domainlist2 = []

    # Generate a list of all possible subdomains
    for t_x in g_originaldomains:
        t_domainlist1.append(t_x)
        for t_y in g_subdomains:
            t_domainlist1.append(t_y + "." + t_x)
    
    # Remove duplicates
    t_domainlist2 = list(dict.fromkeys(t_domainlist1))
    print ("Number of generated subdomains:", len(t_domainlist2))
    print ("Number of founded duplicates:", len(t_domainlist1) - len(t_domainlist2))
    print ("--------------------")

    # Check if domains are exist
    for t_x in t_domainlist2:
        try:
            t_tempdomaindns = socket.gethostbyname(t_x)
        except socket.gaierror:
            print ("Domain ", t_x, " not exist")
        else:
            g_resultdomains.append(t_x)
        
    print ("Number of real domains (",len(g_resultdomains),"): ", g_resultdomains)
    print ("--------------------")

# Function #2 - Searching URLs
def f2urlcheck():
    global g_resultdomains
    global g_urls
    global g_resulturls
    t_urlslist1 = []

    for t_x in g_resultdomains:
        for t_y in g_urls:
            t_urlslist1.append ("https://" + t_x + t_y)
    
    print ("Number of generated URLs: ", str(len(t_urlslist1)))

    # Check if URLs are exist
    for t_x in t_urlslist1:
        try:
            t_response = requests.get(t_x, timeout=1)
            t_server = t_response.headers['Server']
        except:
            pass
        else:
            if (((t_response.status_code == 503) or (t_response.status_code == 401)) and ("Microsoft" in t_server)):
                g_resulturls.append(t_x)

    print ("Number of real URLs ", str(len(g_resulturls)))
    print ("--------------------")

    # Print results
    if len(g_resulturls) != 0:
        print ("VULNERABLE ADFS ENDPOINTS :-)")
        for t_x in g_resulturls:
            print (t_x)
    else:
        print ("Vulnerable ADFS endpoints are not found :-(")


# START
f1subdomains()
f2urlcheck()