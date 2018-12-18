__author__ = 'Jason Maynard'
#
print ('#################################################################')
print ('Author: Jason Maynard')
print ('Twitter: FE80CC1E')
print ('Version = 1.2')
print ('Python 3.x ensure to insall the following modules')
print ('  pip install colorama')
print ('  pip install termcolor')
print ()
print ('Using Umbrella Investigate API for some Threat Hunting Activities')
print ('#################################################################')

import requests
#Requests is an Apache2 Licensed HTTP library, written in Python. ...
#Requests will allow you to send HTTP/1.1 requests using Python. With it,
#you can add content like headers, form data, multipart files, and parameters via simple
#Python libraries. It also allows you to access the response data of Python in the same way.
import re
#This module provides regular expression matching operations similar to those found in Perl
from colorama import init
from termcolor import colored
init()
# use Colorama to make Termcolor work on Windows as well. :)

#user prompt 
varRISK = input ('You accept all responsibilty when using this script yes|no: ')
if varRISK == 'yes':
    print ('Continuing at your own RISK')
else:
    exit()
print ()

#user prompt 
varDOMAIN = input ('Enter Single Domain your are investigating: ')

#build headers (token for investigate API)
var_HEADERS = {
    'Authorization': "Bearer xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    }

#domain categories
#Details https://docs.umbrella.com/investigate-api/docs/domain-status-and-categorization-1
var_URL_CATEGORIES = "https://investigate.api.umbrella.com/domains/categorization/" + varDOMAIN
var_LABELS = {"showLabels":""}
var_RESPONSE_CATEGORIES = requests.request("GET", var_URL_CATEGORIES, headers=var_HEADERS, params=var_LABELS)
var_OUTPUT0 = var_RESPONSE_CATEGORIES.text

print ('#################################################################')
print ()
print ('STATUS= -1 (malicious), 1 (benign), 0 (not classified')
print ('When looking to determine whether or not a domain is malicious, the domain status')
print ('should be considered authoritative over all other Investigate score')

var_DNAME = var_OUTPUT0.split(",")[0]
var_PDNAME = re.sub(r'[{|}|\[\]]',r' ',var_DNAME)
print (colored('  "Domain and Status":' + var_PDNAME, 'red'))

var_SECCAT = var_OUTPUT0.split(",")[1]
var_PSECCAT = re.sub(r'[{|}|\[\]]',r' ',var_SECCAT)
print (colored('  ' + var_PSECCAT, 'red'))

var_WEBCAT = var_OUTPUT0.split(",")[2]
var_PWEBCAT = re.sub(r'[{|}|\[\]]',r' ',var_WEBCAT)
print (colored('  ' + var_PWEBCAT, 'red'))

#domain risk-score
#Details https://docs.umbrella.com/investigate-api/docs/domain-status-and-categorization-1
var_URL_RISK = "https://investigate.api.umbrella.com/domains/risk-score/" + varDOMAIN
var_RESPONSE_RISK = requests.request("GET", var_URL_RISK , headers=var_HEADERS)
var_OUTPUT1 = var_RESPONSE_RISK.text
var_PRESPONSE_RISK = re.sub(r'[{|}|\[\]]',r' ',var_OUTPUT1)

print ('#################################################################')
print ()
print ('Scaled from 0 to 100, with 100 being the highest risk and 0 being no risk at all')
print (colored('  RESULT= ' + var_PRESPONSE_RISK, 'red'))
print ('#################################################################')
print ()

varCONTINUE = input ('Do you want more detail around domain status and categorization? yes|no: ')
if varCONTINUE == 'yes':
    print ()
    print ('POWER PLAY TIME!')
    print ('BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM!')
else:
    exit()

#domain risk details
#Details https://docs.umbrella.com/investigate-api/docs/security-information-for-a-domain-1
var_URL_DETAILS = "https://investigate.api.umbrella.com/security/name/" + varDOMAIN
var_RESPONSE_DETAILS = requests.request("GET", var_URL_DETAILS, headers=var_HEADERS)
var_OUTPUT2 = var_RESPONSE_DETAILS.text

var_DGASCORE = var_OUTPUT2.split(",")[0]
print ('Some of the details that are part of the overall RISK: ')
print ()
print ('DGA: Scale -100 (suspicious) to 0 (benign)')
print (colored('  RESULT= ' + var_DGASCORE + '}', 'red'))
print ()
var_PERPLEXITY = var_OUTPUT2.split(",")[1]
print ('PERPLEXITY: Used with DGA. Scale 0 to 100')
print (colored('  RESULT= ' + var_PERPLEXITY, 'red'))
print ()
var_ENTROPY = var_OUTPUT2.split(",")[2]
print ('ENTROPY: Used with DGA and PERPLEXITY')
print (colored('  RESULT= ' + var_ENTROPY, 'red'))
print ()
var_SECURERANK = var_OUTPUT2.split(",")[3]
print ('SECURERANK2: Scores returned range from -100 (suspicious) to 100 (benign)')
print (colored('  RESULT= ' + var_SECURERANK, 'red'))
print ()
var_PAGERANK = var_OUTPUT2.split(",")[4]
print ('POPULARITY: According to Google\'s pagerank algorithm')
print (colored('  RESULT= ' + var_PAGERANK, 'red'))
print ()
var_ASNSCORE = var_OUTPUT2.split(",")[5]
print ('ASN REPUTATION SCORE: Ranges from -100 to 0, -100 being very suspicious')
print (colored('  RESULT= ' + var_ASNSCORE, 'red'))
print ()
var_PREFIXSCORE = var_OUTPUT2.split(",")[6]
print ('PREFIX SCORE: Ranges from -100 to 0, -100 being very suspicious')
print (colored('  RESULT= ' + var_PREFIXSCORE, 'red'))
print ()
var_RIPSCORE = var_OUTPUT2.split(",")[7]
print ('IP REPUTATION SCORE: Ranges from -100 to 0, -100 being very suspicious')
print (colored('  RESULT= ' + var_RIPSCORE, 'red'))
print ()
var_POPULARITY = var_OUTPUT2.split(",")[8]
print ('POPULARITY: A score of how many different client/unique IPs go to this domain compared to others')
print (colored('  RESULT= ' + var_POPULARITY, 'red'))
print ()
var_FASTFLUX = var_OUTPUT2.split(",")[9]
print ('FASTFLUX:  is a DNS technique used by botnets to hide phishing and malware delivery sites behind an ever-changing')
print ('network of compromised hosts acting as proxies.')
print (colored('  RESULT= ' + var_FASTFLUX, 'red'))
print ('################################################################')
#DGA: 'Domain Generation Algorithm. This score is generated based on the likeliness of the domain name being generated by an algorithm rather than a human. This algorithm is designed to identify domains which have been created using an automated randomization strategy, which is a common evasion technique in malware kits or botnets.
#PERPLEXITY 'A second score on the likeliness of the name to be algorithmically generated, on a scale from 0 to 100. This score is to be used in conjunction with DGA.'
#ENTROPY This score is to be used in conjunction with DGA and Perplexity.
#SECURERANK Suspicious rank for a domain that reviews based on the lookup behavior of client IP for the domain. Securerank is designed to identify hostnames requested by known infected clients but never requested by clean clients, assuming these domains are more likely to be bad. Scores returned range from -100 (suspicious) to 100 (benign).
#POPULARITY Popularity according to Google's pagerank algorithm
#ASN SCORE ASN reputation score, ranges from -100 to 0 with -100 being very suspicious.
#PREFIX SCORE Prefix ranks domains given their IP prefixes (an IP prefix is the first three octets in an IP address) and the reputation score of these prefixes. Ranges from -100 to 0, -100 being very suspicious
#RIP ranks domains given their IP addresses and the reputation score of these IP addresses. Ranges from -100 to 0, -100 being very suspicious.
#POPULARITY The number of unique client IPs visiting this site, relative to the all requests to all sites. A score of how many different client/unique IPs go to this domain compared to others.
#FASTFLUX is a DNS technique used by botnets to hide phishing and malware delivery sites behind an ever-changing network of compromised hosts acting as proxies




