# umb-domain-risklevel
Using Umbrella Investigate API for some Threat Hunting Activities  <BR>
 <BR>
<B>umb-domain-risklevel</B> <BR>
Using Umbrella Investigate API for some Threat Hunting Activities. This script leverages Umbrella's Investigate API and pulls interesting attributes to assist with Threat Hunting <BR>
<BR>
  <b>Video walkthrough </B>https://youtu.be/sisQUu_UTE0 <BR>

<B>Script Usage:</B>
Leverage python 3.x. <BR>
Executing the script will prompt you for a domain <BR>
<BR>
Example below: not as aligned as when running in a terminal but it gives you an idea.<BR>

c:\Python37\python.exe umbrella-get-risklevels.py  <BR>
################################################################# <BR>
Author: Jason Maynard Twitter: FE80CC1E <BR>
Version = 1.2  <BR>
Python 3.x  <BR>
Ensure to insall the following modules: <BR>
  "pip install colorama" <BR>
  "pip install termcolor" <BR>
 <BR>
Using Umbrella Investigate API for some Threat Hunting Activities  <BR>
################################################################# <BR>
You accept all responsibilty when using this script yes|no: yes  <BR>
 <BR>
Continuing at your own RISK <BR>

Enter Single Domain your are investigating: interbadguys.com  <BR>
#################################################################  <BR>
STATUS= -1 (malicious), 1 (benign), 0 (not classified When looking to determine whether or not a domain is malicious, the domain status should be considered authoritative over all other Investigate score  <BR>
"Domain and Status": "interbadguys.com" "status":0  <BR>
"security_categories":  <BR>
"content_categories":  <BR>
#################################################################  <BR>

Scaled from 0 to 100, with 100 being the highest risk and 0 being no risk at all RESULT= "risk_score":72

#################################################################  <BR>

Do you want more detail around domain status and categorization? yes|no: yes  <BR>

POWER PLAY TIME! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! BAM! Some of the details that are part of the overall RISK:  <BR>

DGA: Scale -100 (suspicious) to 0 (benign) RESULT= {"dga_score":0.0}

PERPLEXITY: Used with DGA. Scale 0 to 100 RESULT= "perplexity":0.3207940000547262

ENTROPY: Used with DGA and PERPLEXITY RESULT= "entropy":3.584962500721158

SECURERANK2: Scores returned range from -100 (suspicious) to 100 (benign) RESULT= "securerank2":0.4307234564102559

POPULARITY: According to Google's pagerank algorithm RESULT= "pagerank":0.0

ASN REPUTATION SCORE: Ranges from -100 to 0, -100 being very suspicious RESULT= "asn_score":0.0

PREFIX SCORE: Ranges from -100 to 0, -100 being very suspicious RESULT= "prefix_score":0.0

IP REPUTATION SCORE: Ranges from -100 to 0, -100 being very suspicious RESULT= "rip_score":0.0

POPULARITY: A score of how many different client/unique IPs go to this domain compared to others RESULT= "popularity":0.0

FASTFLUX: is a DNS technique used by botnets to hide phishing and malware delivery sites behind an ever-changing network of compromised hosts acting as proxies. RESULT= "fastflux":false ################################################################
