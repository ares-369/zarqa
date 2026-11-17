"""Sample documents for the demo. ALL FICTIONAL: the campaign, malware, actor and organizations are made up;
IP addresses are from the documentation ranges (RFC 5737) and domains end in .example."""

LABEL = "SAMPLE DATA, FICTIONAL"

DOCS = [
    {"title": "SAMPLE: Glassbridge campaign targets utilities with Quillspin loader",
     "url": "https://research.lab.example/glassbridge",
     "text": """SAMPLE DATA, FICTIONAL. This report is invented for the Zarqa demo.

The Glassbridge campaign targeted energy utilities in Northern Europe during the past two weeks and
delivered the Quillspin loader. The operators,
tracked as Tin Heron, sent spearphishing emails with a malicious attachment that installed the Quillspin loader (T1566.001).

Quillspin contacted its command-and-control server at hxxps://cdn-update[.]glassbridge[.]example/api and the IP address 203.0.113.45.
A second stage was downloaded from 198.51.100.23.

The loader's SHA-256 hash is 3f2a8c1d9e7b6a5f4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b.

Tin Heron exploited CVE-2026-31337 in a widely used VPN appliance to reach internal systems.
Victims included the utility domain grid-ops.example, whose staff received the emails.
For background, see our earlier post at https://research.lab.example/earlier."""},
    {"title": "SAMPLE: Advisory, VPN appliance flaw exploited in the wild",
     "url": "https://advisories.gov.example/2026-001",
     "text": """SAMPLE DATA, FICTIONAL.

A critical authentication bypass, CVE-2026-31337, affects the Example VPN Appliance before version 9.4.
Exploitation in the wild has been reported, including by the actor tracked as Tin Heron.
Administrators should upgrade and review logs for connections from 203.0.113.45."""},
    {"title": "SAMPLE: Weekly roundup, retail and football news",
     "url": "https://news.example/roundup",
     "text": """SAMPLE DATA, FICTIONAL.

A football club changed its kit sponsor this week. Retail sales rose in the run-up to the holidays.
Nothing here concerns security."""},
]

ORG = {"name": "Sample Utility (fictional)", "sectors": ["energy", "utilities"], "regions": ["Northern Europe"],
       "products": ["Example VPN Appliance"], "brands": ["sampleutility"], "domains": ["sampleutility.example"]}
REQUIREMENTS = [{"name": "vpn-exploitation", "question": "Is our VPN appliance being exploited?",
                 "terms": ["VPN appliance", "VPN"]}]
NAMES = {"Glassbridge": "campaign", "Quillspin": "malware", "Tin Heron": "actor"}
RELATIONS = [("Glassbridge", "delivers", "Quillspin"), ("Tin Heron", "uses", "Quillspin"),
             ("Quillspin", "communicates_with", "203.0.113.45"), ("Tin Heron", "exploits", "CVE-2026-31337")]
BENIGN = {"grid-ops.example": "victim"}
BRAND = [{"domain": "sampleutiIity.example", "technique": "homoglyph", "age": 4, "page": True},
         {"domain": "sampleutility-login.example", "technique": "word", "age": 12, "page": True},
         {"domain": "sampleutility.example.net", "technique": "tld", "age": 900, "page": False}]
