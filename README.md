# Must Mets
Must Mets uses the certificate transparency log to collect new domains and Google safe browsing API to train a machine learning classifier. The goal is to have a continuously updated DNSBL which blocks malicious (malware/phishing/etc) domains in real-time.

The list will be kept small, only domains which have been first seen in the last 14 days will be kept in the list. It is safe to assume that anything older is either no longer used for active attacks or is covered by other blocklists.
