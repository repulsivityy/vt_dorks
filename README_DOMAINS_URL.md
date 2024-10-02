## Brand / Domain Monitoring

Searching for any URLs that have been categorised or detected as phishing
```
entity:url (engines:phishing or category:phishing)
```

Searching for typo-squatting domains (leverging fuzzy searches) that looks like Googles but not from the legitimate Google domain
```
entity:domain fuzzy_domain:google.com NOT parent_domain:google.com
```

Searching for websites that uses the same favicon as a brand's page:
```
entity:domain p:1+ main_icon_dhash:"f8e4f23369f0b2f0"

entity: domain (fuzzy_domain:facebook.com OR main_icon_dhash:"f8e4f23369f0b2f0") NOT parent_domain:facebook.com 
```

Leveraging tags to hunt for multiple-redirects
```
entity:url tag:multiple-redirects (fuzzy_hostname:www.microsoft.com NOT (parent_domain:microsoft.com)) response_code:200
```