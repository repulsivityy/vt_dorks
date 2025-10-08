# Digital Threat Monitoring 

## Introduction

This document consolidates the different Luncene query searches within Google Threat Intelligence DTM module to search / hunt / monitor specific threats and chatter. 

## Identifying Card Shop Listings
Searching for shop listings of credit cards

```
__type:"shop_listing" AND item_type:"CC"
```

filtering by credit card brand (eg, mastercard, visa)

```
__type:"shop_listing"
AND item_type:"CC"
AND (payment_card.brand:"mc" OR payment_card.brand:"visa")
```

Search via a specific issuer
```
__type:"shop_listing"
AND item_type:"CC"
AND (payment_card.brand:"mc" OR payment_card.brand:"visa")
AND payment_card.issuer:"lloyds*"
```

Search via a specific issuer country
```
__type:"shop_listing" 
AND item_type:"CC" 
AND (payment_card.brand:"mc" OR payment_card.brand:"visa") 
AND (payment_card.issuer:"*singapore*")
```

I want to search for japanese credit cards from the Russian market shop. The credit cards should have a price starting from 10 USD.
```
item_type:CC 
AND shop.name:"Russian market" 
AND price:[10 TO *] 
AND (payment_card.owner.contact.geo_location.country_code:"JP" 
OR payment_card.owner.contact.geo_location.country:"japan")
```

Searching with BIN codes at specific shops

```
__type:"shop_listing" 
AND item_type:"CC" 
AND payment_card.partial_number_prefix:("492182" OR "492181")
AND shop.name:"Real and Rare"
```

## Shops / selling access / IABs
Searching for "HOST ACCESS" shop listings published for a specific product/OS
```
__type:shop_listing 
AND item_type:host_access 
AND host_access.host_info.operating_system:"Windows 2019"
AND body:"healthcare" or body:"wellness" 
```
I want to find forum posts from auctions/access board in the XSS forum

```
__type:forum_post 
AND forum.name:xss.is 
AND board:"ДОСТУПЫ: сети, rdp, шеллы, ftp, sql-inj, DB's"
```

Searching for IABs in a specific forum
```
__type:forum_post 
AND forum.name:rampforum.onion 
AND subject:"Access for sale"
```


## Tracking Personas in forums / messages
I saw a threat actor named Freebandz in the telegram channel SaneMarket. I want to check if they were previously using a different handle, so I need to grab their user_id first. I can perform a search based on this information and look for their user_id in the JSON structure of a message they sent.

```
__type:message 
AND messenger.name:telegram 
AND sender.identity.name:"Freebandz" 
AND channel.name:"SaneMarket"
```

Now I know their user_id is 6774163110 (sender.telegram.user_id from RAW_JSON view of message) so I can look for all messages they sent on telegram channels.

```
__type:message 
AND messenger.name:telegram 
AND sender.telegram.user_id:6774163110
```

Searching for specific forum authors across multiple boards with a known subject
```
__type:forum_post 
AND author.identity.name:"Gmarket" 
AND forum.name:cracked.to 
AND board:*arketplace* 
AND subject.raw:"G Alts Shop"
```

## Monitoring Chatter
Tracking a specific persona named intel broker

```
__type:forum_post AND author.identity.name:"IntelBroker"
```

Tracking telegram channel 
```
__type:message AND (channel.name:"Scattered Lapsus$ Hunter")
```

## Others
Exploits targeting ICS/OT Vulnerabilities

```
(__type:forum_post OR __type:messages) AND (ICS OR OT OR "industrial control") AND ((exploit OR vulnerability OR CVE OR metasploit OR shodan) OR ((modbus OR DNP3 OR profinet) AND (ICS OR OT OR "industrial control")))
```