# Regex Detection: Darkgate Url Detection

## Reference: 

Blog: https://www.proofpoint.com/us/blog/threat-insight/battleroyal-darkgate-cluster-spreads-email-and-fake-browser-updates

Detection Testing: https://regex101.com/

**** I want to emphasize that the malicious URLs included in our detection rules have been deliberately obfuscated for security purposes. It's crucial to understand that testing detection mechanisms  based on these obfuscated URLs may lead to inaccurate results.

## Urls:
hxxps://heilee[.]com/qxz3l

hxxps://nathumvida[.]org/

hxxp://searcherbigdealk[.]com:2351/zjbicvmd

hxxp://searcherbigdealk[.]com:2351

hxxp://searcherbigdealk[.]com:2351/msizjbicvmd

hxxps://adclick[.]g[.]doubleclick[.]net/pcs/click?fjWWEJMP5797-NovemberQFRSQG65799kd&&adurl=hxxps://kairoscounselingmi[.]com/

hxxps://kairoscounselingmi[.]com/

hxxps://kairoscounselingmi[.]com/wp-content/uploads/astra/help/pr-nv28-2023[.]url


## Regex Detection:
```regex
\b(?:https?:\/\/(?:heilee\.com|nathumvida\.org|searcherbigdealk\.com|adclick\.g\.doubleclick\.net|kairoscounselingmi\.com)[^\s'"<>]*|file:\/\/(?:Downloads))[^\s'"<>]*


    




