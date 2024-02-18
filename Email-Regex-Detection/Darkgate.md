# Regex Detection: Darkgate Url Detection

## Reference: 

Blog: https://www.proofpoint.com/us/blog/threat-insight/battleroyal-darkgate-cluster-spreads-email-and-fake-browser-updates

Detection Testing: https://regex101.com/

## Urls:
hxxps://heilee[.]com/qxz3l

hxxps://nathumvida[.]org/

hxxp://searcherbigdealk[.]com:2351/zjbicvmd

hxxp://searcherbigdealk[.]com:2351

hxxp://searcherbigdealk[.]com:2351/msizjbicvmd

hxxps://adclick[.]g[.]doubleclick[.]net/pcs/click?fjWWEJMP5797-NovemberQFRSQG65799kd&&adurl=hxxps://kairoscounselingmi[.]com/

hxxps://kairoscounselingmi[.]com/

hxxps://kairoscounselingmi[.]com/wp-content/uploads/astra/help/pr-nv28-2023[.]ur


## Regex Detection:
```regex
\b(?:https?:\/\/(?:heilee\.com|nathumvida\.org|searcherbigdealk\.com|adclick\.g\.doubleclick\.net|kairoscounselingmi\.com)[^\s'"<>]*|file:\/\/(?:Downloads))[^\s'"<>]*


    



