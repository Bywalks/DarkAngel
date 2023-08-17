## Title 
WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting - [website]

## Summary
WordPress Plugin WPML Version < 4.6.1  is vulnerable to RXSS via wp_lang parameter.

## Steps To Reproduce
1. Use a browser to navigate to: [website]
2. Observe the JavaScript payload being executed.

## Below is a screenshot
{}

## Reference
https://wpml.org/fr/changelog/2023/03/wpml-4-6-1-important-security-update/
https://twitter.com/bug_vs_me/status/1652789903766200320

## Impact
Reflected XSS could lead to data theft through the attacker’s ability to manipulate data through their access to the application, and their ability to interact with other users, including performing other malicious attacks, which would appear to originate from a legitimate user. These malicious actions could also result in reputational damage for the business through the impact to customers trust.