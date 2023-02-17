## Title
Reflected Cross-Site Scripting - [website]

## Summary
Reflected Cross-Site Scripting (XSS) is a type of injection attack where malicious JavaScript code is injected into a website. When a user visits the affected web page, the JavaScript code executes and its input is reflected in the user's browser. Reflected XSS can be found on this domain which allows an attacker to create a crafted URL which when opened by a user will execute arbitrary Javascript within that user's browser in the context of this domain.

When an attacker can control code that is executed within a user’s browser, they are able to carry out any actions that the user is able to perform, including accessing any of the user's data and modifying information within the user’s permissions. This can result in modification, deletion, or theft of data, including accessing or deleting files, or stealing session cookies which an attacker could use to hijack a user’s session.

## Steps To Reproduce
1. Use a browser to navigate to: [website]
2. Observe the JavaScript payload being executed.

## Below is a screenshot
{}

## Reference
https://owasp.org/www-community/attacks/xss/
https://portswigger.net/web-security/cross-site-scripting

## Impact
Reflected XSS could lead to data theft through the attacker’s ability to manipulate data through their access to the application, and their ability to interact with other users, including performing other malicious attacks, which would appear to originate from a legitimate user. These malicious actions could also result in reputational damage for the business through the impact to customers trust.
