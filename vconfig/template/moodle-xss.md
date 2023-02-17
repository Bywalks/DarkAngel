## Title
Moodle redirect_uri Reflected XSS

# Summary
XSS in moodle via redirect_uri parameter.Reflected cross-site scripting (XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way. An attacker can execute JavaScript arbitrary code on the victim's session.

## Steps To Reproduce
1. Go to: [website]
2. Boom

## Below is a screenshot
{}

## Supporting Material/References
https://twitter.com/jacksonhhax/status/1391367064154042377

## Impact
1. Perform any action within the application that the user can perform.
2. View any information that the user is able to view.
3. Modify any information that the user is able to modify.
4. Initiate interactions with other application users, including malicious attacks, that will appear to originate from the initial victim user..
Steal user's cookie. 



