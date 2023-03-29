## Title
xmlrpc.php FILE IS enable it will used for Bruteforce attack and Denial of Service(DoS) - [website]

## Summary
The web application has enabled XMLRPC file which could be potentially used for such an attack against other victim hosts.
In order to determine whether the xmlrpc.php file is enabled or not, using the Repeater tab in Burp, send the request below.

[website]

```
POST /xmlrpc.php HTTP/2
Host: [website]
Content-Length: 95

<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>

```
 For more information on this - check report
https://hackerone.com/reports/325040

## Below is a screenshot
{}

## Remediation
If the XMLRPC.php file is not being used, it should be disabled and removed completely to avoid any potential risks. Otherwise, it should at the very least be blocked from external access.

## Impact
This can be automated from multiple hosts and be used to cause a mass DDOS attack on the victim.

this method is also used for brute force attacks to stealing the admin credentials and other important credentials


