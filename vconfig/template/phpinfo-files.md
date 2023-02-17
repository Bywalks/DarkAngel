## Title
PHP info page disclosure 

## Summary
The phpinfo() is a debug functionality that prints out detailed information on both the system and the PHP configuration. 

## Steps To Reproduce
1. Visit [website]
2. See the data.

## Below is a screenshot
{}

### References
https://hackerone.com/reports/165930
https://www.php.net/manual/en/function.phpinfo.php

## Impact
An attacker can obtain information such as:

• Exact PHP version 
• Exact SO version 
• Kernel headers 
• Kernel binary 
• Server usernames (XXX) 
• Details of the PHP configuration.  
• Installed modules  
• Server environment variables.  
• Loaded PHP extensions and their configurations.
• Master and local values of configuration options
• HTTP headers
• PHP License.

This information can help an attacker gain more information on the system. After gaining detailed information, the attacker can research known vulnerabilities for that system under review. The attacker can also use this information during the exploitation of other vulnerabilities.





