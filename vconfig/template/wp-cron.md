## Title
WordPress application vulnerable to DoS attack via wp-cron.php - [website]

## Description
Hi team,

The WordPress application is vulnerable to a Denial of Service (DoS) attack via the wp-cron.php script. This script is used by WordPress to perform scheduled tasks, such as publishing scheduled posts, checking for updates, and running plugins.

An attacker can exploit this vulnerability by sending a large number of requests to the wp-cron.php script, causing it to consume excessive resources and overload the server. This can lead to the application becoming unresponsive or crashing, potentially causing data loss and downtime.

I found this vulnerability at [website] endpoint.

## References

https://hackerone.com/reports/1888723
https://medium.com/@thecpanelguy/the-nightmare-that-is-wpcron-php-ae31c1d3ae30

## Steps to Reproduce
1. Get the doser.py script at https://github.com/Quitten/doser.py
2. Use this command to run the script:
```
python3 doser.py -t 999 -g '[website]/wp-cron.php'
```
3. Go to [website] after 1000 requests of the doser.py script.
4. The site returns code 500.
5. See the Image.

## Below is a screenshot
{}

## Suggested Mitigation/Remediation Actions
To mitigate this vulnerability, it is recommended to disable the default WordPress wp-cron.php script and set up a server-side cron job instead.
Here are the steps to disable the default wp-cron.php script and set up a server-side cron job:

   1.  Access your website's root directory via FTP or cPanel File Manager.
   2.  Locate the wp-config.php file and open it for editing.
   3.  Add the following line of code to the file, just before the line that says "That's all, stop editing! Happy publishing.":
```
define('DISABLE_WP_CRON', true);
```
   4.  Save the changes to the wp-config.php file.
   5.  Set up a server-side cron job to run the wp-cron.php script at the desired interval. This can be done using the server's control panel or by editing the server's crontab file.

## Impact

A successful attack on this vulnerability can result in the following consequences:

    - Denial of Service (DoS) attacks, rendering the application unavailable.
    - Server overload and increased resource usage, leading to slow response times or application crashes.
   -  Potential data loss and downtime.