## Title:
Env Disclosure via Spring Boot Actuator

## Summary
The Spring Boot Actuators are exposing critical information on **[website]** and **other** such as the environment configuration.

The endpoints are the following:
- /env

## PoC - Get the environment configuration
Visit the following URL: [website]. The HTTP response will show the Spring Boot configuration file:

**spring.datasource.url:"jdbc:sqlserver://sql004010l.app.123.com;databaseName=UEComProdFMADB"**
**http.nonProxyHosts:"localhost|127.0.0.1|19.0.0.0/8|10.0.0.0/8|172.16.0.0/12|*.123.com"**

## Images
{}

## Other affected sites

## References
https://www.veracode.com/blog/research/exploiting-spring-boot-actuators

## Impact
This way could help attacker search further to spot new vulnerabilties or perform malicious actions. Moreover the configuration of the application is disclosed as well as the client's IP address.