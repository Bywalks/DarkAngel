## Title:
Env Disclosure via Spring Boot Actuator - [https://ccap.codeforamerica.org]

## Summary
The Spring Boot Actuators are exposing information on **[website]** and **other** such as the environment configuration.

The endpoints are the following:
- /actuator/env

## PoC - Get the environment configuration
Visit the following URL: https://ccap.codeforamerica.org/actuator/env. The HTTP response will show the Spring Boot configuration file:

## Below is a screenshot
{}

## Other affected sites

## References
https://www.veracode.com/blog/research/exploiting-spring-boot-actuators

## Impact
This way could help attacker search further to spot new vulnerabilties or perform malicious actions. Moreover the configuration of the application is disclosed as well as the client's IP address.