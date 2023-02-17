## Title
IBM WebSphere Portal SSRF

## Summary
IBM WebSphere Application Server is vulnerable to server-side request forgery (SSRF). By sending a specially crafted request, a remote authenticated attacker could exploit this vulnerability to obtain sensitive data.

## Steps To Reproduce
1. Visit [website]
2. See the data.

## Below is a screenshot
{}

## Other affected assets
{}

## Reference
https://blog.assetnote.io/2021/12/26/chained-ssrf-websphere/

## Impact
The full HTTP response is returned.
