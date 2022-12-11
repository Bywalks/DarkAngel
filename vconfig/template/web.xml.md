## Title
web.xml configuration file disclosure

## Summary
The WEB-INF/web.xml Deployment Descriptor file describes how to deploy a web application in a servlet container such as Tomcat. Normally, this file should not be accessible. However, I'm able to read the contents of this file by direct visit https://cdn-a.e1-np.sonyentertainmentnetwork.com/WEB-INF/web.xml.

## Steps To Reproduce
1. Visit [website]
2. See the data.

## Image
{F1628232}

## Impact
Information disclosure