<p align="center">
<img width=500" src="http://www.bywalks.com/image/darkangel.png"><br><br>
<a href="https://github.com/Bywalks/DarkAngel/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/Bywalks/DarkAngel"/></a>
<a href="https://github.com/Bywalks/DarkAngel/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/MIT-License-blue.svg"/></a>
<a href="https://twitter.com/intent/tweet/?text=Fully%20automatic%20white%20hat%20vulnerability%20reward%20scanner,%20from%20hacker%20and%20bugcrowd%20asset%20monitoring%20to%20vulnerability%20report%20generation%20and%20enterprise%20WeChat%20notification.%20https://github.com/Bywalks/DarkAngel%20%23scanner%20%23cybersecurity%20%23bugbounty%20%23infosec%20%23pentest"><img alt="tweet" src="https://img.shields.io/twitter/url?url=https://github.com/Bywalks/DarkAngel" /></a>
<a href="https://twitter.com/Bywalkss"><img alt="Twitter" src="https://img.shields.io/twitter/follow/Bywalkss?label=Followers&style=social" /></a>
<a href="https://github.com/Bywalks"><img alt="Github" src="https://img.shields.io/github/followers/Bywalks?style=social" /></a><br></br>
<a href="README.md">中文</a> | English
</p>


---

DarkAngel is a fully automatic white hat vulnerability scanner, which can monitor hacker and bugcrowd assets, generate vulnerability reports, and send enterprise WeChat notifications.

DarkAngel download address：[github.com/Bywalks/DarkAngel](https://github.com/Bywalks/DarkAngel)

Currently supported features：

- Hackerone asset monitoring;
- Bugcrowd asset monitoring;
- Add user-defined assets;
- Sub domain name scanning;
- Website fingerprint identification;
- Vulnerability scanning;
- Automatic generation of vulnerability reports;
- Enterprise WeChat notification scanning results;
- The front end displays the scanning results;

## Automatically generate vulnerability reports

Welcome to submit some vulnerability templates to this project
                           
Automatically generate vulnerability report - MarkDown format - storage address/root/darkangel/vulscan/results/report

![](http://www.bywalks.com/image/report.jpg)

Support for self adding vulnerability report templates. Currently, vulnerability report templates have been added as follows. The vulnerability name can be configured as the file name of the nuclei template

![](http://www.bywalks.com/image/report_template1.jpg)

Custom vulnerability report template format

![](http://www.bywalks.com/image/report_template2.jpg)

## Enterprise WeChat notification

You can view how to obtain the configuration first：[Enterprise WeChat development interface document](https://developer.work.weixin.qq.com/document/path/90487)

After obtaining the parameters, configure the parameters in /root/markup/vconfig/config.ini to enable enterprise WeChat notifications

WeChat Notification - Vulnerability Results

 ![](http://www.bywalks.com/image/result_vx2.png)

WeChat notification - scanning process

 ![](http://www.bywalks.com/image/result_vx1.png)

##Installation

The overall project architecture is ES+Kibana+scanner, so the installation requires three parts

ES image:

```
Pull ES image
docker pull bywalkss/darkangel:es7.9.3

Deploy ES image
docker run -e ES_ JAVA_ OPTS="-Xms1024m -Xms1024m" -d -p 9200:9200 -p 9300:9300 --name elasticsearch elasticsearch:7.9.3

view log
docker logs -f elasticsearch

If there is a problem, execute the command
sysctl -w vm.max_ map_ count=262144

Restart Docker
docker restart elasticsearch
```

Kibana image:

```
Pull Kibana image
docker pull bywalkss/darkangel:kibana7.9.3

Deploy Kibana image (modify the es ip)
docker run --name kibana -e ELASTICSEARCH_ URL= http://es-ip:9200 -p 5601:5601 -d docker.io/bywalkss/darkangel:kibana7.9.3

view log
docker logs -f elasticsearch

If there is a problem, execute the command
sysctl -w vm.max_ map_ count=262144

Restart Docker
docker start elasticsearch
```

Scanner image:

```
Pull Scanner Image
docker pull bywalkss/darkangel:v0.0.2

Deployment Scanner
docker run -it -d -v /root/Darkangel:/root/Darkangel --name darkangel bywalkss/darkangel:v0.0.2

Enter the scanner docker
docker exec -it docker_id /bin/bash

Enter the root directory
cd root

Download source code
git clone https://github.com/Bywalks/DarkAngel.git

Add execution permissions
chmod 777 /root/DarkAngel/vulscan/tools/*

You can use it after into the DarkAngel directory
```

The directory mounted in the docker container does not have permission: Solution 1. When running the container: --privileged=true; Solution 2. The host runs the command: setenforce 0

## usage

```
usage: darkangel.py [-h] [--add-new-domain]
                    [--scan-domain-by-time SCAN_DOMAIN_BY_TIME SCAN_DOMAIN_BY_TIME]
                    [--scan-new-domain]
                    [--add-domain-and-scan ADD_DOMAIN_AND_SCAN [ADD_DOMAIN_AND_SCAN ...]]
                    [--offer-bounty {yes,no}] [--nuclei-file-scan]
                    [--nuclei-file-scan-by-new-temp NUCLEI_FILE_SCAN_BY_NEW_TEMP]
                    [--nuclei-file-scan-by-new-add-temp NUCLEI_FILE_SCAN_BY_NEW_ADD_TEMP]
                    [--nuclei-file-scan-by-temp-name NUCLEI_FILE_SCAN_BY_TEMP_NAME]
                    [--nuclei-file-polling-scan]

DarkAngel is a white hat scanner. Every user makes the Internet more secure.

--------------------------------------------------------------------------------

optional arguments:
  -h, --help            show this help message and exit
  --add-new-domain      add new domain from h1 and bc
  --scan-domain-by-time SCAN_DOMAIN_BY_TIME SCAN_DOMAIN_BY_TIME
                        scan h1 and bc domain by launched time
  --scan-new-domain     add and scan new domain from h1 and bc
  --add-domain-and-scan ADD_DOMAIN_AND_SCAN [ADD_DOMAIN_AND_SCAN ...]
                        add and scan new domain self added
  --offer-bounty {yes,no}
                        set add domain is bounty or no bounty
  --nuclei-file-scan    scan new domain from h1 and bc
  --nuclei-file-scan-by-new-temp NUCLEI_FILE_SCAN_BY_NEW_TEMP
                        use new template scan five file by nuclei
  --nuclei-file-scan-by-new-add-temp NUCLEI_FILE_SCAN_BY_NEW_ADD_TEMP
                        add new template scan five file by nuclei
  --nuclei-file-scan-by-temp-name NUCLEI_FILE_SCAN_BY_TEMP_NAME
                        use template scan five file by nuclei
  --nuclei-file-polling-scan
                        five file polling scan by nuclei
```

### --add-new-domain

```$ python3 darkangel.py --add-new-domain```

- Listen to the new domain names of hackerone and bugcrowd

![](http://www.bywalks.com/image/add-new-domain.jpg)

### --scan-domain-by-time

```$ python3 darkangel.py --scan-domain-by-time begin-time end-time```

- With the time interval as the condition, the pdomain in the es library is scanned for vulnerabilities. The development purpose of this module is to scan the pdomain in the library in batches to alleviate the problem of blocking the whole program at one time

![](http://www.bywalks.com/image/scan-domain-by-time.jpg)

### --scan-new-domain

```$ python3 darkangel.py --scan-new-domain```

- Monitor the hacker and bugcrowd domain names and scan them (when using them for the first time, all the hacker and bugcrowd domain names will be added. Prepare when there are too many assets, and the scan takes a long time)

![](http://www.bywalks.com/image/scan-new-domain.jpg)

### --add-domain-and-scan

```$ python3 darkangel.py --add-domain-and-scan program-file-name1 program-file-name2 --offer-bounty yes/no```

-Customized addition of scanning domain names and vulnerability scanning of these domain names
-The file name is the name of the manufacturer, and the file memory needs to scan the domain name
-The --offer-bounty parameter is required to set whether the domain name provides reward

![](http://www.bywalks.com/image/add_domain_and_scan1.jpg)

![](http://www.bywalks.com/image/add_domain_and_scan2.jpg)

After scanning, the subdomain name results will be stored in the /root/Darkangel/vulscan/results/urls directory，They are stored in the，bounty_temp_urls_output.txt、nobounty_temp_urls_output.txt In document

### --nuclei-file-scan

```$ python3 darkangel.py --nuclei-file-scan```

- Scan 20 url files with nuclei

![](http://www.bywalks.com/image/nuclei-file-scan2.jpg)

URL list storage location

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-polling-scan

```$ python3 darkangel.py --nuclei-file-polling-scan```

- Polling uses Nuclei to scan 20 url files. You can put the process in the background, poll and scan, and listen for new vulnerabilities in the url list

### --nuclei-file-scan-by-new-temp

```$ python3 darkangel.py --nuclei-file-scan-by-new-temp nuclei-template-version```

- Listen for updates to the nucleus template. When updating, scan the url list

The current nuclear template version is 9.3.1

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp1.jpg)

Execute the command to monitor the 9.3.2 version update

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp2.jpg)

Enterprise WeChat notification

 ![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp3.png)

URL list storage location

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-scan-by-new-add-temp

```$ python3 darkangel.py --nuclei-file-scan-by-new-add-temp nuclei-template-id```

- Monitor the update of the single template of nuclei. When updating, use this template to scan the url list. There is a time difference here. Sometimes, submit the tempalte first, and then add the nuclei template after verification. When we have not yet joined, we have already listened and scanned. After scanning, the ID will automatically increase, and listen and scan

Check the ID of the single template of Nuclei, which is 6296 here

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_add_temp1.jpg)

Execute the command to scan the template

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_add_temp2.jpg)

URL list storage location

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-scan-by-temp-name

```$ python3 darkangel.py --nuclei-file-scan-by-temp-name nuclei-template-name```

- Scan the url list with a single template

![](http://www.bywalks.com/image/nuclei_file_scan_by_temp.jpg)

## Result display

Front end scanning manufacturer

![]( http://www.bywalks.com/image/result_kibana_program.jpg )

Front end - scan domain name

![]( http://www.bywalks.com/image/result_kibana_domain.jpg )

Front End - Scan Results

![]( http://www.bywalks.com/image/result_kibana_vuln.jpg )

WeChat notification - scanning process

![]( http://www.bywalks.com/image/result_vx1.png )

WeChat Notification - Vulnerability Results

![](http://www.bywalks.com/image/result_vx2.png)
                                                  
## Feedback and contribution code

First of all, thank you for taking the time to make DarkAngel better 👍

Bug feedback, suggestions and vulnerability template submission, your Github ID will be disclosed in the following thanks list:

https://github.com/Bywalks/DarkAngel/blob/main/THANKS.md

Bug feedback

Please submit the current DarkAngel error message or screenshot in [GitHub Issues](https://github.com/Bywalks/DarkAngel/issues), and describe your replication steps in detail.

Function suggestions

In [GitHub Discussions](https://github.com/Bywalks/DarkAngel/discussions), you can speak freely and discuss the functions you want with the developers.

Vulnerability template submission

Welcome to submit vulnerability templates in [GitHub Discussions](https://github.com/Bywalks/DarkAngel/discussions). Open source projects require everyone's contribution.
                                                  
## Recent Updates

#### [v0.0.4] - 2022-02-07

**Update** 

- Update xray to version 1.9.4 and update the configuration file
- Update nuclei to version 2.8.8 and update the configuration file
- Add missing httpx, naabu, crawlergo, whatweb



#### [v0.0.3] - 2022-01-17

**Update**

- Add only the hacker and bugrow asset modules -- add new domain
- Add a vulnerability scan for pdomain in es database based on time interval -- scan-domain-by-time

#### [v0.0.2] - 2022-12-27

**update**  

- Error prompt after filling in ES-IP error
- Correct that the execution permissions of files such as nucleus and xray in the tools directory are 777

#### [v0.0.1] - 2022-12-12

**function**  

- Hackerone asset monitoring
- Bugcrowd asset monitoring
- Custom Asset Add
- Sub domain name scanning
- Website fingerprint identification
- Vulnerability scanning
- Automatic generation of vulnerability reports
- Enterprise WeChat notification scanning results
- Front end displays scanning results

## more

<div align=center><a href="https://github.com/bywalks"><img src="https://api.star-history.com/svg?repos=Bywalks/DarkAngel&type=Timeline"></a></div>

## matters needing attention

* This tool is only used for legal and compliance purposes, and it is strictly prohibited to use it for illegal purposes.
