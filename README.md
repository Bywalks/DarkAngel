<p align="center">
<img width=500" src="http://www.bywalks.com/image/darkangel.png"><br><br>
<a href="https://github.com/Bywalks/DarkAngel/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/Bywalks/DarkAngel"/></a>
<a href="https://github.com/Bywalks/DarkAngel/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/badge/MIT-License-blue.svg"/></a>
<a href="https://twitter.com/intent/tweet/?text=Fully%20automatic%20white%20hat%20vulnerability%20reward%20scanner,%20from%20hacker%20and%20bugcrowd%20asset%20monitoring%20to%20vulnerability%20report%20generation%20and%20enterprise%20WeChat%20notification.%20https://github.com/Bywalks/DarkAngel%20%23scanner%20%23cybersecurity%20%23bugbounty%20%23infosec%20%23pentest"><img alt="tweet" src="https://img.shields.io/twitter/url?url=https://github.com/Bywalks/DarkAngel" /></a>
<a href="https://twitter.com/Bywalkss"><img alt="Twitter" src="https://img.shields.io/twitter/follow/Bywalkss?label=Followers&style=social" /></a>
<a href="https://github.com/Bywalks"><img alt="Github" src="https://img.shields.io/github/followers/Bywalks?style=social" /></a><br></br>
中文 | <a href="README_EN.md">English</a>
</p>


---

DarkAngel 是一款全自动白帽漏洞扫描器，从hackerone、bugcrowd资产监听到漏洞报告生成、企业微信通知。

DarkAngel 下载地址：[github.com/Bywalks/DarkAngel](https://github.com/Bywalks/DarkAngel)

当前已支持的功能：

- hackerone资产监听；
- bugcrowd资产监听；
- 自定义资产添加；
- 子域名扫描；
- 网站指纹识别；
- 漏洞扫描；
- 漏洞报告自动生成；
- 企业微信通知扫描结果；
- 前端显示扫描结果；

## 自动生成漏洞报告

自动生成漏洞报告 - MarkDown格式 - 存放地址/root/Darkangel/vulscan/results/report

![](http://www.bywalks.com/image/report.jpg)

支持自添加漏洞报告模板，目前已添加漏洞报告模板如下，漏洞名配置为nuclei模板文件名即可

![](http://www.bywalks.com/image/report_template1.jpg)

自定义漏洞报告模板格式

![](http://www.bywalks.com/image/report_template2.jpg)

## 企业微信通知

可先查看如何获取配置：[企业微信开发接口文档](https://developer.work.weixin.qq.com/document/path/90487)

获取参数后，在/root/Darkangel/vconfig/config.ini中配置参数，即可启用企业微信通知

微信通知 - 漏洞结果

 ![](http://www.bywalks.com/image/result_vx2.png)

微信通知 - 扫描进程

 ![](http://www.bywalks.com/image/result_vx1.png)

## 安装

整体项目架构ES+Kibana+扫描器，所以安装需要三个部分

ES镜像：

```
拉取ES镜像
docker pull bywalkss/darkangel:es7.9.3

部署ES镜像
docker run -e ES_JAVA_OPTS="-Xms1024m -Xms1024m" -d -p 9200:9200 -p 9300:9300 --name elasticsearch elasticsearch:7.9.3

查看日志
docker logs -f elasticsearch

出现问题，执行命令
sysctl -w vm.max_map_count=262144

重启docker
docker restart elasticsearch
```

Kibana镜像：

```
拉取Kibana镜像
docker pull bywalkss/darkangel:kibana7.9.3

部署Kibana镜像（修改一下es-ip）
docker run --name kibana -e ELASTICSEARCH_URL=http://es-ip:9200 -p 5601:5601 -d docker.io/bywalkss/darkangel:kibana7.9.3

查看日志
docker logs -f elasticsearch

出现问题，执行命令
sysctl -w vm.max_map_count=262144

重启docker
docker start elasticsearch
```

扫描器镜像：

```
拉取扫描器镜像
docker pull bywalkss/darkangel:v0.0.2

部署扫描器
docker run -it -d -v /root/DarkAngel:/root/DarkAngel --name darkangel bywalkss/darkangel:v0.0.2

进入扫描器docker
docker exec -it docker_id /bin/bash

进入root目录
cd root

下载源代码
git clone https://github.com/Bywalks/DarkAngel.git

进行DarkAngel目录后即可使用
```

docker容器内挂载目录无权限：解决方法1、运行容器时：--privileged=true；解决方法2、宿主机运行命令：setenforce 0

## 用法

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

- 监听hackerone和bugcrowd新域名

![](http://www.bywalks.com/image/add-new-domain.jpg)

### --scan-domain-by-time

```$ python3 darkangel.py --scan-domain-by-time begin-time end-time```

- 以时间间隔为条件，对es库中pdomain进行漏洞扫描，该模块开发目的为对库中pdomain进行分批扫描，缓解一次卡断整个程序出错的问题

![](http://www.bywalks.com/image/scan-domain-by-time.jpg)

### --scan-new-domain

```$ python3 darkangel.py --scan-new-domain```

- 监听hackerone和bugcrowd新域名并进行扫描（第一次使用该程序不建议使用该参数，会把hackerone和bugcrowd域名全部添加进去并扫描，资产过多的情况下做好准备，扫描时间很长）

![](http://www.bywalks.com/image/scan-new-domain.jpg)

### --add-domain-and-scan

```$ python3 darkangel.py --add-domain-and-scan program-file-name1 program-file-name2 --offer-bounty yes/no```

- 自定义添加扫描域名，并对这些域名进行漏洞扫描
- 文件名为厂商名称，文件内存放需扫描域名
- 需提供--offer-bounty参数，设置域名是否提供赏金

 ![](http://www.bywalks.com/image/add_domain_and_scan1.jpg)

![](http://www.bywalks.com/image/add_domain_and_scan2.jpg)

扫描结束后，会把子域名结果存在在/root/Darkangel/vulscan/results/urls目录，按照是否提供赏金分别存放在，bounty_temp_urls_output.txt、nobounty_temp_urls_output.txt文件内

### --nuclei-file-scan

```$ python3 darkangel.py --nuclei-file-scan```

- 用nuclei扫描20个url文件

![](http://www.bywalks.com/image/nuclei-file-scan2.jpg)

url列表存放位置

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-polling-scan

```$ python3 darkangel.py --nuclei-file-polling-scan```

- 轮询用nuclei扫描20个url文件，可把该进程放在后台，轮询扫描，监听是否url列表是否存在新漏洞出现

### --nuclei-file-scan-by-new-temp

```$ python3 darkangel.py --nuclei-file-scan-by-new-temp nuclei-template-version```

- 监听nuclei-template更新，当更新时，对url列表进行扫描

当前nuclei-template版本为9.3.1

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp1.jpg)

执行命令，监听9.3.2版本更新

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp2.jpg)

企业微信通知

 ![](http://www.bywalks.com/image/nuclei_file_scan_by_new_temp3.png)

url列表存放位置

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-scan-by-new-add-temp

```$ python3 darkangel.py --nuclei-file-scan-by-new-add-temp nuclei-template-id```

- 监听nuclei单template更新，当更新时，用该template对url列表进行扫描，这里是打了个时间差，某些时候先提交tempalte，验证后才会加入nuclei模板，在还未加入时，我们已经监听并进行扫描，扫描后id会自动增加，监听并进行扫描

查看nuclei单template的id，这里为6296

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_add_temp1.jpg)

执行命令，对该template进行扫描

![](http://www.bywalks.com/image/nuclei_file_scan_by_new_add_temp2.jpg)

url列表存放位置

![](http://www.bywalks.com/image/nuclei-file-scan1.jpg)

### --nuclei-file-scan-by-temp-name

```$ python3 darkangel.py --nuclei-file-scan-by-temp-name nuclei-template-name```

- 用单template对url列表进行扫描

![](http://www.bywalks.com/image/nuclei_file_scan_by_temp.jpg)

## 结果显示

前端 - 扫描厂商

![](http://www.bywalks.com/image/result_kibana_program.jpg)

前端 - 扫描域名

![](http://www.bywalks.com/image/result_kibana_domain.jpg)

前端 - 扫描结果

![](http://www.bywalks.com/image/result_kibana_vuln.jpg)

微信通知 - 扫描进程

 ![](http://www.bywalks.com/image/result_vx1.png)

微信通知 - 漏洞结果

 ![](http://www.bywalks.com/image/result_vx2.png)
 
## 反馈及贡献代码

首先感谢您花费时间来使DarkAngel变得更好用👍

Bug反馈、建议以及漏洞模板提交，您的Github ID会在以下致谢列表披露：

https://github.com/Bywalks/DarkAngel/blob/main/THANKS.md

Bug反馈

请提交在[GitHub Issues](https://github.com/Bywalks/DarkAngel/issues)中，提供当前的DarkAngel报错信息或截图、详细描述您的复现步骤。

功能建议

在[GitHub Discussions](https://github.com/Bywalks/DarkAngel/discussions)中您可以畅所欲言，同开发人员讨论您想要的功能。

漏洞模板提交

欢迎各位在[GitHub Discussions](https://github.com/Bywalks/DarkAngel/discussions)中提交漏洞模板，开源项目需要每个人的贡献。

## 最近更新

#### [v0.0.3] - 2022-01-17

**更新**  

- 增加只添加hackerone和bugcrowd资产模块 - --add-new-domain
- 增加以时间间隔为条件，对es库中pdomain进行漏洞扫描 - --scan-domain-by-time

#### [v0.0.2] - 2022-12-27

**更新**  

- ES-IP填写错误后进行错误提示
- 改正tools目录下nuclei、xray等文件的执行权限为777

#### [v0.0.1] - 2022-12-12

**功能**  

- hackerone资产监听
- bugcrowd资产监听
- 自定义资产添加
- 子域名扫描
- 网站指纹识别
- 漏洞扫描
- 漏洞报告自动生成
- 企业微信通知扫描结果
- 前端显示扫描结果

## 公众号

![](http://www.bywalks.com/image/official_account.jpg)

## 更多

<div align=center><a href="https://github.com/bywalks"><img src="https://api.star-history.com/svg?repos=Bywalks/DarkAngel&type=Timeline"></a></div>

## 注意事项

* 本工具仅用于合法合规用途，严禁用于违法违规用途。
