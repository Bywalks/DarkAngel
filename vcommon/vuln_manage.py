# !/usr/bin/env python
# -*-coding:utf-8 -*-

'''
# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
'''

import os
import sys
import json
import time
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vconfig.config import *
from vcommon.ESHelper import ESHelper
from vconfig.log import logger
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# 防止SSL报错
requests.packages.urllib3.disable_warnings()

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class VulnManager(object):

    """
            vuln_assets-1 field description:
                launched_at: 漏洞发现时间
                scan_name: 扫描引擎
                website: 漏洞所属网站
                vuln_name: 漏洞名
                vuln_type：漏洞类型
                scan_detail： 漏洞详情
                risk_score:  风险得分
    """

    def __init__(self):
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.report_resultDir = PARENT_DIR + "/vulscan/results/report"
        self.report_tempDir = PARENT_DIR + "/vconfig/template"
        self.vuln_index = "vuln-assets-1"
        self.spider_index = "spider-assets-1"
        self.vuln_score_map = {"baseline": 1, 'xss': 5, "ssrf": 5, "sql-injection": 5, "xxe": 5, "cmd-injection": 5,
                              "crlf-injection": 5, "jsonp/fastjson": 4, "dirscan": 2, "upload": 5, "path-traversal": 4,
                              "redirect": 4, "cve": 4, "弱口令": 5, "struts": 4, "thinkphp": 4, 'other': 1, 'critical': 5, 'high': 4, 'medium': 3,
                              'low': 2, 'info': 1}

    @classmethod
    def add_vuln_type(self,scan_item):
        vuln_name = scan_item.get('vuln_name')
        if not vuln_name:
            return
        vuln_name = vuln_name.lower()
        if len(vuln_name.split('/')) > 2:
            vuln_type = vuln_name.split('/')[0]
        #上面一个条件即可解决xray的vuln_type问题
        elif vuln_name.find('弱口令') >= 0 or vuln_name.find('未授权') >= 0 or vuln_name.find('登录绕过') >= 0:
            vuln_type = '弱口令'
        elif vuln_name.find('泄露') >= 0 or vuln_name.find('文件读') >= 0:
            vuln_type = 'baseline'
        elif vuln_name.find('xss') >= 0:
            vuln_type = 'xss'
        elif vuln_name.find('sql') >= 0:
            vuln_type = 'sql-injection'
        elif vuln_name.find('json') >= 0 or vuln_name.find('序列化') >= 0:
            vuln_type = 'jsonp/fastjson'
        elif vuln_name.find('struts') >= 0:
            vuln_type = 'struts'
        elif vuln_name.find('thinkphp') >= 0:
            vuln_type = 'thinkphp'
        elif vuln_name.find('traversal') >= 0 or vuln_name.find('穿越') >= 0:
            vuln_type = 'path-traversal'
        elif vuln_name.find('redirect') >= 0 or vuln_name.find('跳转') >= 0:
            vuln_type = 'redirect'
        elif vuln_name.find('dirscan') >= 0 or vuln_name.find('目录') >= 0 or vuln_name.find('枚举') >= 0:
            vuln_type = 'dirscan'
        elif vuln_name.find('upload') >= 0 or vuln_name.find('文件写') >= 0 or vuln_name.find('文件上传') >= 0:
            vuln_type = 'upload'
        elif vuln_name.find("cmd-injection") != -1 or vuln_name.find("rce") != -1 or vuln_name.find("代码") != -1 or\
                vuln_name.find("执行") != -1:
            vuln_type = 'cmd-injection'
        elif vuln_name.find('poc') >= 0 or vuln_name.find('cve') != -1 or vuln_name.find("phantasm") != -1 or\
                vuln_name.find('漏洞') >= 0:
            vuln_type = 'cve'
        else:
            vuln_type = vuln_name
        scan_item["vuln_type"] = vuln_type

    def add_vuln_score(self,scan_item):
        vuln_type = scan_item['vuln_type']
        vuln_score = self.vuln_score_map.get(vuln_type, 1)
        scan_item['vuln_score'] = vuln_score
        if vuln_score >= 4:
            self.send_vuln_message(scan_item)

    def add_nuclei_vuln_score(self,scan_item):
        vuln_level = scan_item['scan_detail']['info']['severity']
        vuln_score = self.vuln_score_map.get(vuln_level, 1)
        scan_item['vuln_score'] = vuln_score
        if vuln_score >= 3:
            self.send_vuln_message(scan_item)

    def get_vx_token(self):
        url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={CORPID}&corpsecret={CORPSECRET}"
        r = requests.get(url=url, verify=False, timeout=10)
        text = json.loads(r.text)
        token = text["access_token"]
        return token

    def send_vuln_message(self, scan_item):
        title = scan_item['vuln_name']
        detail = scan_item['scan_detail']
        website = scan_item['website']
        score = scan_item['vuln_score']
        try:
            if PLATFORM == "vx":
                token = str(self.get_vx_token())
                vx_url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"
                data = {}
                data["touser"] = f"{TOUSER}"
                data["toparty"] = f"{TOPARTY}"
                data["totag"] = ""
                data["msgtype"] = "text"
                data["agentid"] = "1000002"
                data["text"] = {}
                data["text"]["content"] = f"Title：{title}\n{score}\nUrl：{website}\nDetail：{detail}"
                data["safe"] = "0"
                data["enable_id_trans"] = "0"
                data["enable_duplicate_check"] = "0"
                data = json.dumps(data)
                logger.log('INFOR',data)
                requests.post(url=vx_url, data=data, verify=False, timeout=10)
            elif PLATFORM == "tg":
                telegram_url = f"https://api.telegram.org/bot{TGTOKEN}/sendMessage"
                data = {}
                data["chat_id"] = f"{CHATID}"
                data["text"] = f"Title：{title}\n{score}\nUrl：{website}\nDetail：{detail}"
                logger.log('INFOR', data)
                requests.post(url=telegram_url, data=data, verify=False, timeout=10)
        except Exception as error:
            logger.log('DEBUG',f'{error}')

    def send_message(self, message):
        try:
            if PLATFORM == "vx":
                token = str(self.get_vx_token())
                vx_url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"
                data = {}
                data["touser"] = f"{TOUSER}"
                data["toparty"] = f"{TOPARTY}"
                data["totag"] = ""
                data["msgtype"] = "text"
                data["agentid"] = "1000002"
                data["text"] = {}
                data["text"]["content"] = f"{message}"
                data["safe"] = "0"
                data["enable_id_trans"] = "0"
                data["enable_duplicate_check"] = "0"
                data = json.dumps(data)
                logger.log('INFOR',data)
                requests.post(url=vx_url, data=data, verify=False, timeout=10)
            elif PLATFORM == "tg":
                telegram_url = f"https://api.telegram.org/bot{TGTOKEN}/sendMessage"
                data = {}
                data["chat_id"] = f"{CHATID}"
                data["text"] = f"{message}"
                logger.log('INFOR', data)
                requests.post(url=telegram_url, data=data, verify=False, timeout=10)
        except Exception as error:
            logger.log('DEBUG',f'{error}')

    def generate_report_from_nuclei(self, vuln_info):
        host_name = self.es_helper.remove_http_or_https(vuln_info['website']).split(":")[0].split("/")[0]
        report_name = f"{vuln_info['scan_detail']['template-id']}_{host_name}.md"
        vuln_image_name = f"{vuln_info['scan_detail']['template-id']}_{host_name}.png"
        report_file_name = f"{self.report_resultDir}/{report_name}"
        logger.log('INFOR', "Generate report from nuclei.")
        logger.log('INFOR', f"Website: {report_name}")
        if os.path.exists(report_file_name):
            pass
        else:
            with open(report_file_name,'a+') as f:
                f.write("## Title\n")
                f.write(f"{vuln_info['scan_detail']['info']['name']} - {vuln_info['scan_detail']['host']}\n\n")

                f.write("## Summary\n")
                if "description" in vuln_info['scan_detail']['info']:
                    print(1)
                    f.write(f"{vuln_info['scan_detail']['info']['description']}\n")
                f.write("\n")

                f.write("## Steps To Reproduce\n")
                f.write(f"1. {vuln_info['scan_detail']['matched-at']}\n")
                f.write(f"2. See the data.\n\n")

                f.write("## Image\n")
                f.write(f"![]({vuln_image_name})\n\n")

                if "reference" in vuln_info['scan_detail']['info']:
                    f.write("## Reference\n")
                    if vuln_info['scan_detail']['info']['reference'] != None:
                        for each in vuln_info['scan_detail']['info']['reference']:
                            f.write(f"{each}\n")
                    f.write("\n")

                f.write("## Impact\n")

    def generate_report_from_xray(self, vuln_info):
        host_name = self.es_helper.remove_http_or_https(vuln_info['website']).split(":")[0].split("/")[0]
        vuln_name = vuln_info['vuln_name'].replace("/","_")
        report_name = f"{vuln_name}_{host_name}.md"
        vuln_image_name = f"{vuln_name}_{host_name}.png"
        report_file_name = f"{self.report_resultDir}/{report_name}"
        logger.log('INFOR', "Generate report from xray.")
        logger.log('INFOR', f"Website: {report_name}")
        if os.path.exists(report_file_name):
            pass
        else:
            with open(report_file_name, 'a+') as f:
                f.write("## Title\n")
                f.write(f"{vuln_name} - [{host_name}]\n\n")

                f.write("## Summary\n")
                f.write("\n")

                f.write("## Steps To Reproduce\n")
                f.write(f"1. {vuln_info['scan_detail']['addr']}\n")
                f.write(f"2. See the data.\n")

                f.write("## Image\n")
                f.write(f"![]({vuln_image_name})\n\n")

                f.write("## Reference\n")
                f.write("\n")

                f.write("## Impact\n")

    def generate_report_from_temp(self, vuln_info):
        vuln_name = ""
        vuln_replace = ""
        host_name = self.es_helper.remove_http_or_https(vuln_info['website']).split(":")[0].split("/")[0]
        if vuln_info['scan_name'] == "nuclei_scan":
            vuln_name = vuln_info['scan_detail']['template-id']
            vuln_replace = vuln_info['scan_detail']['matched-at']
        elif vuln_info['scan_name'] == "xray_scan":
            vuln_name = vuln_info['vuln_name'].replace("/", "_")
            vuln_replace = vuln_info['scan_detail']['addr']
        elif vuln_info['scan_name'] == "fuzz_scan":
            vuln_name = vuln_info['vuln_name']
            vuln_replace = vuln_info['scan_detail']
        report_name = f"{vuln_name}_{host_name}.md"
        report_file_name = f"{self.report_resultDir}/{report_name}"
        temp_file_name = f"{self.report_tempDir}/{vuln_name}.md"
        logger.log('INFOR', "Generate report from template.")
        logger.log('INFOR', f"Website: {report_name}")
        if os.path.exists(temp_file_name):
            if os.path.exists(report_file_name):
                pass
            else:
                with open(temp_file_name, 'r') as f1:
                    with open(report_file_name, 'a+') as f2:
                        if vuln_info['scan_name'] == "fuzz_scan":
                            print(vuln_replace)
                            f2.write(f1.read().replace("[request]",str(vuln_replace)))
                        else:
                            f2.write(f1.read().replace("[website]",vuln_replace))

    def generate_report(self, vuln_info):
        if vuln_info['scan_name'] == "nuclei_scan":
            vuln_name = vuln_info['scan_detail']['template-id']
            temp_file_name = f"{self.report_tempDir}/{vuln_name}.md"
            if os.path.exists(temp_file_name):
                self.generate_report_from_temp(vuln_info)
            else:
                self.generate_report_from_nuclei(vuln_info)
        elif vuln_info['scan_name'] == "xray_scan":
            vuln_name = vuln_info['vuln_name'].replace("/", "_")
            temp_file_name = f"{self.report_tempDir}/{vuln_name}.md"
            if os.path.exists(temp_file_name):
                self.generate_report_from_temp(vuln_info)
            else:
                self.generate_report_from_xray(vuln_info)
        elif vuln_info['scan_name'] == "fuzz_scan":
            vuln_name = vuln_info['vuln_name']
            temp_file_name = f"{self.report_tempDir}/{vuln_name}.md"
            if os.path.exists(temp_file_name):
                self.generate_report_from_temp(vuln_info)

    def start_screenshot_driver(self, vuln_info):
        vuln_name = ""
        vuln_url = ""
        host_name = self.es_helper.remove_http_or_https(vuln_info['website']).split(":")[0].split("/")[0]
        if vuln_info['scan_name'] == "nuclei_scan":
            vuln_name = vuln_info['scan_detail']['template-id']
            vuln_url = vuln_info['scan_detail']['matched-at']
        elif vuln_info['scan_name'] == "xray_scan":
            vuln_name = vuln_info['vuln_name'].replace("/", "_")
            vuln_url = vuln_info['scan_detail']['addr']
        vuln_image_name = f"{vuln_name}_{host_name}.png"
        logger.log('INFOR', "Start screenshot.")
        logger.log('INFOR', f"screenshot: {vuln_url}")
        try:
            self.screenshot_driver(vuln_url, vuln_image_name)
        except Exception as error:
            logger.log('DEBUG',f'{error}')

    def screenshot_driver(self, vuln_url, vuln_image_name):
        options = webdriver.ChromeOptions()

        # 浏览器不提供可视化页面. linux下如果系统不支持可视化不加这条会启动失败
        options.add_argument('--headless')
        # 谷歌文档提到需要加上这个属性来规避bug
        options.add_argument('--disable-gpu')
        # 取消沙盒模式
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        # 指定浏览器分辨率
        options.add_argument('window-size=1920x1080')
        self.driver = webdriver.Chrome(options=options)

        # 网页地址
        self.driver.get(vuln_url)
        # 等待2秒再截图，如果网页渲染的慢截图的内容会有问题
        time.sleep(2)

        # 截图
        self.driver.get_screenshot_as_file(f'{PARENT_DIR}/vulscan/results/image/{vuln_image_name}')

        # 退出
        self.driver.close()

if __name__ == "__main__":
    #print(CUR_DIR)
    #print(PARENT_DIR)
    '''
    vulnma = VulnManager()
    filename = f"{vulnma.report_tempDir}/springboot-env.md"
    with open(filename,'r') as f:
        print(f.read().replace("[website]","https://www.baidu.com"))
    
    vulnma = VulnManager()
    vulnma.screenshot_driver(vuln_url="http://www.baidu.com", vuln_image_name="baidu.png")
    '''
    pass