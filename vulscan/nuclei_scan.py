# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : nuclei_scan.py
# Time       ：2021/12/09
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""

import os
import sys
import yaml
import json
import requests
import datetime
from lxml import etree
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.ESHelper import ESHelper
from vcommon.vuln_manage import VulnManager
from vconfig.config import *
from vconfig.log import logger

# 防止SSL报错
requests.packages.urllib3.disable_warnings()

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

class NucleiScan(object):
    def __init__(self):
        self.nuclei_mode = "program_to_all"
        self.nuclei_path = CUR_DIR + "/tools/nuclei"
        self.nuclei_template_path = "/root/nuclei-templates/"
        self.nuclei_config = CUR_DIR + "/tools/nuclei_config.yaml"
        self.nuclei_new_temp_config = CUR_DIR + "/tools/nuclei_new_temp_config.yaml"
        self.nuclei_cmd = f"{self.nuclei_path} -config {self.nuclei_config}"
        self.nuclei_new_temp_cmd = f"{self.nuclei_path} -config {self.nuclei_new_temp_config}"
        self.nuclei_resultDir = CUR_DIR + "/results/nuclei"
        self.urls_resultDir = CUR_DIR + "/results/urls"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.scanner_name = "nuclei_scan"
        self.vuln_index = "vuln-assets-1"
        self.spider_index = "spider-assets-1"
        self.domain_index = "domain-assets-1"
        self.program_index = "program-assets-1"
        self.vuln_manager = VulnManager()

    def read_new_url_list(self, begin_time=None, pdomain=None):
        '''根据筛选条件读取url的list'''
        if begin_time==None:
            begin_time = "2010-01-01T12:10:30Z"
        dsl = {
                "query": {
                    "bool": {
                        "must":
                            {"match_phrase": {"pdomain": pdomain}},
                        "filter": [
                            {
                                "range": {
                                    "update_time": {
                                        "gte": begin_time,
                                        "lt": "2028-01-01T12:10:30Z"
                                    }
                                }
                            }
                        ]
                    }
                },
            "_source": ["url", "subdomain"]
            }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_new_url_list_by_time(self, gt=None, lt=None, offer_bounty=None):
        '''根据筛选条件读取url的list'''
        if gt == None:
            gt = "2010-01-01T12:10:30Z"
        if lt == None:
            lt = "2028-01-01T12:10:30Z"
        dsl = {
            "query": {
                "bool": {
                    "must":
                        {"match": {"offer_bounty": offer_bounty}},
                    "filter": [
                        {
                            "range": {
                                "update_time": {
                                    "gte": gt,
                                    "lt": lt
                                }
                            }
                        }
                    ]
                }
            },
            "_source": ["url"]
        }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_url_list_by_time(self, gt=None, lt=None, offer_bounty=None):
        '''根据筛选条件读取url的list'''
        if gt==None:
            gt = "2010-01-01T12:10:30Z"
        if lt==None:
            lt = "2028-01-01T12:10:30Z"
        dsl = {
                "query": {
                    "bool": {
                        "must":
                            {"match": {"offer_bounty": offer_bounty}},
                        "filter": [
                            {
                                "range": {
                                    "launched_at": {
                                        "gte": gt,
                                        "lt": lt
                                    }
                                }
                            }
                        ]
                    }
                },
            "_source": ["url"]
            }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_url_list_by_time1(self, gt=None, lt=None, offer_bounty=None, platform=None):
        '''根据筛选条件读取url的list'''
        if gt==None:
            gt = "2010-01-01T12:10:30Z"
        if lt==None:
            lt = "2028-01-01T12:10:30Z"
        dsl = {
                "query": {
                    "bool": {
                        "must":
                            [
                                {"match_phrase": {"offer_bounty": offer_bounty}},
                                {"match_phrase": {"platform": platform}},
                                {"match_phrase": {"alive": "1"}}
                            ],
                        "filter": [
                            {
                                "range": {
                                    "launched_at": {
                                        "gte": gt,
                                        "lt": lt
                                    }
                                }
                            }
                        ]
                    }
                },
            "_source": ["url"]
            }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_spider_list_by_program(self, program):
        '''根据筛选条件读取url的list'''
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"program": str(program)}}
                    ]
                }
            },
            "_source": ["url"]
        }
        url_list = self.es_helper.query_domains_by_dsl(self.spider_index, dsl)
        return url_list

    def read_url_list(self, program=None, pdomain=None, subdomain=None):
        '''根据筛选条件读取url的list'''
        if subdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"subdomain": str(subdomain)}}
                        ]
                    }
                },
                "_source":  ["url", "subdomain"]
            }
        elif pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"pdomain": str(pdomain)}}
                        ]
                    }
                },
                "_source": ["url", "subdomain"]
            }
        elif program != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"program": str(program)}}
                        ]
                    }
                },
                "_source": ["url", "subdomain"]
            }
        else:
            dsl = {
                "query": {"match_all": {}},
                "_source": ["url", "subdomain"]
            }
        url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return url_list

    def read_url_list_status_200(self, program=None, pdomain=None, subdomain=None):
        '''根据筛选条件读取url的list'''
        if subdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"subdomain": str(subdomain)}},
                            {"match_phrase": {"alive": "1"}}
                        ],
                        "filter": {
                            "terms": {
                                "status": [
                                    "200"
                                ]
                            }
                        }
                    }
                },
                "_source":  ["url", "subdomain"]
            }
        elif pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"pdomain": str(pdomain)}},
                            {"match_phrase": {"alive": "1"}}
                        ],
                        "filter": {
                            "terms": {
                                "status": [
                                    "200"
                                ]
                            }
                        }
                    }
                },
                "_source": ["url", "subdomain"]
            }
        elif program != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"program": str(program)}},
                            {"match_phrase": {"alive": "1"}}
                        ],
                        "filter": {
                            "terms": {
                                "status": [
                                    "200"
                                ]
                            }
                        }
                    }
                },
                "_source": ["url", "subdomain"]
            }
        else:
            dsl = {
                "query": {
                    "bool": {
                        "must": {
                            "match_phrase": {
                                "alive": "1"
                            }
                        },
                        "filter": {
                            "terms": {
                                "status": [
                                    "200"
                                ]
                            }
                        }
                    }
                },
                "_source": ["url", "subdomain"]
            }
        url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return url_list

    def deal_url_list(self, url_list=None):
        '''根据筛选条件读取url的list'''
        return_url_list = []
        for each in url_list:
            each = each["_source"]["url"]
            return_url_list.append(each)
        return return_url_list

    def startNucleiScan(self,asset_info):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -stats -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        :return:
        '''
        logger.log('INFOR',"Nuclei urls scan starting....")
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        # url = "http://www.52helong.cn/"
        url = asset_info['url']
        scheme = urlparse(url).scheme
        netloc = urlparse(url).netloc
        if ":" in netloc:
            netloc = urlparse(url).netloc.split(":")[0] + "_" + urlparse(url).netloc.split(":")[1]
        path = urlparse(url).path
        if path == "" or path == "/":
            nuclei_output_file = f"{self.nuclei_resultDir}/{scheme}_{netloc}_nuclei_output.json"
        else:
            path = path.replace(path[0], '')
            nuclei_output_file = f"{self.nuclei_resultDir}/{scheme}_{netloc}_{path}_nuclei_output.json"
        logger.log('INFOR',nuclei_output_file)
        if os.path.exists(nuclei_output_file):
            os.remove(nuclei_output_file)
        cmd_lines = f"{self.nuclei_cmd} -json -o {nuclei_output_file} -u {url}"
        logger.log('INFOR',cmd_lines)
        # 开启dirsearch
        os.system(cmd_lines)

    def startNucleiNewTemlScan(self,asset_info):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -stats -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        :return:
        '''
        logger.log('INFOR',"Nuclei urls new temp scan starting....")
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        # url = "http://www.52helong.cn/"
        url = asset_info['url']
        scheme = urlparse(url).scheme
        netloc = urlparse(url).netloc
        if ":" in netloc:
            netloc = urlparse(url).netloc.split(":")[0] + "_" + urlparse(url).netloc.split(":")[1]
        path = urlparse(url).path
        if path == "" or path == "/":
            nuclei_output_file = f"{self.nuclei_resultDir}/{scheme}_{netloc}_nuclei_output.json"
        else:
            path = path.replace(path[0], '')
            nuclei_output_file = f"{self.nuclei_resultDir}/{scheme}_{netloc}_{path}_nuclei_output.json"
        logger.log('INFOR',nuclei_output_file)
        if os.path.exists(nuclei_output_file):
            os.remove(nuclei_output_file)
        cmd_lines = f"{self.nuclei_new_temp_cmd} -json -o {nuclei_output_file} -u {url}"
        logger.log('INFOR',cmd_lines)
        # 开启dirsearch
        os.system(cmd_lines)

    def startNucleiNewTemlFileScan(self, filename):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -stats -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        :return:
        '''
        logger.log('INFOR',"Nuclei urls new temp file scan starting....")
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        nuclei_output_file = f"{self.nuclei_resultDir}/{filename}_nuclei_output.json"
        urls_output_txt = f"{self.urls_resultDir}/{filename}_urls_output.txt"
        if os.path.exists(nuclei_output_file):
            os.remove(nuclei_output_file)
        if os.path.exists(urls_output_txt):
            cmd_lines = f"{self.nuclei_new_temp_cmd} -json -o {nuclei_output_file} -l {urls_output_txt}"
            logger.log('INFOR',cmd_lines)
            # 开启dirsearch
            os.system(cmd_lines)

    def startNucleiTempFileScan(self, program ,templateName):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -status -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        Temp: -t vulnerabilities/my/my-cache.yaml
        '''
        logger.log('INFOR',"Nuclei template scan starting....")
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        assert os.path.exists(urls_output_txt), f"url list file:{urls_output_txt} not exists!"
        nuclei_template_output_file = f"{self.nuclei_resultDir}/{program}_nuclei_output.json"
        logger.log('INFOR',urls_output_txt)
        if os.path.exists(nuclei_template_output_file):
            os.remove(nuclei_template_output_file)
        if os.path.exists(urls_output_txt):
            cmd_lines = f"{self.nuclei_cmd} -t {templateName} -json -o {nuclei_template_output_file} -l {urls_output_txt}"
            logger.log('INFOR',cmd_lines)
            # 开启dirsearch
            os.system(cmd_lines)

    def startNucleiFileScan(self, program):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -status -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        Temp: -t vulnerabilities/my/my-cache.yaml
        '''
        logger.log('INFOR',"Nuclei template scan starting....")
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        assert os.path.exists(urls_output_txt), f"url list file:{urls_output_txt} not exists!"
        nuclei_template_output_file = f"{self.nuclei_resultDir}/{program}_nuclei_output.json"
        logger.log('INFOR',urls_output_txt)
        if os.path.exists(nuclei_template_output_file):
            os.remove(nuclei_template_output_file)
        if os.path.exists(urls_output_txt):
            cmd_lines = f"{self.nuclei_cmd} -json -o {nuclei_template_output_file} -l {urls_output_txt}"
            logger.log('INFOR',cmd_lines)
            # 开启dirsearch
            os.system(cmd_lines)

    def startNucleiListScan(self, program):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -status -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -json -o 1.json
        Temp: -t vulnerabilities/my/my-cache.yaml
        '''
        logger.log('INFOR',"Nuclei template scan starting....")
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        assert os.path.exists(self.nuclei_path), f"nuclei file:{self.nuclei_path} not exists!"
        assert os.path.exists(urls_output_txt), f"url list file:{urls_output_txt} not exists!"
        nuclei_list_output_file = f"{self.nuclei_resultDir}/{program}_nuclei_output.json"
        logger.log('INFOR',nuclei_list_output_file)
        cmd_lines = f"{self.nuclei_cmd} -json -o {nuclei_list_output_file} -l {urls_output_txt}"
        logger.log('INFOR',cmd_lines)
        # 开启dirsearch
        os.system(cmd_lines)

    '''Dir数据去重'''
    def remove_duplicate_data(self, list_dict_data):
        copy_list = []
        for list_data in list_dict_data:
            num = 0
            for cop in copy_list:
                if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop[
                    'data']:
                    num += 1
            if num == 0:
                copy_list.append(list_data)
        return copy_list

    def write_url_list(self, program, asset_list):
        #nuclei_output_json = "/root/vuln_scan/vulscan/results/nuclei/1.json"
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        if os.path.exists(urls_output_txt):
            if "temp" in urls_output_txt:
                pass
            else:
                os.remove(urls_output_txt)
        with open(urls_output_txt, 'a') as f:
            for asset_info in asset_list:
                asset_info_url = asset_info['_source']['url']
                #asset_info_url = asset_info['url']
                if asset_info_url != None:
                    f.write(asset_info_url + "\n")
        logger.log('INFOR',f'[+]添加-[{program}]-扫描文件成功')

    def write_spider_list(self, program, asset_list):
        #nuclei_output_json = "/root/vuln_scan/vulscan/results/nuclei/1.json"
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        if os.path.exists(urls_output_txt):
            os.remove(urls_output_txt)
        new_asset_list = []
        for each in asset_list:
            new_asset_list.append(each['_source']['url'])
        early_len = len(new_asset_list)
        new_asset_list = list(set(new_asset_list))
        after_len = len(new_asset_list)
        logger.log('INFOR',"去重前长度"+str(early_len)+"-去重后长度"+str(after_len))
        with open(urls_output_txt, 'a') as f:
            for asset_info_url in new_asset_list:
                if "?" not in asset_info_url and  "#" not in asset_info_url and "*" not in asset_info_url:
                    #asset_info_url = asset_info['url']
                    f.write(asset_info_url+"\n")
        logger.log('INFOR',f'[+]添加-[{program}]-扫描文件成功')

    def write_nuclei_list(self, asset_info):
        url = asset_info['url']
        scheme = urlparse(url).scheme
        netloc = urlparse(url).netloc
        if ":" in netloc:
            netloc = urlparse(url).netloc.split(":")[0] + "_" + urlparse(url).netloc.split(":")[1]
        path = urlparse(url).path
        #nuclei_output_json = f"{self.nuclei_resultDir}/bc_no_bounty_02_nuclei_output.json"
        if path == "" or path == "/":
            nuclei_output_json = f"{self.nuclei_resultDir}/{scheme}_{netloc}_nuclei_output.json"
        else:
            path = path.replace(path[0],'')
            nuclei_output_json = f"{self.nuclei_resultDir}/{scheme}_{netloc}_{path}_nuclei_output.json"
        if os.path.exists(nuclei_output_json):
            with open(nuclei_output_json, 'r') as f:
                vuln_info = {}
                vuln_info['launched_at'] = datetime.datetime.now()
                vuln_info['scan_name'] = "nuclei_scan"
                '''
                ADD：URL、Method、Headers、Data、Source
                '''
                for each in f:
                    each = json.loads(each)
                    vuln_info['website'] = each['host']
                    vuln_info['vuln_type'] = each['info']['tags']
                    vuln_info['vuln_name'] = each['info']['name']
                    vuln_info['scan_detail'] = each
                    self.vuln_manager.add_nuclei_vuln_score(vuln_info)
                    self.vuln_manager.generate_report(vuln_info)
                    self.vuln_manager.start_screenshot_driver(vuln_info)
                    logger.log('INFOR',vuln_info)
                    self.es_helper.insert_one_doc(self.vuln_index, vuln_info)
                logger.log('INFOR',f'[+]nuclei[{url}]扫描完毕')

    def write_nuclei_template_list(self, program):
        #nuclei_output_json = "/root/vuln_scan/vulscan/results/nuclei/1.json"
        nuclei_template_output_file = f"{self.nuclei_resultDir}/{program}_nuclei_output.json"
        if os.path.exists(nuclei_template_output_file):
            with open(nuclei_template_output_file, 'r') as f:
                vuln_info = {}
                vuln_info['launched_at'] = datetime.datetime.now()
                vuln_info['scan_name'] = "nuclei_scan"
                '''
                ADD：URL、Method、Headers、Data、Source
                '''
                for each in f:
                    each = json.loads(each)
                    vuln_info['website'] = each['host']
                    vuln_info['vuln_type'] = each['info']['tags']
                    vuln_info['vuln_name'] = each['info']['name']
                    vuln_info['scan_detail'] = each
                    self.vuln_manager.add_nuclei_vuln_score(vuln_info)
                    self.vuln_manager.generate_report(vuln_info)
                    self.vuln_manager.start_screenshot_driver(vuln_info)
                    logger.log('INFOR',vuln_info)
                    self.es_helper.insert_one_doc(self.vuln_index, vuln_info)
                logger.log('INFOR',f'[+]nuclei[{program}]扫描完毕')

    def get_html(self, number):
        url = f"https://github.com/projectdiscovery/nuclei-templates/issues/{number}"
        try:
            r = requests.get(url, verify=False, timeout=10)
            if r.status_code == 404:
                return None
            elif r.status_code == 200:
                data = r.text
                return data
        except Exception as error:
            logger.log('DEBUG', f'{error}')

    def lxml_parser(self, html_data):
        # html_path = "C:/Users/xx/Desktop/lxml/1.txt"
        html = etree.HTML(html_data)
        result = html.xpath(
            "//div[@class='highlight highlight-source-yaml notranslate position-relative overflow-auto'][1]/@data-snippet-clipboard-copy-content")
        return result[0]

    def write_yaml_file(self, number):
        number = number
        html_data = self.get_html(number=number)
        filename = ""
        templatename = ""
        if html_data != None:
            if "highlight highlight-source-yaml notranslate position-relative overflow-auto" in html_data:
                result = self.lxml_parser(html_data=html_data)
                data = yaml.load(result, Loader=yaml.FullLoader)
                if "id" in data:
                    id = data['id']
                    severity = data['info']['severity']
                    if severity in ['critical', 'high', 'medium']:
                        if "CVE-" in id:
                            year = id.split("-")[1]
                            templatename= f"cves/{year}/{id}.yaml"
                            filename = f"{self.nuclei_template_path}{templatename}"
                        else:
                            templatename = f"vulnerabilities/my/{id}.yaml"
                            filename = f"{self.nuclei_template_path}{templatename}"
                    if filename != "":
                        if os.path.exists(filename):
                            templatename = ""
                        else:
                            with open(filename, "a+") as f:
                                f.write(result)
            elif "js-issue-title markdown-title" in html_data:
                html = etree.HTML(html_data)
                result = html.xpath("//span[@class='js-issue-title markdown-title'][1]/text()")
                if "Create" in result[0] or "Add" in result[0]:
                    templatename_yaml =  result[0].split(" ")[1]
                    pull_url = f"https://github.com/projectdiscovery/nuclei-templates/pull/{number}/files"
                    try:
                        rr = requests.get(url=pull_url, verify=False, timeout=10)
                        if rr.status_code == 200:
                            data = rr.text
                            html1 = etree.HTML(data)
                            filename = ""
                            # result2 = html1.xpath("//span[@data-code-marker='+']//text()")
                            result2 = html1.xpath("//span[@data-code-marker='+']")
                            data1 = ""
                            for each in result2:
                                result3 = each.xpath(".//text()")
                                for each1 in result3:
                                    data1 = data1 + each1
                                data1 = data1 + "\n"
                            print(data1)
                            if "severity: critical" in data1 or "severity: high" in data1 or "severity: medium" in data1:
                                if "CVE-" in templatename_yaml:
                                    year = templatename_yaml.split("-")[1]
                                    templatename = f"cves/{year}/{templatename_yaml}"
                                    filename = f"{self.nuclei_template_path}{templatename}"
                                else:
                                    templatename = f"vulnerabilities/my/{templatename_yaml}"
                                    filename = f"{self.nuclei_template_path}{templatename}"
                                logger.log('INFO', f'nuclei_template - {templatename} 添加成功')
                                if filename != "":
                                    if os.path.exists(filename):
                                        templatename = ""
                                    else:
                                        with open(filename, "a+") as f:
                                            f.write(data1)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
        return templatename

if __name__ == "__main__":
    #nuclei_scan = NucleiScan()
    #asset_info = [{
    #    'url': 'https://tw.mina.mi.com'
    #}]
    '''
    nuclei_scan = NucleiScan()
    asset_info = {
        'url': 'https://registry.git.maximum.nl'
    }
    nuclei_scan.write_nuclei_list(asset_info)
    #nuclei_scan.write_url_list(program="test",asset_list=asset_info)
    #nuclei_scan.startNucleiTempScan(program="test",templateName="misconfiguration/http-missing-security-headers.yaml")
    #nuclei_scan.write_nuclei_template_list(program="test")
    
    #list1 = nuclei_scan.read_url_list(program="ninja-kiwi")
    for each in asset_info:
        nuclei_scan.startNucleiScan(each['_source'])
    #nuclei_scan.write_nuclei_list(asset_info)
    '''
    pass