# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : domain_port_scan.py
# Time       ：2022/03/28
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""

import os
import sys
import time
import json
import datetime
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.ESHelper import ESHelper
from vconfig.config import *
from vconfig.log import logger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

class SubdomainPortScan(object):
    def __init__(self):
        self.naabu_path = CUR_DIR + "/tools/naabu"
        self.httpx_path = CUR_DIR + "/tools/httpx"
        self.naabu_cmd = f"{self.naabu_path} -exclude-ports 21,22,80,443,445,3389 -top-ports -exclude-cdn -silent"
        self.httpx_cmd = f"{self.httpx_path} -sc -title -fc 301,302,307,400,502,503,521,523,525,530 -fs '400 The plain HTTP request was sent to HTTPS port'"
        self.subdomain_port_resultDir = CUR_DIR + "/results/subdomainport"
        self.subdomain_resultDir = CUR_DIR + "/results/subdomain"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.scanner_name = "subdomain_port_scan"
        self.program_index = "program-assets-1"
        self.domain_index = "domain-assets-1"

    def searchallprogramdomain(self):
        logger.log('INFOR', "[+]Start search all program domains.")
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        pdomain_list = []
        if res:
            for each in res:
                pdomain_list.append(each['_source']['domain'].lower())
        return pdomain_list

    def read_subdomain_list_by_pdomain(self, begin_time=None, pdomain=None):
        '''根据筛选条件读取url的list'''
        if begin_time == None:
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
            "_source": ["subdomain"]
        }
        new_subdomain_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_subdomain_list

    def read_subdomain_list_by_time(self, gt=None, lt=None):
        '''根据筛选条件读取url的list'''
        if gt == None:
            gt = "2010-01-01T12:10:30Z"
        if lt == None:
            lt = "2028-01-01T12:10:30Z"
        dsl = {
            "query": {
                "bool": {
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
            "_source": ["subdomain"]
        }
        new_subdomain_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_subdomain_list

    def read_subdomain_list(self, program=None, pdomain=None, subdomain=None):
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
                "_source": ["subdomain"]
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
                "_source": ["subdomain"]
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
                "_source": ["subdomain"]
            }
        else:
            dsl = {
                "query": {"match_all": {}},
                "_source": ["subdomain"]
            }
        subdomain_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return subdomain_list

    def read_info_by_pdomain(self, pdomain=None):
        '''根据筛选条件读取url的list'''
        pdomain_info = None
        if pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"domain": str(pdomain)}}
                        ]
                    }
                },
                "_source": ["program", "launched_at", "domain", "max_severity", "platform", "offer_bounty"]
            }
            pdomain_info = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return pdomain_info

    def deal_subdomain_list(self, subdomain_list=None):
        '''根据筛选条件读取url的list'''
        return_subdomain_list = []
        for each in subdomain_list:
            each = each["_source"]["subdomain"]
            return_subdomain_list.append(each)
        return return_subdomain_list

    def startSubdomainPortFileScan(self, program):
        '''
        /root/vuln_scan/vulscan/tools/naabu -l 5.txt -exclude-ports 21,22,80,443,445,3389 -top-ports -exclude-cdn -silent -o 55.txt
        /root/vuln_scan/vulscan/tools/httpx -l 55.txt -sc -title -fc 301,302,400,503,521,523,525,530 -fs "400 The plain HTTP request was sent to HTTPS port"
        '''
        logger.log('INFOR', f"[+]Start scan pdomain {program}\'s subdomain port assets")
        subdomain_output_txt = f"{self.subdomain_resultDir}/{program}_subdomain_output.txt"
        subdomainport_output_file = f"{self.subdomain_port_resultDir}/{program}_subdomainport_output.json"
        logger.log('INFOR', subdomain_output_txt)
        if os.path.exists(subdomainport_output_file):
            os.remove(subdomainport_output_file)
        if os.path.exists(subdomain_output_txt):
            subdomainport_lines = f"{self.naabu_cmd} -l {subdomain_output_txt} | {self.httpx_cmd} -json -o {subdomainport_output_file}"
            logger.log('INFOR', subdomainport_lines)
            # 开启fingerprint
            os.system(subdomainport_lines)

    def remove_duplicate_subdomain_list(self, asset_list):
        return_list = []
        for asset_info in asset_list:
            asset_subdomain = asset_info['_source']['subdomain'].lower()
            if asset_subdomain != None:
                return_list.append(asset_subdomain)
        return_list = list(set(return_list))
        return return_list

    def write_subdomain_list(self, program, asset_list):
        subdomain_output_txt = f"{self.subdomain_resultDir}/{program}_subdomain_output.txt"
        if os.path.exists(subdomain_output_txt):
            os.remove(subdomain_output_txt)
        asset_list = self.remove_duplicate_subdomain_list(asset_list=asset_list)
        with open(subdomain_output_txt, 'a') as f:
            for asset_info in asset_list:
                f.write(asset_info + "\n")
        logger.log('INFOR', f'[+]添加-[{program}]-扫描文件成功')

    def write_subdomainport_file_list(self, psource):
        psource = psource["_source"]
        pdomain = self.es_helper.remove_http_or_https(psource["domain"]).split("/")[0].replace("*.", "").replace("*", "")
        # subdomainport_output_file = f"{self.subdomain_port_resultDir}/1.json"
        subdomainport_output_file = f"{self.subdomain_port_resultDir}/{pdomain}_subdomainport_output.json"
        subdomain_info = {}
        subdomain_info['platform'] = psource["platform"]
        subdomain_info['program'] = psource['program']
        subdomain_info['pdomain'] = psource['domain']
        subdomain_info['offer_bounty'] = psource['offer_bounty']
        subdomain_info['launched_at'] = psource['launched_at']
        subdomain_info['update_time'] = datetime.datetime.now()
        if "max_severity" in psource:
            subdomain_info['max_severity'] = psource['max_severity']
        if os.path.exists(subdomainport_output_file):
            with open(subdomainport_output_file, 'r') as f:
                for info in f:
                    info = json.loads(info.strip())
                    if "title" in info:
                        #print(info['title'])
                        subdomain_info['alive'] = 1
                        subdomain_info['url'] = info['url']
                        subdomain_info['ip'] = info['host']
                        subdomain_info['port'] = info['port']
                        subdomain_info['status'] = info['status-code']
                        subdomain_info['title'] = info['title']
                        if subdomain_info['url'] != None:
                            subdomain_info['subdomain'] = urlparse(info['url']).netloc.split(":")[0]
                            self.es_helper.insert_one_doc(self.domain_index, subdomain_info)
                        logger.log('INFOR', f'[+]URL:[{subdomain_info["url"]}]入库完成')

    def subdomainport_scan_all(self):
        # 1:read all pdomain
        all_pdomain_list = self.searchallprogramdomain()

        pdomain_len = len(all_pdomain_list)
        '''
        # 2:write all subdomain by pdomain
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFOR',"[SubdomainPort] 开始写入父域第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            asset_list = self.read_subdomain_list(pdomain=pdomain)
            if asset_list != None:
                pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
                self.write_subdomain_list(program=pdomain_name,asset_list=asset_list)
            i = i + 1
        '''
        '''
        # 3:start scan subdomain port
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFOR',"[SubdomainPort] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.startSubdomainPortFileScan(program=pdomain_name)
            i = i + 1
        '''
        # 4:write subdomain port
        i= 1
        for pdomain in all_pdomain_list:
            logger.log('INFOR',"[SubdomainPort] 开始写入资产第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            psource = self.read_info_by_pdomain(pdomain=pdomain)
            if psource != None:
                try:
                    psource = psource[0]
                    self.write_subdomainport_file_list(psource=psource)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')
            i = i + 1

    def subdomainport_scan_by_pdomain(self, pdomain=None):
        logger.log('INFOR',"[SubdomainPort] 开始写入 - " + pdomain)
        asset_list = self.read_subdomain_list(pdomain=pdomain)
        if asset_list != None:
            # write subdomain file by pdomain
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
            self.write_subdomain_list(program=pdomain_name,asset_list=asset_list)

            # start scan subdomain
            logger.log('INFOR',"[SubdomainPort] 开始扫描 - " + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.startSubdomainPortFileScan(program=pdomain_name)

            # write subdomain
            logger.log('INFOR',"[SubdomainPort] 开始写入子域资产 - " + pdomain)
            psource = self.read_info_by_pdomain(pdomain=pdomain)
            if psource != None:
                try:
                    psource = psource[0]
                    self.write_subdomainport_file_list(psource=psource)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')

if __name__ == "__main__":
    #subdomainport_scan = SubdomainPortScan()
    #subdomainport_scan.subdomainport_scan_all()
    pass
