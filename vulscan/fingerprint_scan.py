# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : fingetprint_scan.py
# Time       ：2022/03/10
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

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.ESHelper import ESHelper
from vconfig.config import *
from vconfig.log import logger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

class FingerprintScan(object):
    def __init__(self):
        self.fingerprint_path = CUR_DIR + "/tools/whatweb/whatweb"
        self.fingerprint_cmd = f"{self.fingerprint_path} -a 3 --follow-redirect never -U 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36'"
        self.fingerprint_resultDir = CUR_DIR + "/results/fingerprint"
        self.urls_resultDir = CUR_DIR + "/results/urls"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.scanner_name = "fingerprint_scan"
        self.program_index = "program-assets-1"
        self.domain_index = "domain-assets-1"

    def searchallprogramdomain(self):
        logger.log('INFO', "[+]Start search all program domains.")
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        pdomain_list = []
        if res:
            for each in res:
                pdomain_list.append(each['_source']['domain'].lower())
        return pdomain_list

    def read_new_url_list_by_pdomain(self, begin_time=None, pdomain=None):
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
            "_source": ["url", "subdomain"]
        }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_new_url_list_by_time(self, gt=None, lt=None):
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
            "_source": ["url"]
        }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    def read_url_list_by_time(self, gt=None, lt=None):
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
                "_source": ["url", "subdomain"]
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

    def deal_url_list(self, url_list=None):
        '''根据筛选条件读取url的list'''
        return_url_list = []
        for each in url_list:
            each = each["_source"]["url"]
            return_url_list.append(each)
        return return_url_list

    def startFingerprintFileScan(self, program):
        '''
        /root/vuln_scan/vulscan/tools/whatweb/whatweb -a 3 -v --follow-redirect=never -U='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -i test.txt --log-json 123.json
        /root/WhatWeb-0.5.5/whatweb -a 3 -v --follow-redirect=never -U 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -i test.txt --log-json 123.json
        '''
        logger.log('INFOR', f"[+]Start scan program {program}\'s fingerprint")
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        fingerprint_output_file = f"{self.fingerprint_resultDir}/{program}_fingerprint_output.json"
        logger.log('INFOR', urls_output_txt)
        if os.path.exists(fingerprint_output_file):
            os.remove(fingerprint_output_file)
        if os.path.exists(urls_output_txt):
            fingerprint_lines = f"{self.fingerprint_cmd} --log-json {fingerprint_output_file} -i {urls_output_txt}"
            logger.log('INFOR', fingerprint_lines)
            # 开启fingerprint
            os.system(fingerprint_lines)

    def write_url_list(self, program, asset_list):
        urls_output_txt = f"{self.urls_resultDir}/{program}_urls_output.txt"
        if os.path.exists(urls_output_txt):
            os.remove(urls_output_txt)
        with open(urls_output_txt, 'a') as f:
            for asset_info in asset_list:
                asset_info_url = asset_info['_source']['url']
                # asset_info_url = asset_info['url']
                if asset_info_url != None:
                    f.write(asset_info_url + "\n")
        logger.log('INFOR', f'[+]添加-[{program}]-扫描文件成功')

    def write_fingerprint_file_list(self, program):
        fingerprint_file_output_file = f"{self.fingerprint_resultDir}/{program}_fingerprint_output.json"
        if os.path.exists(fingerprint_file_output_file):
            with open(fingerprint_file_output_file, 'r') as f:
                '''
                ADD：plugin
                '''
                f = json.load(f)
                for each in f:
                    plugin = each['plugins']
                    title = "None"
                    if "Title" in plugin:
                        title = plugin['Title']['string'][0]
                        plugin.pop('Title')
                    url = each['target']
                    plugin = str(plugin)
                    self.update_finger(url=url,plugin=plugin,title=title)
                    logger.log('INFOR', f'[+]update finger {url}:{plugin}')

    def update_finger(self, url=None, plugin=None, title=None):
        if url != None and plugin != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "match_phrase": {
                                    "url": str(url)
                                }
                            }
                        ]
                    }
                },
                "script": {
                    "source": "ctx._source.fingerprint=params.fingerprint;ctx._source.title=params.title",
                    "params":{
                        "fingerprint": str(plugin),
                        "title": str(title)
                    },
                    "lang": "painless"
                }
            }
            self.es_helper.update_by_query(index=self.domain_index,dsl=dsl)

    def finger_scan_all(self):
        # 1:read all pdomain
        all_pdomain_list = self.searchallprogramdomain()

        pdomain_len = len(all_pdomain_list)

        # 2:write all pdomain file
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[Fingerprint] 开始写入父域第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            asset_list = self.read_url_list(pdomain=pdomain)
            if asset_list != None:
                pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
                self.write_url_list(program=pdomain_name,asset_list=asset_list)
            i = i + 1

        # 3:start scan fingerprint
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[Fingerprint] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.startFingerprintFileScan(program=pdomain_name)
            i = i + 1

        # 4:write fingerprint
        i= 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[Fingerprint] 开始写入指纹第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            try:
                self.write_fingerprint_file_list(program=pdomain_name)
            except Exception as error:
                logger.log('DEBUG', f'{error}')
            i = i + 1

    def finger_scan_by_pdomain(self, pdomain=None):
        logger.log('INFO',"[Fingerprint] 开始写入 - " + pdomain)
        asset_list = self.read_url_list(pdomain=pdomain)
        if asset_list != None:
            # write pdomain file
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
            self.write_url_list(program=pdomain_name,asset_list=asset_list)

            # start scan fingerprint
            logger.log('INFO',"[Fingerprint] 开始扫描 - " + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.startFingerprintFileScan(program=pdomain_name)

            # write fingerprint
            logger.log('INFO',"[Fingerprint] 开始写入指纹 - " + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.write_fingerprint_file_list(program=pdomain_name)

if __name__ == "__main__":
    #fingerprint_scan = FingerprintScan()
    #fingerprint_scan.finger_scan_all()
    pass
    #fingerprint_scan.write_fingerprint_file_list(program="ponds.com")
    #fingerprint_scan.startFingerprintFileScan(program="program1")
    #fingerprint_scan.write_fingerprint_file_list(program="program1")
    #fingerprint_scan.update_finger(url="http://odr.thomsonreuters.com",plugin="{'Bootstrap': {'version': ['3.1.1', '3.2.0']}, 'Ruby-on-Rails': {}, 'X-Powered-By': {'string': ['Phusion Passenger 4.0.57']}}")
