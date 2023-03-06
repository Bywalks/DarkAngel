# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : subdomain_dir_scan.py
# Time       ：2022/06/27
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
from vulscan.nuclei_scan import NucleiScan
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

class SubdomainDirScan(object):
    def __init__(self):
        self.dirsearch_path = CUR_DIR + "/dirsearch/dirsearch.py"
        self.directory = CUR_DIR + "/dirsearch/db/dicc.txt"
        self.dirsearch_cmd = f"python3 {self.dirsearch_path} -w {self.directory}"
        self.subdomain_dir_resultDir = CUR_DIR + "/results/dir/dir"
        self.subdomain_url_resultDir = CUR_DIR + "/results/urls"
        self.subdomain_resultDir = CUR_DIR + "/results/dir/subdomain"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.nuclei_scan = NucleiScan()
        self.scanner_name = "subdomain_port_scan"
        self.program_index = "program-assets-1"
        self.domain_index = "domain-assets-1"
        self.dirsearch_index = "dirsearch-assets-1"

    def searchallprogramdomain(self):
        logger.log('INFO', "[+]Start search all program domains.")
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        pdomain_list = []
        if res:
            for each in res:
                pdomain_list.append(each['_source']['domain'].lower())
        return pdomain_list

    def searchallprivatebountydomain(self):
        logger.log('INFO', "[+]Start search all program domains.")
        query = {
            "query": {
                "bool": {"must": [
                    {"match_phrase": {"hackerone_private": "yes"}},
                    {"match_phrase": {"offer_bounty": "yes"}}
                ]
                }
            }
        }
        res = self.es_helper.query_domains_by_dsl(self.program_index,dsl=query)
        pdomain_list = []
        if res:
            for each in res:
                pdomain_list.append(each['_source']['domain'].lower())
        return pdomain_list

    def searchallh1cdomain(self):
        logger.log('INFO', "[+]Start search hack-us-h1c program domains.")
        query = {
            "query": {
                "range": {
                    "update_time": {
                        "gte": "2022-07-05T14:41:10Z",
                        "lt": "2028-01-01T12:10:30Z"
                    }
                }
            }
        }
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
                        "must": [{
                            "match_phrase": {
                                "subdomain": str(subdomain)
                            }
                        }],
                        "should": [{
                                "term": {
                                    "status": "403"
                                }
                            },
                            {
                                "term": {
                                    "status": "404"
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
                "_source": ["subdomain"]
            }
        elif pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [{
                            "match_phrase": {
                                "pdomain": str(pdomain)
                            }
                        }],
                        "should": [{
                                "term": {
                                    "status": "403"
                                }
                            },
                            {
                                "term": {
                                    "status": "404"
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
                "_source": ["subdomain"]
            }
        elif program != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [{
                            "match_phrase": {
                                "program": str(program)
                            }
                        }],
                        "should": [{
                                "term": {
                                    "status": "403"
                                }
                            },
                            {
                                "term": {
                                    "status": "404"
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
                "_source": ["subdomain"]
            }
        else:
            dsl = {
                "query": {
                    "bool": {
                        "should": [{
                                "term": {
                                    "status": "403"
                                }
                            },
                            {
                                "term": {
                                    "status": "404"
                                }
                            }
                        ],
                        "minimum_should_match": 1
                    }
                },
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

    def startSubdomainDirFileScan(self, program):
        '''
        python3 /root/vuln_scan/vulscan/dirsearch/dirsearch.py -f -w /root/vuln_scan/vulscan/dirsearch/db/dicc.txt --random-agent -F -l /root/vuln_scan/403.txt -t 5 --format=simple -o /root/vuln_scan/1.json
        '''
        logger.log('INFOR', f"[+]Start scan subdomain {program}\'s subdomain dir assets")
        subdomain_output_txt = f"{self.subdomain_resultDir}/{program}_subdomain_output.txt"
        subdomaindir_output_file = f"{self.subdomain_dir_resultDir}/{program}_subdomaindir_output.json"
        logger.log('INFOR', subdomain_output_txt)
        if os.path.exists(subdomaindir_output_file):
            os.remove(subdomaindir_output_file)
        if os.path.exists(subdomain_output_txt):
            subdomainport_lines = f"{self.dirsearch_cmd} -l {subdomain_output_txt} --format=json -o {subdomaindir_output_file}"
            logger.log('INFOR', subdomainport_lines)
            # 开启dirsearch
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

    def write_subdomainDir_file_list(self, pdomain_name):
        subdomaindir_output_file = f"{self.subdomain_dir_resultDir}/{pdomain_name}_subdomaindir_output.json"
        subdomainurl_output_file = f"{self.subdomain_url_resultDir}/{pdomain_name}_urls_output.txt"
        # print(subdomainurl_output_file)
        # print(subdomaindir_output_file)
        subdomaindir_info = {}
        subdomaindir_info['launched_at'] = datetime.datetime.now()
        subdomaindir_info['scan_name'] = "dirsearch"
        subdomaindir_info['pdomain'] = pdomain_name
        if os.path.exists(subdomainurl_output_file):
            os.remove(subdomainurl_output_file)
        if os.path.exists(subdomaindir_output_file):
            with open(subdomaindir_output_file, 'r') as f:
                info = json.loads(f.read())
                for each in info['results']:
                    for key, value in each.items():
                        # subdomaindir_info['website'] = key
                        subdomaindir_info['website'] = urlparse(key).netloc.split(":")[0]
                        if len(value) < 30:
                            for val in value:
                                subdomaindir_info['content-length'] = val['content-length']
                                subdomaindir_info['status'] = val['status']
                                subdomaindir_info['url'] = key + val['path'][1:]
                                subdomaindir_info['uri'] = val['path']
                                if val['path'][1:].endswith("/"):
                                    subdomaindir_info['dir_type'] = "directory"
                                    with open(subdomainurl_output_file,"a") as f1:
                                        f1.write(subdomaindir_info['url']+"\n")
                                else:
                                    subdomaindir_info['dir_type'] = "file"
                                # print(subdomaindir_info)
                                logger.log('INFOR', f'[+]{subdomaindir_info}]')
                                self.es_helper.insert_one_doc(self.dirsearch_index, subdomaindir_info)
                                logger.log('INFOR', f'[+]DIR:[{pdomain_name}]入库完成')

    def subdomaindir_scan_all(self):
        # 1:read all pdomain
        all_pdomain_list = self.searchallh1cdomain()

        pdomain_len = len(all_pdomain_list)
        executor = ThreadPoolExecutor(max_workers=5)
        futures = []

        # 2:write all 403,404 subdomain by pdomain
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[SubdomainDir] 开始写入父域第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            asset_list = self.read_subdomain_list(pdomain=pdomain)
            if asset_list != None:
                pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
                self.write_subdomain_list(program=pdomain_name,asset_list=asset_list)
            i = i + 1

        # 3:start scan subdomain dir
        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[SubdomainDir] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            # self.startSubdomainDirFileScan(pdomain_name)
            f1 = executor.submit(self.startSubdomainDirFileScan, pdomain_name)
            futures.append(f1)
            i = i + 1
        wait(futures)

        # 4:write subdomain dir
        i = 1
        for pdomain in all_pdomain_list:
            try:
                #logger.log('INFO',"[SubdomainDir] 开始写入资产第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain)
                pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
                self.write_subdomainDir_file_list(pdomain_name)
            except Exception as error:
                logger.log('DEBUG', f'{error}')
            i = i + 1

        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[Nuclei] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + str(pdomain))
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            f1 = executor.submit(self.nuclei_scan.startNucleiFileScan, pdomain_name)
            futures.append(f1)
            i = i + 1
        # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
        wait(futures)

        i = 1
        for pdomain in all_pdomain_list:
            logger.log('INFO',"[Nuclei] 开始写入第" + str(i) + "/" + str(pdomain) + "-" + str(pdomain))
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.nuclei_scan.write_nuclei_template_list(program=pdomain_name)
            i = i + 1

    def subdomaindir_scan_by_pdomain(self, pdomain=None):
        logger.log('INFO',"[SubdomainPort] 开始写入 - " + pdomain)
        asset_list = self.read_subdomain_list(pdomain=pdomain)
        if asset_list != None:
            # write subdomain file by pdomain
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.","").replace("*","")
            self.write_subdomain_list(program=pdomain_name,asset_list=asset_list)

            # start scan subdomain
            logger.log('INFO',"[SubdomainPort] 开始扫描 - " + pdomain)
            pdomain_name = self.es_helper.remove_http_or_https(pdomain).split("/")[0].replace("*.", "").replace("*", "")
            self.startSubdomainPortFileScan(program=pdomain_name)

            # write subdomain
            logger.log('INFO',"[SubdomainPort] 开始写入子域资产 - " + pdomain)
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
    #dirscan = SubdomainDirScan()
    #dirscan.testScan(url="https://lessons.uacdn.net")
    #dirscan.subdomaindir_scan_all()
    pass