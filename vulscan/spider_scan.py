# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : spider_scan.py
# Time       ：2021/11/26 19:05
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""
import os, sys
import json
import shlex
import copy
import time
import requests
import datetime
import subprocess
from functools import reduce
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.common import cmdprocess
from vcommon.ESHelper import ESHelper
from vconfig.config import *
from vconfig.log import logger
#from subdomain.oneforall.config.log import logger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
requests.packages.urllib3.disable_warnings()

class SpiderScan(object):
    def __init__(self):
        self.crawlergo_cmd = f"{CUR_DIR}/tools/crawlergo -c /usr/bin/google-chrome-stable -t 20 -f smart --fuzz-path --robots-path --output-json"
        self.spiderResultDir = CUR_DIR + "/results/spider"
        self.urls_resultDir = CUR_DIR + "/results/urls"
        self.scanner_name = "spider_scan"
        self.domain_index = "domain-assets-1"
        self.spider_index = "spider-assets-1"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)

    def spider(self, asset_info):
        try:
            logger.log('INFOR',"Start spider urls scan starting....")
            #url = "http://www.52helong.cn/"
            url = asset_info['url']
            scheme = urlparse(url).scheme
            netloc = urlparse(url).netloc
            if ":" in netloc:
                netloc = urlparse(url).netloc.split(":")[0] + "_" + urlparse(url).netloc.split(":")[1]
            crawlergo_output_json = f"{self.spiderResultDir}/{scheme}_{netloc}_crawlergo_output.json"
            logger.log('INFOR',crawlergo_output_json)
            if os.path.exists(crawlergo_output_json):
                os.remove(crawlergo_output_json)
            crawlergo_cmd_line = f"{self.crawlergo_cmd} {crawlergo_output_json} {url}"
            logger.log('INFOR',crawlergo_cmd_line)
            os.system(crawlergo_cmd_line)
            #time.sleep(3)
            logger.log('INFOR',"[crawl ok]")
        except Exception as error:
            logger.log('DEBUG', f'{error}')

    def read_url_list(self, program=None, pdomain=None, subdomain=None):
        '''根据筛选条件读取url全list'''
        if subdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"subdomain": str(subdomain)}},
                            {"match_phrase": {"alive": "1"}},
                            {"match_phrase": {"status": "200"}}
                        ]
                    }
                },
                "_source": ["program", "launched_at", "pdomain", "subdomain", "url", "max_severity"]
            }
        elif pdomain != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"pdomain": str(pdomain)}},
                            {"match_phrase": {"alive": "1"}},
                            {"match_phrase": {"status": "200"}}
                        ]
                    }
                },
                "_source": ["program", "launched_at", "pdomain", "subdomain", "url", "max_severity"]
            }
        elif program != None:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"program": str(program)}},
                            {"match_phrase": {"alive": "1"}},
                            {"match_phrase": {"status": "200"}}
                        ]
                    }
                },
                "_source": ["program", "launched_at", "pdomain", "subdomain", "url", "max_severity"]
            }
        else:
            dsl = {
                "query": {
                    "bool": {
                        "must": [
                            {"match_phrase": {"alive": "1"}},
                            {"match_phrase": {"status": "200"}}
                        ]
                    }
                },
                "_source": ["program", "launched_at", "pdomain", "subdomain", "url", "max_severity"]
            }
            # dsl = {'query': {'match': {'program': str(program)}}}
        domain_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return domain_list

    def read_new_url_list(self, last_update_time=None):
        '''根据筛选条件读取url全list'''
        if last_update_time == None:
            last_update_time = datetime.datetime.now().replace(day=datetime.datetime.now().day - 1)
        dsl = {
            "query": {
                "bool": {
                    "must": [
                        {"match_phrase": {"alive": "1"}},
                        {"match_phrase": {"status": "200"}}
                    ],
                    "filter": [
                        {
                            "range": {
                                "update_time": {
                                    "gte": last_update_time,
                                    "lt": "2028-01-01T12:10:30Z"
                                }
                            }
                        }
                    ]
                }
            },
            "_source": ["program", "launched_at", "pdomain", "subdomain", "url", "max_severity"]
        }
        new_url_list = self.es_helper.query_domains_by_dsl(self.domain_index, dsl)
        return new_url_list

    '''爬虫数据去重'''
    def remove_duplicate_data_from_list(self, list_dict_data):
        copy_list = []
        for list_data in list_dict_data:
            num = 0
            for cop in copy_list:
                if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop['data']:
                    num += 1
            if num == 0:
                copy_list.append(list_data)
        return copy_list

    def write_spider_list_to_kibana(self,asset_info):
        url = asset_info['url']
        scheme = urlparse(url).scheme
        netloc = urlparse(url).netloc
        if ":" in netloc:
            netloc = urlparse(url).netloc.split(":")[0] + "_" + urlparse(url).netloc.split(":")[1]
        #file = "/root/vuln_scan/vulscan/results/172.16.100.203_crawlergo_output.json"
        crawlergo_output_json = f"{self.spiderResultDir}/{scheme}_{netloc}_crawlergo_output.json"
        if os.path.exists(crawlergo_output_json):
            logger.log('INFOR',"[+]"+crawlergo_output_json)
            with open(crawlergo_output_json, 'r') as f:
                json_file = json.loads(f.read())
                req_list = json_file["req_list"]
                spider_info = {}
                spider_info['program'] = asset_info['program']
                spider_info['launched_at'] = datetime.datetime.now()
                spider_info['pdomain'] = asset_info['pdomain']
                spider_info['subdomain'] = asset_info['subdomain']
                spider_info['url'] = asset_info['url']
                if "max_severity" in asset_info:
                    spider_info['max_severity'] = asset_info['max_severity']
                '''
                ADD：URL、Method、Headers、Data、Source
                '''
                req_list = self.remove_duplicate_data_from_list(req_list)
                for each in req_list:
                    for key,value in each.items():
                        try:
                            if key == "headers":
                                value.pop('Spider-Name')
                                #value = json.dumps(value)
                            spider_info[key] = value
                        except Exception as error:
                            logger.log('DEBUG',f'{error}')
                    logger.log('INFOR',spider_info)
                    self.es_helper.insert_one_doc(self.spider_index, spider_info)
                logger.log('INFOR',f'[+]爬取网站[{url}]入库完成')

    def write_spider_list_to_txt(self, program, asset_list):
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

if __name__ == "__main__":
    '''
    spider_scan = SpiderScan()  # http://172.16.234.134:10083/http://172.16.200.60:8080
    asset_info_list = spider_scan.read_url_list(program="ninja-kiwi")
    #asset_info_list = [{"program":"p1", "launched_at":"Oct 13, 2021 @ 16:48:10.985", "url":"http://www.52helong.cn/", "max_severity":"p1"}]
    start = time.time()
    for asset_info in asset_info_list:
        asset_info = asset_info['_source']
        logger.log('INFOR',asset_info)
        spider_scan.spider(asset_info)
        spider_scan.write_spider_list(asset_info)
    #spider_scan.remove_duplicate_data_from_index(program="ninja-kiwi")
    end = time.time()
    spend_time = end - start
    logger.log('INFOR',spend_time)
    '''