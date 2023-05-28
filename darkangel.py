# !/usr/bin/env python
# -*-coding:utf-8 -*-
"""
# File       : main_scan.py
# Time       ：2021/12/15
# version    ：python 3
# Description：

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""
import os
import re
import sys
import json
import time
import uuid
import copy
import datetime
import argparse
import requests
import datetime
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
from multiprocessing import Process
from optparse import OptionParser

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/subdomain/oneforall")

from vulscan.xray_scan import *
from vulscan.nuclei_scan import NucleiScan
from vulscan.spider_scan import SpiderScan
from vulscan.fuzz_scan import FuzzScan
from vulscan.subdomain_port_scan import SubdomainPortScan
from vulscan.fingerprint_scan import FingerprintScan
from vcommon.ESHelper import ESHelper
from vcommon.vuln_manage import VulnManager
from vconfig.config import *
from vconfig.log import logger
# from subdomain.oneforall.config.log import logger
from h1domain.collecth1domain import CollectH1Domain
from h1domain.collectbcdomain import CollectBCDomain
from subdomain.oneforall.subdomain_run import SubDomain
import traceback

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
# 防止SSL报错
requests.packages.urllib3.disable_warnings()

yellow = '\033[01;33m'
white = '\033[01;37m'
green = '\033[01;32m'
blue = '\033[01;34m'
red = '\033[1;31m'
end = '\033[0m'

darkangel_banner = f'''{green}
    ____             __   ___                     __
   / __ \____ ______/ /__/   |  ____  ____ ____  / /
  / / / / __ `/ ___/ //_/ /| | / __ \/ __ `/ _ \/ / 
 / /_/ / /_/ / /  / ,< / ___ |/ / / / /_/ /  __/ /  
/_____/\__,_/_/  /_/|_/_/  |_/_/ /_/\__, /\___/_/   
                                   /____/                  
{green}                           By Bywalks | V 0.0.8    

DarkAngel is a white hat scanner. Every white hat makes the Internet more secure.        
'''


class DarkAngel(object):
    def __init__(self):
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.subdomain_scan = SubDomain()
        self.nuclei_scan = NucleiScan()
        self.spider_scan = SpiderScan()
        self.subdomain_port_scan = SubdomainPortScan()
        self.finger_scan = FingerprintScan()
        self.fuzz_scan = FuzzScan()
        self.xray_scan = XrayScan()
        self.h1_scan = CollectH1Domain()
        self.bc_scan = CollectBCDomain()
        self.vuln_mng = VulnManager()
        self.program_index = "program-assets-1"
        self.domain_index = "domain-assets-1"
        self.spider_index = "spider-assets-1"

    def get_new_pdomain(self, begin_time=None):
        if begin_time == None:
            begin_time = datetime.datetime.now().replace(day=datetime.datetime.now().day - 1)
        dsl = {
            "query": {
                "range": {
                    "update_time": {
                        "gte": begin_time,
                        "lt": "2028-01-01T12:10:30Z"
                    }
                }
            },
            "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
        }
        # res = es_helper.es_instance.search(index="program-assets-1", scroll='2m', size=10, body=dsl)
        new_pdomain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return new_pdomain_list

    def get_pdomain_by_launched_time(self, gte, lt):
        dsl = {
            'query': {
                "range": {
                    "launched_at": {
                        "gte": gte,
                        "lt": lt
                    }
                }
            },
            "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
        }
        pdomain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return pdomain_list

    def get_pdomain_by_program(self, program):
        dsl = {
            'query': {
                "bool": {
                    "must": [
                        {"match_phrase": {"program": str(program)}}
                    ]
                }
            },
            "_source": ["program", "launched_at", "update_time", "domain", "max_severity", "platform", "offer_bounty"]
        }
        # res = es_helper.es_instance.search(index="program-assets-1", scroll='2m', size=10, body=dsl)
        pdomain_list = self.es_helper.query_domains_by_dsl(self.program_index, dsl)
        return pdomain_list

    def scan_module(self, pdomain_list, begin_time=None):
        # 1：根据pdomain信息进行子域名扫描，并把扫到的子域名打入ES
        if pdomain_list != None:
            executor = ThreadPoolExecutor(max_workers=5)
            futures = []
            pdomain_len = len(pdomain_list)

            i = 1
            for pdomain_info in pdomain_list:
                logger.log('INFOR',
                           "[Subdomain] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                               'program'] + "-" + pdomain_info['_source']['domain'])
                try:
                    self.subdomain_scan.scansubdomain(pdomain_info)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')
                i = i + 1

            if begin_time != None:
                # 添加bounty和no_bounty域名
                self.save_new_url_list_by_time(begin_time=begin_time)

            # 2：subdomain_port_scan，然后写入assets_list
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                logger.log('INFOR',
                           "[SubdomainPort] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                               'program'] + "-" + pdomain_info['_source']['domain'])
                try:
                    self.subdomain_port_scan.subdomainport_scan_by_pdomain(pdomain)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')
                i = i + 1

            # 3：fingerprint_scan，然后写入fingerprint_list
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                logger.log('INFOR', "[Fingerprint] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" +
                           pdomain_info['_source']['program'] + "-" + pdomain_info['_source']['domain'])
                self.finger_scan.finger_scan_by_pdomain(pdomain=pdomain)
                i = i + 1

            # 4：nuclei_url_list，然后对nuclei_url_list进行nuclei扫描
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                logger.log('INFOR',
                           "[Nuclei-Pdomain] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                               'program'] + "-" + pdomain_info['_source']['domain'])
                i = i + 1
                new_nuclei_url_list = self.nuclei_scan.read_url_list(pdomain=pdomain)
                if new_nuclei_url_list:
                    new_nuclei_url_len = len(new_nuclei_url_list)

                    j = 1
                    for url_info in new_nuclei_url_list:
                        logger.log('INFOR', "[Nuclei-Subdomain] 开始扫描第" + str(j) + "/" + str(new_nuclei_url_len) + "-" +
                                   url_info['_source']['url'])
                        j = j + 1
                        f1 = executor.submit(self.nuclei_scan.startNucleiScan, url_info['_source'])
                        futures.append(f1)
                    # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
                    wait(futures)

                    j = 1
                    for url_info1 in new_nuclei_url_list:
                        logger.log('INFOR', "[Nuclei-Subdomain] 开始写入第" + str(j) + "/" + str(new_nuclei_url_len) + "-" +
                                   url_info1['_source']['url'])
                        j = j + 1
                        self.nuclei_scan.write_nuclei_list(url_info1['_source'])

            # 5：对新增的url做爬虫
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                logger.log('INFOR', "[Spider] 开始爬取第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                    'program'] + "-" + pdomain_info['_source']['domain'])
                i = i + 1
                asset_info_list = self.spider_scan.read_url_list(pdomain=pdomain)
                if asset_info_list != None:
                    for asset_info in asset_info_list:
                        asset_info = asset_info['_source']
                        logger.log('INFOR', asset_info)
                        f1 = executor.submit(self.spider_scan.spider, asset_info)
                        futures.append(f1)
                    # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
                    wait(futures)

            # 读写spider数据
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                logger.log('INFOR', "[Spider] 开始写入第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                    'program'] + "-" + pdomain_info['_source']['domain'])
                # 做spider之前pdomain中有http:// https://则把http://或者https://去除掉再查（加http://或者https://）
                asset_info_list = self.spider_scan.read_url_list(pdomain=pdomain)
                if asset_info_list != None:
                    for asset_info in asset_info_list:
                        print(asset_info)
                        try:
                            self.spider_scan.write_spider_list_to_kibana(asset_info['_source'])
                        except Exception as error:
                            logger.log('DEBUG', f'{error}')
                    self.es_helper.remove_duplicate_data_in_spider_pdomain(pdomain=pdomain)
                i = i + 1

            '''
            # 7：对新增的url做fuzz扫描
            # ./interactsh-client-new -server https://xx -j -token xx -o /root/vuln_scan/vulscan/results/fuzz/fuzz.json
            time.sleep(20)
            i = 1
            for pdomain_info in pdomain_list:
                pdomain = pdomain_info['_source']['domain']
                pdomain = self.fuzz_scan.deal_domain_name(domain_name=pdomain)
                logger.log('INFOR', "[Fuzz] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                    'program'] + "-" + pdomain_info['_source']['domain'])
                if pdomain != None:
                    self.fuzz_scan.startfuzz(pdomain=pdomain)
                    time.sleep(1)
                    logger.log('INFOR', "[Fuzz] 扫描成功" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                        'program'] + "-" + pdomain_info['_source']['domain'])
                    self.fuzz_scan.write_fuzz_list(domain=pdomain)
                i = i + 1
            '''

            # 8：对新增的url做xray扫描
            self.xray_scan.delxray()
            # 启动xray漏洞扫描器
            scanner = threading.Thread(target=self.xray_scan.startxray)
            # scanner.setDaemon(True)
            scanner.start()
            time.sleep(20)
            # 启动flask
            web = threading.Thread(target=start_webhook)
            # web.setDaemon(True)
            web.start()
            time.sleep(20)
            # 启动调度，把爬虫结果打入xray扫描

            i = 1
            for pdomain_info in pdomain_list:
                logger.log('INFOR', "[Xray] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                    'program'] + "-" + pdomain_info['_source']['domain'])
                i = i + 1
                pdomain = pdomain_info['_source']['domain']
                self.xray_scan.startdispatch(pdomain=pdomain)

        else:
            logger.log('INFOR', "不存在新增pdomain，扫描结束！")

    def scan_new_domain(self):
        # 1：收集h1和bc 新program和pdomain
        '''
        begin_time = "2022-01-20T10:05:38Z"
        :return: 
        '''
        while True:
            if not self.es_helper.es_instance.ping():
                logger.log('INFOR', f"ES未连接，请检查配置文件是否填写或是否正确。")
                logger.log('DEBUG', f"ES未连接，请检查配置文件是否填写或是否正确。")
                break

            begin_time = datetime.datetime.now()
            # begin_time = datetime.datetime.now().replace(hour=datetime.datetime.now().hour - 1)
            # begin_time = "2022-11-25T08:21:10.34Z"
            logger.log('INFOR', "[begin_time]" + str(begin_time))

            time.sleep(30)
            # 收集新的私有程序
            all_private_programs = self.h1_scan.collecprivateprogram()
            # 通过program获取h1 private域名，并与原库域名做匹配，若不存在则入库 ES
            self.h1_scan.collectnewprivateprogramdomain(all_private_programs)

            all_programs = self.h1_scan.collecprogram()
            # 通过program获取h1域名，并与原库域名做匹配，若不存在则入库 ES
            self.h1_scan.collectnewprogramdomain(all_programs)

            # 获取bc域名，并与原库域名做匹配，若不存在则入库 ES
            self.bc_scan.collect_new_bc_program_domain()

            # 延时5s
            time.sleep(30)

            # 2：漏洞扫描模块-获取新pdomain
            # 通过时间获取之前插入的新域名
            # begin_time = "2022-01-20T10:05:38Z"
            new_pdomain_list = self.get_new_pdomain(begin_time=begin_time)
            if new_pdomain_list:
                message = f"发现新pdomain,开始进行扫描。"
                self.vuln_mng.send_message(message=message)
                self.scan_module(pdomain_list=new_pdomain_list, begin_time=begin_time)

                message = f"新pdomain扫描完成。"
                self.vuln_mng.send_message(message=message)
            else:
                message = f"未发现新pdomain,等待半小时后进行扫描。"
                self.vuln_mng.send_message(message=message)
            time.sleep(10800)

    def scan_domain_by_program(self, program):
        # 1：漏洞扫描模块-获取新pdomain
        # 通过program获取pdomain
        program_pdomain_list = self.get_pdomain_by_program(program)

        # 2: 漏洞扫描模块-开始扫描
        self.scan_module(pdomain_list=program_pdomain_list, begin_time=None)

    def scan_domain_by_time(self, gte, lt):
        # 1：漏洞扫描模块-通过时间获取pdomain_list
        # 通过时间获取pdomain
        pdomain_list = self.get_pdomain_by_launched_time(gte, lt)

        # 2: 漏洞扫描模块-开始扫描
        if pdomain_list:
            message = f"发现新pdomain,开始进行扫描。"
            self.vuln_mng.send_message(message=message)
            self.scan_module(pdomain_list=pdomain_list, begin_time=gte)
            message = f"新pdomain扫描完成。"
            self.vuln_mng.send_message(message=message)
        else:
            message = f"未发现新pdomain,请检查该时间段是否存在pdomain资产。"
            self.vuln_mng.send_message(message=message)

    def add_domain_and_scan(self, program_list, offer_bounty):
        if not self.es_helper.es_instance.ping():
            logger.log('INFOR', f"ES未连接，请检查配置文件是否填写或是否正确。")
            logger.log('DEBUG', f"ES未连接，请检查配置文件是否填写或是否正确。")
        else:
            # 获取开始时间
            begin_time = datetime.datetime.now().replace(hour=datetime.datetime.now().hour - 1)
            # begin_time = "2022-04-13T08:24:59Z"
            logger.log('INFOR', "[begin_time]" + str(begin_time))
            old_domains = self.h1_scan.searchallprogramdomain()
            # 1：添加程序
            if offer_bounty == "yes":
                for each in program_list:
                    self.add_new_program_from_file(program=str(each), offer_bounty="yes", old_domains=old_domains)
            elif offer_bounty == "no":
                for each in program_list:
                    self.add_new_program_from_file(program=str(each), offer_bounty="no", old_domains=old_domains)

            time.sleep(10)
            # 2：通过时间获取pdomain
            pdomain_list = self.get_pdomain_by_launched_time(gte=begin_time, lt="2028-01-01")

            # 3: 漏洞扫描模块-开始扫描
            self.scan_module(pdomain_list=pdomain_list, begin_time=begin_time)

    def add_new_domain(self):
        # 收集h1和bc 新program和pdomain
        begin_time = datetime.datetime.now()
        # begin_time = datetime.datetime.now().replace(hour=datetime.datetime.now().hour - 1)
        # begin_time = "2022-11-25T08:21:10.34Z"
        logger.log('INFOR', "[begin_time]" + str(begin_time))

        if not self.es_helper.es_instance.ping():
            logger.log('INFOR', f"ES未连接，请检查配置文件是否填写或是否正确。")
            logger.log('DEBUG', f"ES未连接，请检查配置文件是否填写或是否正确。")
            return

        time.sleep(30)
        # 收集新的私有程序
        all_private_programs = self.h1_scan.collecprivateprogram()
        # 通过program获取h1 private域名，并与原库域名做匹配，若不存在则入库 ES
        self.h1_scan.collectnewprivateprogramdomain(all_private_programs)

        all_programs = self.h1_scan.collecprogram()
        # 通过program获取h1域名，并与原库域名做匹配，若不存在则入库 ES
        self.h1_scan.collectnewprogramdomain(all_programs)

        # 获取bc域名，并与原库域名做匹配，若不存在则入库 ES
        self.bc_scan.collect_new_bc_program_domain()

    def scan_subdomain_by_launched_at(self, gte=None, lt=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        pdomain_list = self.subdomain_scan.read_domains_by_launched_at(gte, lt)
        if pdomain_list != None:
            pdomain_len = len(pdomain_list)
            i = 1
            for pdomain_info in pdomain_list:
                logger.log('INFOR',
                           "[Subdomain] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + pdomain_info['_source'][
                               'domain'])
                i = i + 1
                try:
                    logger.log('INFOR', pdomain_info['_source']['program'] + " - " + pdomain_info['_source']['domain'])
                    self.subdomain_scan.scansubdomain(pdomain_info)
                except Exception as error:
                    logger.log('DEBUG', f'{error}')

    def scan_subdomain_by_domain(self, filename):
        file_name = f"/root/DarkAngel/{filename}.txt"
        file_len = len(open(file_name, 'r').readlines())
        i = 1
        with open(file_name, 'r') as f:
            for each in f:
                each = each.strip("\n")
                logger.log('INFOR', "[Subdomain] 开始扫描第" + str(i) + "/" + str(file_len) + "-" + each)
                pdomain_info = self.subdomain_scan.read_domains_by_domain(str(each))
                if pdomain_info:
                    try:
                        self.subdomain_scan.scansubdomain(pdomain_info[0])
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
                i = i + 1

    def nuclei_scan_by_temp(self, gte=None, lt=None, templateName=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        pdomain_list = self.get_pdomain_by_launched_time(gte, lt)
        if pdomain_list != None:
            pdomain_len = len(pdomain_list)
            i = 1

            # 读写url_list，并生成txt文件，给后续的nuclei扫描
            for each_info in pdomain_list:
                pdomain_info = each_info["_source"]["domain"]
                if "/" not in pdomain_info:
                    logger.log('INFOR', pdomain_info)
                    url_list = self.nuclei_scan.read_url_list(pdomain=pdomain_info)
                    if url_list:
                        logger.log('INFOR', url_list)
                        self.nuclei_scan.write_url_list(program=pdomain_info, asset_list=url_list)

            # 对这些以pdomain为单位的url_list进行nuclei扫描
            for each_info in pdomain_list:
                logger.log('INFOR',
                           "[Nuclei] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + each_info['_source']['domain'])
                i = i + 1
                pdomain_info = each_info["_source"]["domain"]
                if "/" not in pdomain_info:
                    try:
                        # pdomain_info = each_info["_source"]["domain"]
                        logger.log('INFOR', pdomain_info)
                        urls_output_txt = f"{self.nuclei_scan.urls_resultDir}/{pdomain_info}_urls_output.txt"
                        if os.path.exists(urls_output_txt):
                            self.nuclei_scan.startNucleiTempFileScan(program=pdomain_info,
                                                                     templateName=templateName)
                            self.nuclei_scan.write_nuclei_template_list(program=pdomain_info)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

    def nuclei_five_file_scan_temp(self, templateName=None, offer_bounty=None, platform=None):
        '''
        /root/vuln_scan/vulscan/tools/nuclei -u https://tw.mina.mi.com -severity critical,high,medium -status -header 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36' -j -o 1.json
        Temp: -t vulnerabilities/my/my-cache.yaml
        '''
        file_list = []
        if platform == "h1":
            if offer_bounty == "yes":
                file_list = ["h1_bounty_01", "h1_bounty_02", "h1_bounty_03", "h1_bounty_04", "h1_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["h1_no_bounty_01", "h1_no_bounty_02", "h1_no_bounty_03", "h1_no_bounty_04",
                             "h1_no_bounty_05"]
        elif platform == "bc":
            if offer_bounty == "yes":
                file_list = ["bc_bounty_01", "bc_bounty_02", "bc_bounty_03", "bc_bounty_04", "bc_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["bc_no_bounty_01", "bc_no_bounty_02", "bc_no_bounty_03", "bc_no_bounty_04",
                             "bc_no_bounty_05"]
        file_len = len(file_list)
        i = 1
        executor = ThreadPoolExecutor(max_workers=5)
        futures = []
        for file_name in file_list:
            args = []
            args.append(file_name)
            args.append(templateName)
            logger.log('INFOR', "[Nuclei] 开始扫描第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            f1 = executor.submit(lambda p: self.nuclei_scan.startNucleiTempFileScan(*p), args)
            futures.append(f1)
            i = i + 1
        # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
        wait(futures)

        i = 1
        for file_name in file_list:
            logger.log('INFOR', "[Nuclei] 开始写入第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            self.nuclei_scan.write_nuclei_template_list(program=file_name)
            i = i + 1

    def nuclei_scan_by_file(self, gte=None, lt=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        pdomain_list = self.get_pdomain_by_launched_time(gte, lt)
        if pdomain_list != None:
            pdomain_len = len(pdomain_list)
            i = 1

            # 读写url_list，并生成txt文件，给后续的nuclei扫描
            for each_info in pdomain_list:
                pdomain_info = each_info["_source"]["domain"]
                if "/" not in pdomain_info:
                    logger.log('INFOR', pdomain_info)
                    url_list = self.nuclei_scan.read_url_list(pdomain=pdomain_info)
                    if url_list:
                        logger.log('INFOR', url_list)
                        self.nuclei_scan.write_url_list(program=pdomain_info, asset_list=url_list)

            # 对这些以pdomain为单位的url_list进行nuclei扫描
            for each_info in pdomain_list:
                logger.log('INFOR',
                           "[Nuclei] 开始扫描第" + str(i) + "/" + str(pdomain_len) + "-" + each_info['_source']['domain'])
                i = i + 1
                pdomain_info = each_info["_source"]["domain"]
                if "/" not in pdomain_info:
                    try:
                        # pdomain_info = each_info["_source"]["domain"]
                        logger.log('INFOR', pdomain_info)
                        urls_output_txt = f"{self.nuclei_scan.urls_resultDir}/{pdomain_info}_urls_output.txt"
                        if os.path.exists(urls_output_txt):
                            self.nuclei_scan.startNucleiTempFileScan(program=pdomain_info,
                                                                     templateName=templateName)
                            self.nuclei_scan.write_nuclei_template_list(program=pdomain_info)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')

    def nuclei_five_file_scan_new_temp(self, offer_bounty=None, platform=None):
        file_list = []
        if platform == "h1":
            if offer_bounty == "yes":
                file_list = ["h1_bounty_01", "h1_bounty_02", "h1_bounty_03", "h1_bounty_04", "h1_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["h1_no_bounty_01", "h1_no_bounty_02", "h1_no_bounty_03", "h1_no_bounty_04",
                             "h1_no_bounty_05"]
        elif platform == "bc":
            if offer_bounty == "yes":
                file_list = ["bc_bounty_01", "bc_bounty_02", "bc_bounty_03", "bc_bounty_04", "bc_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["bc_no_bounty_01", "bc_no_bounty_02", "bc_no_bounty_03", "bc_no_bounty_04",
                             "bc_no_bounty_05"]
        file_len = len(file_list)
        i = 1
        executor = ThreadPoolExecutor(max_workers=5)
        futures = []
        for file_name in file_list:
            logger.log('INFOR', "[Nuclei] 开始扫描第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            f1 = executor.submit(self.nuclei_scan.startNucleiNewTemlFileScan, file_name)
            futures.append(f1)
            i = i + 1
        # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
        wait(futures)

        i = 1
        for file_name in file_list:
            logger.log('INFOR', "[Nuclei] 开始写入第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            self.nuclei_scan.write_nuclei_template_list(program=file_name)
            i = i + 1

    def nuclei_five_file_scan(self, offer_bounty=None, platform=None):
        file_list = []
        if platform == "h1":
            if offer_bounty == "yes":
                file_list = ["h1_bounty_01", "h1_bounty_02", "h1_bounty_03", "h1_bounty_04", "h1_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["h1_no_bounty_01", "h1_no_bounty_02", "h1_no_bounty_03", "h1_no_bounty_04",
                             "h1_no_bounty_05"]
        elif platform == "bc":
            if offer_bounty == "yes":
                file_list = ["bc_bounty_01", "bc_bounty_02", "bc_bounty_03", "bc_bounty_04", "bc_bounty_05"]
            elif offer_bounty == "no":
                file_list = ["bc_no_bounty_01", "bc_no_bounty_02", "bc_no_bounty_03", "bc_no_bounty_04",
                             "bc_no_bounty_05"]
        file_len = len(file_list)
        i = 1
        executor = ThreadPoolExecutor(max_workers=5)
        futures = []

        for file_name in file_list:
            logger.log('INFOR', "[Nuclei] 开始扫描第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            f1 = executor.submit(self.nuclei_scan.startNucleiFileScan, file_name)
            futures.append(f1)
            i = i + 1
        # 等待futures里面所有的子线程执行结束， 再执行主线程(join())
        wait(futures)

        i = 1
        for file_name in file_list:
            logger.log('INFOR', "[Nuclei] 开始写入第" + str(i) + "/" + str(file_len) + "-" + str(file_name))
            self.nuclei_scan.write_nuclei_template_list(program=file_name)
            i = i + 1

    def nuclei_file_scan_by_temp(self, templateName=None):
        # Temp: -t vulnerabilities/my/my-cache.yaml
        # 通知
        message = f"Nuclei模板扫描\n开始扫描template: {templateName}"
        self.vuln_mng.send_message(message=message)
        time.sleep(15)
        # 开始扫描h1赏金部分
        self.nuclei_five_file_scan_temp(templateName=templateName, offer_bounty="yes", platform="h1")
        # 通知
        message = "Nuclei-h1模板赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描bc赏金部分
        self.nuclei_five_file_scan_temp(templateName=templateName, offer_bounty="yes", platform="bc")
        # 通知
        message = "Nuclei-bc模板赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描h1非赏金部分
        self.nuclei_five_file_scan_temp(templateName=templateName, offer_bounty="no", platform="h1")
        # 通知
        message = "Nuclei-h1模板非赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描bc非赏金部分
        self.nuclei_five_file_scan_temp(templateName=templateName, offer_bounty="no", platform="bc")
        # 通知
        message = "Nuclei-bc模板非赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

    def nuclei_file_scan(self):
        message = f"Nuclei模板扫描\n开始扫描"
        self.vuln_mng.send_message(message=message)

        # 开始扫描h1赏金部分
        self.nuclei_five_file_scan(offer_bounty="yes", platform="h1")
        # 通知
        message = "Nuclei-h1模板赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描bc赏金部分
        self.nuclei_five_file_scan(offer_bounty="yes", platform="bc")
        # 通知
        message = "Nuclei-bc模板赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描h1非赏金部分
        self.nuclei_five_file_scan(offer_bounty="no", platform="h1")
        # 通知
        message = "Nuclei-h1模板非赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

        time.sleep(15)
        # 开始扫描bc非赏金部分
        self.nuclei_five_file_scan(offer_bounty="no", platform="bc")
        # 通知
        message = "Nuclei-bc模板非赏金部分扫描完成"
        self.vuln_mng.send_message(message=message)

    def nuclei_file_polling_scan(self):
        # Temp: -t vulnerabilities/my/my-cache.yaml
        while True:
            # 通知
            message = f"Nuclei模板扫描\n开始扫描"
            self.vuln_mng.send_message(message=message)

            # 开始扫描h1赏金部分
            self.nuclei_five_file_scan(offer_bounty="yes", platform="h1")
            # 通知
            message = "Nuclei-h1模板赏金部分扫描完成"
            self.vuln_mng.send_message(message=message)

            time.sleep(15)

            # 开始扫描bc赏金部分
            self.nuclei_five_file_scan(offer_bounty="yes", platform="bc")
            # 通知
            message = "Nuclei-bc模板赏金部分扫描完成"
            self.vuln_mng.send_message(message=message)

            time.sleep(15)
            # 开始扫描h1非赏金部分
            self.nuclei_five_file_scan(offer_bounty="no", platform="h1")
            # 通知
            message = "Nuclei-h1模板非赏金部分扫描完成"
            self.vuln_mng.send_message(message=message)

            time.sleep(15)
            # 开始扫描bc非赏金部分
            self.nuclei_five_file_scan(offer_bounty="no", platform="bc")
            # 通知
            message = "Nuclei-bc模板非赏金部分扫描完成"
            self.vuln_mng.send_message(message=message)
            time.sleep(7200)

    def nuclei_file_scan_by_new_temp(self, version):
        '''
        # 写入五个文件
        self.write_url_list_by_time(gte="2010-01-01", lt="2013-04-01", filename="new_temp_01_no_bounty")
        self.write_url_list_by_time(gte="2013-04-01", lt="2013-09-01", filename="new_temp_02_no_bounty")
        self.write_url_list_by_time(gte="2013-09-01", lt="2015-06-01", filename="new_temp_03_no_bounty")
        self.write_url_list_by_time(gte="2015-06-01", lt="2019-10-01", filename="new_temp_04_no_bounty")
        self.write_url_list_by_time(gte="2019-10-01", lt="2023-06-01", filename="new_temp_05_no_bounty")
        '''
        version_number = version.split(".")
        x = int(version_number[0])
        y = int(version_number[1])
        z = int(version_number[2])

        while True:
            version = f"{str(x)}.{str(y)}.{str(z)}"
            url = f"https://github.com/projectdiscovery/nuclei-templates/releases/tag/v{version}"
            try:
                r = requests.get(url, verify=False, timeout=10)
                if r.status_code == 404:
                    message = f"Nuclei模板{version}暂未更新,等待半小时后再次检测。\nurl:{url}"
                    self.vuln_mng.send_message(message=message)
                elif r.status_code == 200:
                    # 通知
                    message = f"Nuclei模板已更新到{version},等待2小时后开始进行扫描\nurl:{url}"
                    self.vuln_mng.send_message(message=message)

                    # 更新模板，暂时非实时更新，故等待两小时后更新
                    time.sleep(7200)
                    self.update_nuclei_temp()
                    time.sleep(15)
                    # 开始扫描h1赏金部分
                    self.nuclei_five_file_scan_new_temp(offer_bounty="yes", platform="h1")
                    # 通知
                    message = "Nuclei-h1模板赏金部分扫描完成"
                    self.vuln_mng.send_message(message=message)

                    time.sleep(15)
                    # 开始扫描bc赏金部分
                    self.nuclei_five_file_scan_new_temp(offer_bounty="yes", platform="bc")
                    # 通知
                    message = "Nuclei-bc模板赏金部分扫描完成"
                    self.vuln_mng.send_message(message=message)

                    time.sleep(15)
                    # 开始扫描h1非赏金部分
                    self.nuclei_five_file_scan_new_temp(offer_bounty="no", platform="h1")
                    # 通知
                    message = "Nuclei-h1模板非赏金部分扫描完成"
                    self.vuln_mng.send_message(message=message)

                    time.sleep(15)
                    # 开始扫描bc非赏金部分
                    self.nuclei_five_file_scan_new_temp(offer_bounty="no", platform="bc")
                    # 通知
                    message = "Nuclei-bc模板非赏金部分扫描完成"
                    self.vuln_mng.send_message(message=message)

                    z = z + 1
                    if z == 10:
                        z = 0
                        y = y + 1
                    if y == 10:
                        y = 0
                        x = x + 1

                time.sleep(1800)
            except Exception as error:
                logger.log('DEBUG', f'{error}')

    def nuclei_file_scan_by_new_add_temp(self, number):
        # number = 4859
        number = int(number)
        while True:
            template_url = f"https://github.com/projectdiscovery/nuclei-templates/pull/{number}"
            logger.log('INFOR', "[NEW-Nuclei] 开始扫描第" + str(number))
            logger.log('INFOR', "[NEW-Nuclei] 开始扫描 - " + str(template_url))
            try:
                r = requests.get(url=template_url, verify=False, timeout=10)
                if r.status_code == 404:
                    message = f"Nuclei模板{number}暂未更新,等待一小时后再次检测。\nurl:{template_url}"
                    self.vuln_mng.send_message(message=message)
                    time.sleep(3600)
                elif r.status_code == 200:
                    template_name = ""
                    try:
                        template_name = self.nuclei_scan.write_yaml_file(number)
                        time.sleep(10)
                    except Exception as error:
                        logger.log('DEBUG', f'{error}')
                    if template_name != "":
                        logger.log('INFOR', "[NEW-Nuclei] 开始扫描" + str(template_name))
                        message = f"Nuclei模板{number}-{template_name}已更新,开始检测。\nurl:{template_url}"
                        self.vuln_mng.send_message(message=message)
                        time.sleep(10)
                        self.nuclei_file_scan_by_temp(templateName=template_name)
                    number = number + 1
            except Exception as error:
                logger.log('DEBUG', f'{error}')
            time.sleep(5)

    def write_nuclei_five_file(self):
        # 写入五个文件
        self.write_url_list_by_time(gte="2022-02-21", lt="2022-02-24", filename="bc_bounty_01", offer_bounty="yes")
        self.write_url_list_by_time(gte="2022-02-21", lt="2022-02-24", filename="bc_no_bounty_01", offer_bounty="no")

    def write_url_list_by_time(self, gte=None, lt=None, filename=None, offer_bounty=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        url_list = self.nuclei_scan.read_url_list_by_time(gte, lt, offer_bounty)
        if url_list != None:
            self.nuclei_scan.write_url_list(program=filename, asset_list=url_list)

    def write_new_url_list_by_time(self, gte=None, lt=None, filename=None, offer_bounty=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        # read_new_url_list_by_time 区别在于用的是update_time
        url_list = self.nuclei_scan.read_new_url_list_by_time(gte, lt, offer_bounty)
        if url_list != None:
            self.nuclei_scan.write_url_list(program=filename, asset_list=url_list)

    def save_new_url_list_by_time(self, begin_time=None):
        self.write_new_url_list_by_time(gte=begin_time, filename="bounty_temp", offer_bounty="yes")
        self.write_new_url_list_by_time(gte=begin_time, filename="no_bounty_temp", offer_bounty="no")

    def write_url_list_by_pdomain(self, pdomain=None, filename=None):
        url_list = self.nuclei_scan.read_url_list(pdomain=pdomain)
        if url_list != None:
            self.nuclei_scan.write_url_list(program=filename, asset_list=url_list)

    def update_nuclei_temp(self):
        os.system("nuclei -ut")

    def add_new_program_from_file(self, program, offer_bounty, old_domains):
        file = "/root/DarkAngel/" + str(program) + ".txt"
        data = datetime.datetime.now()
        with open(file, "r") as f:
            for each in f:
                each = each.strip("\n")
                logger.log('INFOR', f'Add {str(program)} - {each}')
                if str(each) not in old_domains:
                    asset_info = {'domain': str(each), 'resolved_report_count': 0, 'submission_state': 'open',
                                  'max_severity': 'critical', 'update_time': data, 'hackerone_private': "yes",
                                  'average_bounty_lower_amount': 0, 'launched_at': data,
                                  'average_bounty_upper_amount': 0, 'program': str(program), 'base_bounty': 0,
                                  'platform': "hackerone", 'offer_bounty': offer_bounty}
                    self.es_helper.insert_one_doc(index="program-assets-1", asset_info=asset_info)

    def delete_by_query(self, index):
        if index == "program":
            index = "program-assets-1"
        elif index == "domain":
            index = "domain-assets-1"
        elif index == "spider":
            index = "spider-assets-1"
        query = {"query": {
            "bool": {
                "must": [
                    {"match_phrase": {"url": "*"}}
                ]
            }
        }}
        es.es_instance.delete_by_query(index=index, body=query)

    def save_new_url_list1(self):
        print("1")
        self.write_new_url_list_by_time1(gte="2000-10-21",lt="2013-10-21",filename="hackerone_bounty_temp_01", offer_bounty="yes", platform="hackerone")
        self.write_new_url_list_by_time1(gte="2013-10-21", lt="2018-10-21", filename="hackerone_bounty_temp_02",offer_bounty="yes", platform="hackerone")
        self.write_new_url_list_by_time1(gte="2018-10-21", lt="2030-10-21", filename="hackerone_bounty_temp_03",
                                         offer_bounty="yes", platform="hackerone")
        #self.write_new_url_list_by_time1(filename="hackerone_bounty_temp", offer_bounty="yes", platform="hackerone")
        #self.write_new_url_list_by_time1(filename="hackerone_no_bounty_temp", offer_bounty="no", platform="hackerone")
        self.write_new_url_list_by_time1(gte="2000-10-21", lt="2013-10-21", filename="hackerone_no_bounty_temp_01",
                                         offer_bounty="no", platform="hackerone")
        self.write_new_url_list_by_time1(gte="2013-10-21", lt="2018-10-21", filename="hackerone_no_bounty_temp_02",
                                         offer_bounty="no", platform="hackerone")
        self.write_new_url_list_by_time1(gte="2018-10-21", lt="2030-10-21", filename="hackerone_no_bounty_temp_03",
                                         offer_bounty="no", platform="hackerone")
        #self.write_new_url_list_by_time1(filename="bugcrowd_bounty_temp", offer_bounty="yes", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2000-10-21", lt="2013-10-21", filename="bugcrowd_bounty_temp_01",
                                         offer_bounty="yes", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2013-10-21", lt="2018-10-21", filename="bugcrowd_bounty_temp_02",
                                         offer_bounty="yes", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2018-10-21", lt="2030-10-21", filename="bugcrowd_bounty_temp_03",
                                         offer_bounty="yes", platform="bugcrowd")
        #self.write_new_url_list_by_time1(filename="bugcrowd_no_bounty_temp", offer_bounty="no", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2000-10-21", lt="2013-10-21", filename="bugcrowd_no_bounty_temp_01",
                                         offer_bounty="no", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2013-10-21", lt="2018-10-21", filename="bugcrowd_no_bounty_temp_02",
                                         offer_bounty="no", platform="bugcrowd")
        self.write_new_url_list_by_time1(gte="2018-10-21", lt="2030-10-21", filename="bugcrowd_no_bounty_temp_03",
                                         offer_bounty="no", platform="bugcrowd")

    def write_new_url_list_by_time1(self, gte=None, lt=None, filename=None, offer_bounty=None, platform=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        # read_new_url_list_by_time 区别在于用的是update_time
        url_list = self.nuclei_scan.read_url_list_by_time1(gt=gte,lt=lt,offer_bounty=offer_bounty,platform=platform)
        if url_list != None:
            self.nuclei_scan.write_url_list(program=filename, asset_list=url_list)

    def write_all_program(self, gte=None, lt=None):
        if gte == None:
            gte = "2010-01-01"
        if lt == None:
            lt = "2030-01-01"
        # read_new_url_list_by_time 区别在于用的是update_time
        all_program_list = self.get_pdomain_by_launched_time(gte, lt)
        all_program = []
        print(all_program_list)
        if all_program_list != None:
            for each in all_program_list:
                each = each["_source"]["program"]
                all_program.append(each)
        all_program = set(all_program)
        with open("/root/DarkAngel/result.txt","a+") as f:
            for program_name in all_program:
                f.write(program_name+"\n")

    def write_all_spider_data(self):
        all_program = []
        with open("/root/DarkAngel/result.txt", "r") as f:
            for each in f:
                print(each.replace('\n', ''))
                all_program.append(each.replace('\n', ''))
        for program_name in all_program:
            spider_data = self.spider_scan.read_spider_list_by_program(program=program_name)
            if spider_data != None:
                self.spider_scan.write_spider_list_to_txt(program=program_name, asset_list=spider_data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--add-new-domain", help="add new domain from h1 and bc", action="store_true")
    parser.add_argument("--scan-domain-by-time", help="scan h1 and bc domain by launched time", nargs=2)
    parser.add_argument("--scan-new-domain", help="add and scan new domain from h1 and bc", action="store_true")
    parser.add_argument("--add-domain-and-scan", help="add and scan new domain self added", nargs="+")
    parser.add_argument("--offer-bounty", help="set add domain is bounty or no bounty", choices=["yes", "no"])
    parser.add_argument("--nuclei-file-scan", help="scan new domain from h1 and bc", action="store_true")
    parser.add_argument("--nuclei-file-scan-by-new-temp", help="use new template scan five file by nuclei",
                        action="store")
    parser.add_argument("--nuclei-file-scan-by-new-add-temp", help="add new template scan five file by nuclei",
                        action="store")
    parser.add_argument("--nuclei-file-scan-by-temp-name", help="use template scan five file by nuclei",
                        action="store")
    parser.add_argument("--nuclei-file-polling-scan", help="five file polling scan by nuclei",
                        action="store_true")
    print(darkangel_banner)
    args = parser.parse_args()
    darkAngel = DarkAngel()

    if args.scan_new_domain:
        darkAngel.scan_new_domain()
    elif args.add_new_domain:
        darkAngel.add_new_domain()
    elif args.scan_domain_by_time:
        try:
            gte = datetime.datetime.strptime(args.scan_domain_by_time[0], "%Y-%m-%d")
            lt = datetime.datetime.strptime(args.scan_domain_by_time[1], "%Y-%m-%d")
            if gte >= lt:
                logger.log('INFOR',"时间输入错误，之后的时间点需大于之前的时间点！")
                return
            else:
                darkAngel.scan_domain_by_time(gte, lt)
        except ValueError:
            logger.log("参数为日期，格式为2022-12-12，请按照格式输入！")
    elif args.add_domain_and_scan and args.offer_bounty == "yes":
        darkAngel.add_domain_and_scan(program_list=args.add_domain_and_scan, offer_bounty="yes")
    elif args.add_domain_and_scan and args.offer_bounty == "no":
        darkAngel.add_domain_and_scan(program_list=args.add_domain_and_scan, offer_bounty="no")
    elif args.nuclei_file_scan:
        darkAngel.nuclei_file_scan()
    elif args.nuclei_file_scan_by_new_temp:
        darkAngel.nuclei_file_scan_by_new_temp(version=args.nuclei_file_scan_by_new_temp)
    elif args.nuclei_file_scan_by_new_add_temp:
        darkAngel.nuclei_file_scan_by_new_add_temp(number=args.nuclei_file_scan_by_new_add_temp)
    elif args.nuclei_file_scan_by_temp_name:
        darkAngel.nuclei_file_scan_by_temp(templateName=args.nuclei_file_scan_by_temp_name)
    elif args.nuclei_file_polling_scan:
        darkAngel.nuclei_file_polling_scan()

if __name__ == "__main__":
    main()
