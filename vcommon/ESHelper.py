# !/usr/bin/env python
# -*-coding:utf-8 -*-

"""
# File       : ElasticSearch.py
# Time       ：2021/9/15 15:02
# version    ：python 3

# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks
"""
from elasticsearch import Elasticsearch, helpers
import traceback
import time
from vconfig.log import logger

class ESHelper(object):
    def __init__(self, hosts=None, auth_user=None, auth_pass=None):
        assert hosts, f"ElasticSearch init failed, because of the hosts is empty!"
        if hosts:
            if auth_user and auth_pass:
                self.es_instance = Elasticsearch(hosts, http_auth=(auth_user, auth_pass))
            else:
                self.es_instance = Elasticsearch(hosts)
        self.spider_index = "spider-assets-1"
        self.domain_index = "domain-assets-1"
        self.vuln_index = "vuln-assets-1"
        self.batch_actions = []
        self.bulk_time = time.time()
        self.bulk_count = 10
        self.time_threshold = 60

    def bulk_write(self, actions):
        response = helpers.bulk(self.es_instance, actions)
        return response

    def insert_one_doc(self, index, asset_info):
        result = self.es_instance.index(index, body=asset_info)
        logger.log('INFOR',f"index:{index}, result:{result.get('result')}")
        return result

    def update_by_query(self, index, dsl, refresh=True, conflicts="proceed"):
        res = self.es_instance.update_by_query(index, body=dsl, refresh=refresh, conflicts=conflicts)
        logger.log('INFOR',f"update_by_query:{dsl}, result:{res.get('result')}")
        return res

    def query_by_id(self, index, id):
        dsl = {"query": {"match_phrase": {"_id": id}}}
        res = self.es_instance.search(index=index, body=dsl)
        if res and 'hits' in res:
            total = res['hits'].get("total")
            if total and total.get('value') >= 1:
                hit_doc = res['hits']['hits'][0]['_source']
                return hit_doc
            else:
                return None

    def query_domains_by_dsl(self, index, dsl):
        try:
            page = self.es_instance.search(index=index, scroll='2m', size=10, body=dsl)
            if not isinstance(page, dict):
                logger.log('INFOR',f"{index}, dsl:{dsl}, res none!")
                return
            sid = page['_scroll_id']

            scroll_size = page['hits']['total']['value']
            total_count = scroll_size
            if scroll_size == 0:
                return
            result = []
            for doc in page['hits']['hits']:
                result.append(doc)
            while scroll_size > 0:
                scroll_res = self.es_instance.scroll(scroll_id=sid, scroll='2m')
                sid = scroll_res['_scroll_id']
                scroll_size = len(scroll_res['hits']['hits'])
                for doc in scroll_res['hits']['hits']:
                    result.append(doc)
            logger.log('INFOR',f"query dsl:{dsl}, total:{total_count}, res_count:{len(result)}")
            return result
        except:
            logger.log('DEBUG',f"Query idnex:{index}, dsl:{dsl} exception:{traceback.format_exc()}")

    def delete_by_id(self, index, doc_id):
        result = self.es_instance.delete(index=index, id=doc_id)
        logger.log('INFOR',f"delete {index}:{doc_id} res:{result.get('result')}")

    def delete_all_by_index(self, index):
        query = {
                "query": {
                    "match_all": { }
                }
            }
        self.es_instance.delete_by_query(index=index, body=query)
        logger.log('INFOR',f"delete all {index}")

    def delete_all_by_pdomain(self, pdomain):
        query = {"query": {
                    "bool": {
                            "must": [
                                {"match_phrase": {"pdomain": str(pdomain)}}
                            ]
                        }
                }}
        self.es_instance.delete_by_query(index="domain-assets-1", body=query)
        logger.log('INFOR',f"[delete]delete all {pdomain}")

    def delete_all_by_dsl(self, index, dsl):
        self.es_instance.delete_by_query(index=index, body=dsl)
        logger.log('INFOR',f"delete all {index}")

    def remove_http_or_https(self,domain):
        if domain.startswith("http://"):
            domain = domain.replace("http://", "")
        if domain.startswith("https://"):
            domain = domain.replace("https://", "")
        return domain

    '''在spider索引中通过program去除重复数据'''
    def remove_duplicate_data_in_spider_program(self, program):
        dsl = {'query': {'match_phrase': {'program': str(program)}}}
        spider_list = self.query_domains_by_dsl(self.spider_index, dsl)
        if spider_list != None:
            self.delete_all_by_dsl(self.spider_index, dsl)
            copy_list = []
            for list_data in spider_list:
                list_data = list_data['_source']
                logger.log('INFOR',list_data)
                num = 0
                for cop in copy_list:
                    if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop[
                        'data']:
                        num += 1
                if num == 0:
                    copy_list.append(list_data)
                    self.insert_one_doc(self.spider_index, list_data)

    '''在spider索引中通过pdomain去除重复数据'''
    def remove_duplicate_data_in_spider_pdomain(self, pdomain):
        dsl = {'query': {'match_phrase': {'pdomain': str(pdomain)}}}
        #print(dsl)
        spider_list = self.query_domains_by_dsl(self.spider_index, dsl)
        if spider_list != None:
            #print(dsl)
            try:
                self.delete_all_by_dsl(self.spider_index, dsl)
                copy_list = []
                for list_data in spider_list:
                    list_data = list_data['_source']
                    logger.log('INFOR',list_data)
                    num = 0
                    for cop in copy_list:
                        if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop[
                            'data']:
                            num += 1
                    if num == 0:
                        copy_list.append(list_data)
                        self.insert_one_doc(self.spider_index, list_data)
            except Exception as e:
                logger.log('ERROR', e)

    '''在spider索引中去除重复数据'''
    def remove_duplicate_data_in_spider(self):
        dsl = {'query': {'match_all': {}}}
        spider_list = self.query_domains_by_dsl(self.spider_index, dsl)
        if spider_list != None:
            self.delete_all_by_dsl(self.spider_index, dsl)
            copy_list = []
            for list_data in spider_list:
                list_data = list_data['_source']
                logger.log('INFOR',list_data)
                num = 0
                for cop in copy_list:
                    if list_data['url'] == cop['url'] and list_data['method'] == cop['method'] and list_data['data'] == cop[
                        'data']:
                        num += 1
                if num == 0:
                    copy_list.append(list_data)
                    self.insert_one_doc(self.spider_index, list_data)

    '''在domain索引中通过program去除重复数据'''
    def remove_duplicate_data_in_domain_program(self, program):
        dsl = {'query': {'match': {'program': str(program)}}}
        spider_list = self.query_domains_by_dsl(self.domain_index, dsl)
        if spider_list != None:
            self.delete_all_by_dsl(self.domain_index, dsl)
            copy_list = []
            for list_data in spider_list:
                list_data = list_data['_source']
                num = 0
                for cop in copy_list:
                    if list_data['url'] == cop['url']:
                        num += 1
                if num == 0:
                    copy_list.append(list_data)
                    self.insert_one_doc(self.domain_index, list_data)

    '''在domain索引中去除重复数据'''
    def remove_duplicate_data_in_domain(self):
        dsl = {'query': {'match_all': {}}}
        spider_list = self.query_domains_by_dsl(self.domain_index, dsl)
        if spider_list != None:
            self.delete_all_by_dsl(self.domain_index, dsl)
            copy_list = []
            for list_data in spider_list:
                list_data = list_data['_source']
                num = 0
                for cop in copy_list:
                    if list_data['url'] == cop['url']:
                        num += 1
                if num == 0:
                    copy_list.append(list_data)
                    self.insert_one_doc(self.domain_index, list_data)

    '''在vuln索引中去除重复数据'''
    def remove_duplicate_data_in_vuln(self):
        dsl = {'query': {'match_all': {}}}
        vuln_list = self.query_domains_by_dsl(self.vuln_index, dsl)
        if vuln_list != None:
            self.delete_all_by_dsl(self.vuln_index, dsl)
            copy_list = []
            for list_data in vuln_list:
                list_data = list_data['_source']
                num = 0
                for cop in copy_list:
                    if list_data['vuln_name'] == cop['vuln_name'] and list_data['website'] == cop['website']:
                        num += 1
                if num == 0:
                    copy_list.append(list_data)
                    self.insert_one_doc(self.vuln_index, list_data)