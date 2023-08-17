# Author：bywalks
# Blog：http://www.bywalks.com
# Github：https://github.com/bywalks

import requests
import jsonpath
import copy
import os
import sys
import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vcommon.ESHelper import ESHelper
from vconfig.config import *
from vconfig.log import logger
from vcommon.vuln_manage import VulnManager
#from subdomain.oneforall.config.log import logger

# 防止SSL报错
requests.packages.urllib3.disable_warnings()

class CollectH1Domain(object):
    def __init__(self):
        self.headers = {'content-type': 'application/json'}
        self.auth_headers = {
            'content-type': 'application/json',
            'Cookie': H1_COOKIE,
            'X-Csrf-Token': X_Csrf_Token
        }
        self.url = "https://hackerone.com/graphql"
        self.es_helper = ESHelper(ES_HOSTS, ES_USER, ES_PASSWD)
        self.vuln_mng = VulnManager()
        self.index = "program-assets-1"
        self.black_pdomain = ["*.taobao.com","*.alibaba.com","www.paypal-*.com","onboarding-*.cloud.com","https://dbc-a1ba5468-749b.staging.cloud.databricks.com,https://community.cloud.databricks.com/","connect.databricks.com,databricks-staging-cloudfront.staging.cloud.databricks.com,docs-admin.databricks.com,docs-user.databricks.com,e.databricks.com,go.databricks.com,go.dev.databricks.com,homebrew-tap.dev.databricks.com,ideas.staging.databricks.com,info.databricks.com,it.corp.databricks.com,ok.databricks.com,pages.databricks.com,partnermarketing.databricks.com,signup.cloud.mrkt.databricks.com,signup.dev.mrkt.databricks.com,ssh.databricks.com,ssh.spark-summit.org,staging.spark-summit.org,tools.sec-sf.databricks.com,training.databricks.com,uberlyft-ns.dev.databricks.com,waf-test.corp.databricks.com,academy.databricks.com,accounts.cloud.databricks.com,databricks-prod-cloudfront.cloud.databricks.com,delta.io,demo.cloud.databricks.com,docs.cloud.databricks.com,docs.databricks.com,docs.delta.io,files.training.databricks.com,ftp.databricks.com,go.corp.databricks.com,gw1-ap.corp.databricks.com,gw1-eu.corp.databricks.com,gw1-us.corp.databricks.com,gw2-us.corp.databricks.com","help.corp.databricks.com,help.databricks.com,ideas.databricks.com,kb.azuredatabricks.net,kb.databricks.com,maintenance.databricks.com,partners.databricks.com,pgg11o.hubspot.databricks.com,preferences.databricks.com,sophos.corp.databricks.com,spark-portal.org,spark-summit.com,spark-summit.org,sparkhub.databricks.com,support.databricks.com,unsubscribe.corp.databricks.com,vpn-us.corp.databricks.com,www.databricks.com,www.sparkhub.databricks.com,*.mil"]

    ### 第一个循环请求用来抓取所有的program
    def collecprogram(self):
        logger.log('INFOR',"Start collecting h1 programs")
        # 每页的Program数量被限制在25，所以cursor参数需要25*n，然后base64编码
        cursor = "MAo="
        all_programs = []
        while (type(cursor) == str):
            try:
                #data = '''{"operationName":"DirectoryQuery","variables":{"where":{"_and":[{"_or":[{"offers_bounties":{"_eq":true}},{"external_program":{"offers_rewards":{"_eq":true}}}]},{"structured_scopes":{"_and":[{"asset_type":{"_eq":"URL"}},{"is_archived":false}]}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"_not":{"external_program":{}}},{"_or":[{"_and":[{"state":{"_neq":"sandboxed"}},{"state":{"_neq":"soft_launched"}}]},{"external_program":{}}]}]},"first":25,"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {\\n  me {\\n    id\\n    edit_unclaimed_profiles\\n    h1_pentester\\n    __typename\\n  }\\n  teams(first: 25, after: $cursor, secure_order_by: $secureOrderBy, where: $where) {\\n    pageInfo {\\n      endCursor\\n      hasNextPage\\n      __typename\\n    }\\n    edges {\\n      node {\\n        id\\n        bookmarked\\n        ...TeamTableResolvedReports\\n        ...TeamTableAvatarAndTitle\\n        ...TeamTableLaunchDate\\n        ...TeamTableMinimumBounty\\n        ...TeamTableAverageBounty\\n        ...BookmarkTeam\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n\\nfragment TeamTableResolvedReports on Team {\\n  id\\n  resolved_report_count\\n  __typename\\n}\\n\\nfragment TeamTableAvatarAndTitle on Team {\\n  id\\n  profile_picture(size: medium)\\n  name\\n  handle\\n  submission_state\\n  triage_active\\n  publicly_visible_retesting\\n  state\\n  allows_bounty_splitting\\n  external_program {\\n    id\\n    __typename\\n  }\\n  ...TeamLinkWithMiniProfile\\n  __typename\\n}\\n\\nfragment TeamLinkWithMiniProfile on Team {\\n  id\\n  handle\\n  name\\n  __typename\\n}\\n\\nfragment TeamTableLaunchDate on Team {\\n  id\\n  launched_at\\n  __typename\\n}\\n\\nfragment TeamTableMinimumBounty on Team {\\n  id\\n  currency\\n  base_bounty\\n  __typename\\n}\\n\\nfragment TeamTableAverageBounty on Team {\\n  id\\n  currency\\n  average_bounty_lower_amount\\n  average_bounty_upper_amount\\n  __typename\\n}\\n\\nfragment BookmarkTeam on Team {\\n  id\\n  bookmarked\\n  __typename\\n}\\n"}'''
                #data = '''{"operationName":"DirectoryQuery","variables":{"where":{"_and":[{"_or":[{"structured_scopes":{"_and":[{"asset_type":{"_eq":"URL"}},{"is_archived":false}]}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"_not":{"external_program":{}}},{"_or":[{"_and":[{"state":{"_neq":"sandboxed"}},{"state":{"_neq":"soft_launched"}}]},{"external_program":{}}]}]},"first":25,"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {\\n  me {\\n    id\\n    edit_unclaimed_profiles\\n    h1_pentester\\n    __typename\\n  }\\n  teams(first: 25, after: $cursor, secure_order_by: $secureOrderBy, where: $where) {\\n    pageInfo {\\n      endCursor\\n      hasNextPage\\n      __typename\\n    }\\n    edges {\\n      node {\\n        id\\n        bookmarked\\n        ...TeamTableResolvedReports\\n        ...TeamTableAvatarAndTitle\\n        ...TeamTableLaunchDate\\n        ...TeamTableMinimumBounty\\n        ...TeamTableAverageBounty\\n        ...BookmarkTeam\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n\\nfragment TeamTableResolvedReports on Team {\\n  id\\n  resolved_report_count\\n  __typename\\n}\\n\\nfragment TeamTableAvatarAndTitle on Team {\\n  id\\n  profile_picture(size: medium)\\n  name\\n  handle\\n  submission_state\\n  triage_active\\n  publicly_visible_retesting\\n  state\\n  allows_bounty_splitting\\n  external_program {\\n    id\\n    __typename\\n  }\\n  ...TeamLinkWithMiniProfile\\n  __typename\\n}\\n\\nfragment TeamLinkWithMiniProfile on Team {\\n  id\\n  handle\\n  name\\n  __typename\\n}\\n\\nfragment TeamTableLaunchDate on Team {\\n  id\\n  launched_at\\n  __typename\\n}\\n\\nfragment TeamTableMinimumBounty on Team {\\n  id\\n  currency\\n  base_bounty\\n  __typename\\n}\\n\\nfragment TeamTableAverageBounty on Team {\\n  id\\n  currency\\n  average_bounty_lower_amount\\n  average_bounty_upper_amount\\n  __typename\\n}\\n\\nfragment BookmarkTeam on Team {\\n  id\\n  bookmarked\\n  __typename\\n}\\n"}'''
                data = '''{"operationName":"DirectoryQuery","variables":{"where":{"_and":[{"structured_scopes":{"_and":[{"asset_type":{"_eq":"URL"}},{"is_archived":false}]}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"_not":{"external_program":{}}},{"_or":[{"_and":[{"state":{"_neq":"sandboxed"}},{"state":{"_neq":"soft_launched"}}]},{"external_program":{}}]}]},"first":25,"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {\\n  me {\\n    id\\n    edit_unclaimed_profiles\\n    h1_pentester\\n    __typename\\n  }\\n  teams(first: 25, after: $cursor, secure_order_by: $secureOrderBy, where: $where) {\\n    pageInfo {\\n      endCursor\\n      hasNextPage\\n      __typename\\n    }\\n    edges {\\n      node {\\n        id\\n        bookmarked\\n        ...TeamTableResolvedReports\\n        ...TeamTableAvatarAndTitle\\n        ...TeamTableLaunchDate\\n        ...TeamTableMinimumBounty\\n        ...TeamTableAverageBounty\\n        ...BookmarkTeam\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n\\nfragment TeamTableResolvedReports on Team {\\n  id\\n  resolved_report_count\\n  __typename\\n}\\n\\nfragment TeamTableAvatarAndTitle on Team {\\n  id\\n  profile_picture(size: medium)\\n  name\\n  handle\\n  submission_state\\n  triage_active\\n  publicly_visible_retesting\\n  state\\n  allows_bounty_splitting\\n  external_program {\\n    id\\n    __typename\\n  }\\n  ...TeamLinkWithMiniProfile\\n  __typename\\n}\\n\\nfragment TeamLinkWithMiniProfile on Team {\\n  id\\n  handle\\n  name\\n  __typename\\n}\\n\\nfragment TeamTableLaunchDate on Team {\\n  id\\n  launched_at\\n  __typename\\n}\\n\\nfragment TeamTableMinimumBounty on Team {\\n  id\\n  currency\\n  base_bounty\\n  __typename\\n}\\n\\nfragment TeamTableAverageBounty on Team {\\n  id\\n  currency\\n  average_bounty_lower_amount\\n  average_bounty_upper_amount\\n  __typename\\n}\\n\\nfragment BookmarkTeam on Team {\\n  id\\n  bookmarked\\n  __typename\\n}\\n"}'''
                r = requests.post(self.url, data=data, headers=self.auth_headers, verify=False,timeout=10)
                if r.json()["data"] == None:
                    # print(1)
                    message = f"H1-Token失效，请及时更新。"
                    logger.log('INFOR', "H1-Token失效，请及时更新。")
                    self.vuln_mng.send_message(message=message)
                    break
                cursor = jsonpath.jsonpath(r.json(), "$..endCursor")[0]
                edges_list = r.json()["data"]["teams"]["edges"]
                for i in range(0, len(edges_list)):
                    nodes = {}
                    node = r.json()["data"]["teams"]["edges"][i]['node']
                    nodes['program'] = node["handle"]
                    nodes['platform'] = "hackerone"
                    nodes['hackerone_private'] = "no"
                    nodes['launched_at'] = node["launched_at"]
                    nodes['base_bounty'] = node["base_bounty"]
                    nodes['average_bounty_lower_amount'] = node["average_bounty_lower_amount"]
                    nodes['average_bounty_upper_amount'] = node["average_bounty_upper_amount"]
                    nodes['resolved_report_count'] = node["resolved_report_count"]
                    nodes['submission_state'] = node["submission_state"]
                    all_programs.append(copy.deepcopy(nodes))
            except Exception as error:
                logger.log('INFOR', f'收集h1 program时出现异常 - {error}')
                logger.log('DEBUG', f'收集h1 program时出现异常 - {error}')
        len_all_programs = len(all_programs)
        logger.log('INFOR',str(len_all_programs) + " programs have been Collected")
        return all_programs

    ### 第二个循环请求用来抓取所有的private program
    def collecprivateprogram(self):
        logger.log('INFOR', "Start collecting h1 private programs")
        # 每页的Program数量被限制在25，所以cursor参数需要25*n，然后base64编码
        cursor = "MAo="
        all_programs = []
        while (type(cursor) == str):
            try:
                # data = '''{"operationName":"DirectoryQuery","variables":{"where":{"_and":[{"_or":[{"offers_bounties":{"_eq":true}},{"external_program":{"offers_rewards":{"_eq":true}}}]},{"structured_scopes":{"_and":[{"asset_type":{"_eq":"URL"}},{"is_archived":false}]}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"_not":{"external_program":{}}},{"_or":[{"_and":[{"state":{"_neq":"sandboxed"}},{"state":{"_neq":"soft_launched"}}]},{"external_program":{}}]}]},"first":25,"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {\\n  me {\\n    id\\n    edit_unclaimed_profiles\\n    h1_pentester\\n    __typename\\n  }\\n  teams(first: 25, after: $cursor, secure_order_by: $secureOrderBy, where: $where) {\\n    pageInfo {\\n      endCursor\\n      hasNextPage\\n      __typename\\n    }\\n    edges {\\n      node {\\n        id\\n        bookmarked\\n        ...TeamTableResolvedReports\\n        ...TeamTableAvatarAndTitle\\n        ...TeamTableLaunchDate\\n        ...TeamTableMinimumBounty\\n        ...TeamTableAverageBounty\\n        ...BookmarkTeam\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n\\nfragment TeamTableResolvedReports on Team {\\n  id\\n  resolved_report_count\\n  __typename\\n}\\n\\nfragment TeamTableAvatarAndTitle on Team {\\n  id\\n  profile_picture(size: medium)\\n  name\\n  handle\\n  submission_state\\n  triage_active\\n  publicly_visible_retesting\\n  state\\n  allows_bounty_splitting\\n  external_program {\\n    id\\n    __typename\\n  }\\n  ...TeamLinkWithMiniProfile\\n  __typename\\n}\\n\\nfragment TeamLinkWithMiniProfile on Team {\\n  id\\n  handle\\n  name\\n  __typename\\n}\\n\\nfragment TeamTableLaunchDate on Team {\\n  id\\n  launched_at\\n  __typename\\n}\\n\\nfragment TeamTableMinimumBounty on Team {\\n  id\\n  currency\\n  base_bounty\\n  __typename\\n}\\n\\nfragment TeamTableAverageBounty on Team {\\n  id\\n  currency\\n  average_bounty_lower_amount\\n  average_bounty_upper_amount\\n  __typename\\n}\\n\\nfragment BookmarkTeam on Team {\\n  id\\n  bookmarked\\n  __typename\\n}\\n"}'''
                # data = '''{"operationName":"DirectoryQuery","variables":{"where":{"_and":[{"_or":[{"structured_scopes":{"_and":[{"asset_type":{"_eq":"URL"}},{"is_archived":false}]}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"_not":{"external_program":{}}},{"_or":[{"_and":[{"state":{"_neq":"sandboxed"}},{"state":{"_neq":"soft_launched"}}]},{"external_program":{}}]}]},"first":25,"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DirectoryQuery($cursor: String, $secureOrderBy: FiltersTeamFilterOrder, $where: FiltersTeamFilterInput) {\\n  me {\\n    id\\n    edit_unclaimed_profiles\\n    h1_pentester\\n    __typename\\n  }\\n  teams(first: 25, after: $cursor, secure_order_by: $secureOrderBy, where: $where) {\\n    pageInfo {\\n      endCursor\\n      hasNextPage\\n      __typename\\n    }\\n    edges {\\n      node {\\n        id\\n        bookmarked\\n        ...TeamTableResolvedReports\\n        ...TeamTableAvatarAndTitle\\n        ...TeamTableLaunchDate\\n        ...TeamTableMinimumBounty\\n        ...TeamTableAverageBounty\\n        ...BookmarkTeam\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n\\nfragment TeamTableResolvedReports on Team {\\n  id\\n  resolved_report_count\\n  __typename\\n}\\n\\nfragment TeamTableAvatarAndTitle on Team {\\n  id\\n  profile_picture(size: medium)\\n  name\\n  handle\\n  submission_state\\n  triage_active\\n  publicly_visible_retesting\\n  state\\n  allows_bounty_splitting\\n  external_program {\\n    id\\n    __typename\\n  }\\n  ...TeamLinkWithMiniProfile\\n  __typename\\n}\\n\\nfragment TeamLinkWithMiniProfile on Team {\\n  id\\n  handle\\n  name\\n  __typename\\n}\\n\\nfragment TeamTableLaunchDate on Team {\\n  id\\n  launched_at\\n  __typename\\n}\\n\\nfragment TeamTableMinimumBounty on Team {\\n  id\\n  currency\\n  base_bounty\\n  __typename\\n}\\n\\nfragment TeamTableAverageBounty on Team {\\n  id\\n  currency\\n  average_bounty_lower_amount\\n  average_bounty_upper_amount\\n  __typename\\n}\\n\\nfragment BookmarkTeam on Team {\\n  id\\n  bookmarked\\n  __typename\\n}\\n"}'''
                data = '''{"operationName":"DiscoveryQuery","variables":{"where":{"_and":[{"_not":{"user_opportunities_feedbacks":{"likes_team":false}}},{"_or":[{"whitelisted_hackers":{"is_me":true}},{"reporters":{"is_me":true}}]},{"type":{"_neq":"Assessment"}},{"_or":[{"submission_state":{"_eq":"open"}},{"submission_state":{"_eq":"api_only"}},{"external_program":{}}]},{"state":{"_eq":"soft_launched"}}]},"secureOrderBy":{"launched_at":{"_direction":"DESC"}},"cursor":"''' + cursor + '''"},"query":"query DiscoveryQuery($cursor: String, $where: FiltersTeamFilterInput, $secureOrderBy: FiltersTeamFilterOrder) {  me {    id    ...OpportunityListMe    __typename  }  teams(first: 24, where: $where, after: $cursor, secure_order_by: $secureOrderBy) {    pageInfo {      endCursor      hasNextPage      __typename    }    ...SearchSummaryTeamConnection    ...OpportunityListTeamConnection    __typename  }}fragment OpportunityListTeamConnection on TeamConnection {  edges {    node {      id      ...OpportunityCardTeam      __typename    }    __typename  }  __typename}fragment OpportunityCardTeam on Team {  _id  id  name  handle  profile_picture(size: small)  triage_active  publicly_visible_retesting  allows_private_disclosure  allows_bounty_splitting  launched_at  state  offers_bounties  external_program {    id    __typename  }  last_updated_at  currency  type  minimum_bounty_table_value  maximum_bounty_table_value  response_efficiency_percentage  first_response_time  ...ResponseEfficiencyIndicator  ...BookmarkTeam  ...ScopeTeam  team_display_options {    id    show_response_efficiency_indicator    __typename  }  user_feedback {    id    likes_team    __typename  }  __typename}fragment ResponseEfficiencyIndicator on Team {  id  response_efficiency_percentage  __typename}fragment BookmarkTeam on Team {  id  bookmarked  __typename}fragment ScopeTeam on Team {  id  structured_scope_stats  __typename}fragment OpportunityListMe on User {  id  ...OpportunityCardMe  __typename}fragment OpportunityCardMe on User {  id  ...BookmarkMe  __typename}fragment BookmarkMe on User {  id  __typename}fragment SearchSummaryTeamConnection on TeamConnection {  total_count  __typename}"}'''
                r = requests.post(self.url, data=data, headers=self.auth_headers, verify=False, timeout=10)
                if r.text == "" or "STANDARD_ERROR" in r.text or "Invalid CSRF token" in r.text or 'me":null' in r.text:
                    message = f"H1-Token失效，请及时更新。"
                    logger.log('INFOR', "H1-Token失效，请及时更新。")
                    self.vuln_mng.send_message(message=message)
                    break
                cursor = jsonpath.jsonpath(r.json(), "$..endCursor")[0]
                edges_list = r.json()["data"]["teams"]["edges"]
                for i in range(0, len(edges_list)):
                    nodes = {}
                    node = r.json()["data"]["teams"]["edges"][i]['node']
                    nodes['program'] = node["handle"]
                    nodes['platform'] = "hackerone"
                    nodes['hackerone_private'] = "yes"
                    nodes['launched_at'] = node["launched_at"]
                    nodes['base_bounty'] = "100"
                    nodes['average_bounty_lower_amount'] = node["minimum_bounty_table_value"]
                    nodes['average_bounty_upper_amount'] = node["maximum_bounty_table_value"]
                    nodes['resolved_report_count'] = "100"
                    nodes['submission_state'] = "open"
                    # print(nodes)
                    all_programs.append(copy.deepcopy(nodes))
            except Exception as error:
                logger.log('DEBUG', f'收集h1 private program时出现异常 - {error}')
        len_all_programs = len(all_programs)
        logger.log('INFOR', str(len_all_programs) + " private programs have been Collected")
        return all_programs

    def searchallprogramdomain(self):
        query = {'query': {'match_all': {}}}
        res = self.es_helper.query_domains_by_dsl(self.index,dsl=query)
        domain_list = []
        if res:
            for each in res:
                domain_list.append(each['_source']['domain'].lower())
        return domain_list

    def collectprogramdomain(self,all_programs_domains):
        logger.log('INFOR',"Start collecting h1 domains")
        ### 第二个循环请求用来抓取每个Program的Domain
        domain_list = {}
        for i in range(0, len(all_programs_domains)):
            single_program = all_programs_domains[i]['program']
            data = '''{"operationName":"TeamAssets","variables":{"handle":"''' + single_program + '''"},"query":"query TeamAssets($handle: String!) {\\n  me {\\n    id\\n    membership(team_handle: $handle) {\\n      id\\n      permissions\\n      __typename\\n    }\\n    __typename\\n  }\\n  team(handle: $handle) {\\n    id\\n    handle\\n    structured_scope_versions(archived: false) {\\n      max_updated_at\\n      __typename\\n    }\\n    in_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: true) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          max_severity\\n          eligible_for_bounty\\n          labels(first: 100) {\\n            edges {\\n              node {\\n                id\\n                name\\n                __typename\\n              }\\n              __typename\\n            }\\n            __typename\\n          }\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    out_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: false) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n"}'''
            try:
                r = requests.post(self.url, data=data, headers=self.auth_headers, verify=False,timeout=10)
                edges_list = r.json()["data"]["team"]["in_scope_assets"]["edges"]
                domain_list = {}
                for j in range(0, len(edges_list)):
                    single_node = r.json()["data"]["team"]["in_scope_assets"]["edges"][j]["node"]
                    single_asset_type = single_node["asset_type"]
                    single_asset_eligible_for_bounty = single_node["eligible_for_bounty"]
                    single_asset_identifier = single_node["asset_identifier"].lower()
                    single_asset_max_severity = single_node["max_severity"]
                    if ("*" in single_asset_identifier and not single_asset_identifier.startswith(
                            "*.")) or "(" in single_asset_identifier:
                        pass
                    else:
                        if single_asset_eligible_for_bounty==True and single_asset_type=='URL':
                            if single_asset_identifier not in self.black_pdomain:
                                all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                all_programs_domains[i]["domain"] = single_asset_identifier
                                all_programs_domains[i]["offer_bounty"] = "yes"
                                all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
                        if single_asset_eligible_for_bounty==False and single_asset_type=='URL':
                            if single_asset_identifier not in self.black_pdomain:
                                all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                all_programs_domains[i]["domain"] = single_asset_identifier
                                all_programs_domains[i]["offer_bounty"] = "no"
                                all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
            except Exception as error:
                logger.log('BEBUG',f'收集h1 pdomain时出现异常 - {error}')
            logger.log('INFOR',"Collected  " + str(len(domain_list)) + " In Scope domains of [" + single_program + "] on Hackerone")
        logger.log('INFOR',"Finished")
        return all_programs_domains

    def collectnewprogramdomain(self,all_programs_domains):
        logger.log('INFOR',"Start collecting h1 new domains")
        domain_old_list = self.searchallprogramdomain()
        ### 第二个循环请求用来抓取每个Program的Domain
        for i in range(0, len(all_programs_domains)):
            single_program = all_programs_domains[i]['program']
            # print(single_program)
            data = '''{"operationName":"TeamAssets","variables":{"handle":"''' + single_program + '''"},"query":"query TeamAssets($handle: String!) {\\n  me {\\n    id\\n    membership(team_handle: $handle) {\\n      id\\n      permissions\\n      __typename\\n    }\\n    __typename\\n  }\\n  team(handle: $handle) {\\n    id\\n    handle\\n    structured_scope_versions(archived: false) {\\n      max_updated_at\\n      __typename\\n    }\\n    in_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: true) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          max_severity\\n          eligible_for_bounty\\n          labels(first: 100) {\\n            edges {\\n              node {\\n                id\\n                name\\n                __typename\\n              }\\n              __typename\\n            }\\n            __typename\\n          }\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    out_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: false) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n"}'''
            try:
                r = requests.post(self.url, data=data, headers=self.auth_headers, verify=False,timeout=10)
                edges_list = r.json()["data"]["team"]["in_scope_assets"]["edges"]
                domain_list = {}
                for j in range(0, len(edges_list)):
                    single_node = r.json()["data"]["team"]["in_scope_assets"]["edges"][j]["node"]
                    single_asset_type = single_node["asset_type"]
                    single_asset_eligible_for_bounty = single_node["eligible_for_bounty"]
                    single_asset_identifier = single_node["asset_identifier"].lower()
                    single_asset_max_severity = single_node["max_severity"]
                    if single_asset_identifier not in domain_old_list:
                        if ("*" in single_asset_identifier and not single_asset_identifier.startswith("*.")) or "(" in single_asset_identifier:
                            pass
                        else:
                            if single_asset_eligible_for_bounty==True and single_asset_type=='URL':
                                if single_asset_identifier not in self.black_pdomain:
                                    all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                    all_programs_domains[i]["domain"] = single_asset_identifier.lower()
                                    all_programs_domains[i]["offer_bounty"] = "yes"
                                    all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                    logger.log('INFOR',"Program  [" + single_program + "] add new domain " + single_asset_identifier)
                                    self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
                            # open and no reward domain will not be scanned
                            if single_asset_eligible_for_bounty==False and single_asset_type=='URL':
                                if single_asset_identifier not in self.black_pdomain:
                                    all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                    all_programs_domains[i]["domain"] = single_asset_identifier.lower()
                                    all_programs_domains[i]["offer_bounty"] = "no"
                                    all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                    logger.log('INFOR',"Program  [" + single_program + "] add new domain " + single_asset_identifier)
                                    self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
            except Exception as error:
                logger.log('DEBUG',f'收集h1 new pdomain时出现异常 - {error}')
        logger.log('INFOR',"Finished")

    def collectnewprivateprogramdomain(self,all_programs_domains):
        logger.log('INFOR',"Start collecting h1 new domains")
        domain_old_list = self.searchallprogramdomain()
        ### 第二个循环请求用来抓取每个Program的Domain
        for i in range(0, len(all_programs_domains)):
            single_program = all_programs_domains[i]['program']
            data = '''{"operationName":"TeamAssets","variables":{"handle":"''' + single_program + '''"},"query":"query TeamAssets($handle: String!) {\\n  me {\\n    id\\n    membership(team_handle: $handle) {\\n      id\\n      permissions\\n      __typename\\n    }\\n    __typename\\n  }\\n  team(handle: $handle) {\\n    id\\n    handle\\n    structured_scope_versions(archived: false) {\\n      max_updated_at\\n      __typename\\n    }\\n    in_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: true) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          max_severity\\n          eligible_for_bounty\\n          labels(first: 100) {\\n            edges {\\n              node {\\n                id\\n                name\\n                __typename\\n              }\\n              __typename\\n            }\\n            __typename\\n          }\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    out_scope_assets: structured_scopes(first: 650, archived: false, eligible_for_submission: false) {\\n      edges {\\n        node {\\n          id\\n          asset_type\\n          asset_identifier\\n          instruction\\n          __typename\\n        }\\n        __typename\\n      }\\n      __typename\\n    }\\n    __typename\\n  }\\n}\\n"}'''
            try:
                r = requests.post(self.url, data=data, headers=self.auth_headers, verify=False,timeout=10)
                if "INVALID_CREDENTIALS" in str(r.json()):
                    break
                edges_list = r.json()["data"]["team"]["in_scope_assets"]["edges"]
                domain_list = {}
                for j in range(0, len(edges_list)):
                    single_node = r.json()["data"]["team"]["in_scope_assets"]["edges"][j]["node"]
                    single_asset_type = single_node["asset_type"]
                    single_asset_eligible_for_bounty = single_node["eligible_for_bounty"]
                    single_asset_identifier = single_node["asset_identifier"].lower()
                    single_asset_max_severity = single_node["max_severity"]
                    if single_asset_identifier not in domain_old_list:
                        if ("*" in single_asset_identifier and not single_asset_identifier.startswith("*.")) or "(" in single_asset_identifier:
                            pass
                        else:
                            if single_asset_eligible_for_bounty==True and single_asset_type=='URL':
                                if single_asset_identifier not in self.black_pdomain:
                                    all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                    all_programs_domains[i]["domain"] = single_asset_identifier.lower()
                                    all_programs_domains[i]["offer_bounty"] = "yes"
                                    all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                    logger.log('INFOR',"Program  [" + single_program + "] add new domain " + single_asset_identifier)
                                    self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
                            if single_asset_eligible_for_bounty==False and single_asset_type=='URL':
                                if single_asset_identifier not in self.black_pdomain:
                                    all_programs_domains[i]["max_severity"] = single_asset_max_severity
                                    all_programs_domains[i]["domain"] = single_asset_identifier.lower()
                                    all_programs_domains[i]["offer_bounty"] = "no"
                                    all_programs_domains[i]["update_time"] = datetime.datetime.now()
                                    logger.log('INFOR',"Program  [" + single_program + "] add new domain " + single_asset_identifier)
                                    self.es_helper.insert_one_doc(self.index,all_programs_domains[i])
            except Exception as error:
                logger.log('DEBUG',f'收集h1 new pdomain时出现异常 - {error}')
        logger.log('INFOR',"Finished")

    def update_hackerone_private(self, program):
        dsl = {
                "query": {
                "bool": {
                        "must":
                            {"match": {"program": str(program)}}

                    }
            },
            "script": {
            "lang": "painless",
            "source": "ctx._source.hackerone_private= 'no'"
              }
            }
        self.es_helper.update_by_query(index="program-assets-1",dsl=dsl)

def main():
    pass
    # x1 = CollectH1Domain()
    # res = x1.collecprivateprogram()
    '''
    all_programs_domains = x1.collecprogram()
    for i in range(0, len(all_programs_domains)):
        single_program = all_programs_domains[i]['program']
        print(single_program)
        x1.update_hackerone_private(program=str(single_program))
    '''
    # 入库 ES
    # x1.collectnewprogramdomain(all_programs)


if __name__ == "__main__":
    main()
