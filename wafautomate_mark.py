#-*- encoding:utf-8 -*-
import os
import json
import sys
import time

# Global Variable
_SRC_REGION = ''
_DST_REGION = ''
_SRC_SCOPE = ''
_DST_SCOPE = ''
_RULEGROUP_ARN_DICT = {}
_REGEX_ARN_DICT = {}
_IPSET_ARN_DIC= {}


# Rule temporary JSON file
if not os.path.exists("./json_file"):
	os.makedirs("./json_file")

# Function: Updated reference resource ARN
# Example ARN: arn:aws:wafv2:ap-northeast-1:123456789:regional/ipset/testip2/a1112334-8e07-4279-b7eb-a881224sdf
def update_ARN(Rules):
	for key in _REGEX_ARN_DICT:
		Rules = json.loads(json.dumps(Rules).replace(key, _REGEX_ARN_DICT[key]))
	for key in _RULEGROUP_ARN_DICT:
		Rules = json.loads(json.dumps(Rules).replace(key, _RULEGROUP_ARN_DICT[key]))
	for key in _IPSET_ARN_DIC:
		Rules = json.loads(json.dumps(Rules).replace(key, _IPSET_ARN_DIC[key]))
	# print(Rules)
	return Rules

# Function: Clone IPSets
def create_ipset():

	global _IPSET_ARN_DIC

	command_get_ipset_list = "aws wafv2 list-ip-sets --scope %s --output json --region %s" % (_SRC_SCOPE,_SRC_REGION)
	ipsets = os.popen(command_get_ipset_list)
	ipsets_list = json.loads(ipsets.read())
	print("-----Clone IPSets....-----")
	for i in ipsets_list["IPSets"]:
		command_get_ipset = "aws wafv2 get-ip-set --scope %s --region %s --output json --name %s --id %s"%(_SRC_SCOPE,_SRC_REGION,i["Name"],i["Id"])
		d_ipset = os.popen(command_get_ipset)
		des_ipset = json.loads(d_ipset.read())
		Description = des_ipset["IPSet"]["Description"]
		Name = des_ipset["IPSet"]["Name"]
		ARN = des_ipset["IPSet"]["ARN"]
		IPVestion = des_ipset["IPSet"]["IPAddressVersion"]
		IPs = ""
		for ip in des_ipset["IPSet"]["Addresses"]:
			IPs = IPs + "\"" +ip + "\"" + " "
		if not Description:
			create_ipset = """aws wafv2 create-ip-set --region %s --output json --scope %s --name %s --ip-address-version %s --addresses %s """ % (
				_DST_REGION, _DST_SCOPE, Name, IPVestion, IPs)
		else:
			create_ipset = """aws wafv2 create-ip-set --region %s --output json --scope %s --description %s --name %s --ip-address-version %s --addresses %s """ % (
				_DST_REGION, _DST_SCOPE, Description, Name, IPVestion, IPs)
		print(create_ipset)
		res = os.popen(create_ipset)
		res_list = json.loads(res.read())
		print(res_list)
		# Add into dict
		_IPSET_ARN_DIC[ARN] = res_list["Summary"]["ARN"]


# Function: Clone Regex patten sets
def create_regex():
	global _REGEX_ARN_DICT

	command_get_regex_list = "aws wafv2 list-regex-pattern-sets --scope %s --region %s --output json"%(_SRC_SCOPE, _SRC_REGION)
	acl = os.popen(command_get_regex_list)
	acl_list = json.loads(acl.read())
	print("-----Clone Regex patten sets.....-----")
	for i in acl_list["RegexPatternSets"]:
		command_get_regex = "aws wafv2 get-regex-pattern-set --scope %s --region %s --output json --name %s --id %s"%(_SRC_SCOPE, _SRC_REGION,i["Name"],i["Id"])
		d_regex = os.popen(command_get_regex)
		des_regex = json.loads(d_regex.read())
		Description = des_regex["RegexPatternSet"]["Description"]
		Name = des_regex["RegexPatternSet"]["Name"]
		ARN = des_regex["RegexPatternSet"]["ARN"]
		RegexString = des_regex["RegexPatternSet"]["RegularExpressionList"]
		if not Description:
			create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope %s --name %s 
			--regular-expression-list '%s'""" % (
				_DST_REGION,_DST_SCOPE, Name, json.dumps(RegexString))
		else:
			create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope %s --description %s 
			--name %s --regular-expression-list '%s'""" % (
				_DST_REGION,_DST_SCOPE, Description, Name, json.dumps(RegexString))
		# create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope REGIONAL --description %s --name %s --regular-expression-list '[{"RegexString": %s}]'"""%(_DST_REGION,Description,Name,json.dumps(RegexString))
		print(create_regex)
		res = os.popen(create_regex)
		res_list = json.loads(res.read())
		print(res_list)
		# Add into dict
		_REGEX_ARN_DICT[ARN] = res_list["Summary"]["ARN"]


# Function: Clone rule groups
def create_rule_group():
	global _RULEGROUP_ARN_DICT

	command_get_rule_groups_list = "aws wafv2 list-rule-groups --scope %s --output json --region %s"%(_SRC_SCOPE,_SRC_REGION)
	rule_groups = os.popen(command_get_rule_groups_list)
	rule_groups_list = json.loads(rule_groups.read())
	print("-----Clone rule groups....-----")
	for i in rule_groups_list["RuleGroups"]:
		Name = i["Name"]
		Id = i["Id"]
		command_get_rule = "aws wafv2 get-rule-group --scope %s --region %s --output json --name %s --id %s"%(_SRC_SCOPE,_SRC_REGION,Name,Id)
		des_rule = os.popen(command_get_rule)
		# print(des_rule.read())
		rule_group = json.loads(des_rule.read())["RuleGroup"]
		#print(rule_group)
		Name = rule_group["Name"]
		Description = rule_group["Description"]
		ARN = rule_group["ARN"]
		Capacity = rule_group["Capacity"]
		#rules_json = rule_group["Rules"][0]
		rules_json = rule_group["Rules"]
		#print(rules_json)
		rules_json = update_ARN(rules_json)
		# print(rules_json)
		file = open("./json_file/%s.json"%Name,"w",encoding="utf-8")
		file.write(json.dumps(rules_json))
		file.close()
		if not Description:
			create_rule_group_cli = """aws wafv2 create-rule-group --name %s --scope %s --capacity %s --rules file://./json_file/%s.json --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=%s --output json --region %s"""%(Name, _DST_SCOPE,str(Capacity),Name,Name,_DST_REGION)
		else:
			create_rule_group_cli = """aws wafv2 create-rule-group --name %s --scope %s --capacity %s --description %s --rules file://./json_file/%s.json --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=%s --output json --region %s""" % (Name, _DST_SCOPE, str(Capacity), Description, Name,Name, _DST_REGION)
		print(create_rule_group_cli)
		res = os.popen(create_rule_group_cli)
		res_list = json.loads(res.read())
		print(res_list)
		# Add into dict
		_RULEGROUP_ARN_DICT[ARN] = res_list["Summary"]["ARN"]

# Function: Clone WebACLs
def create_web_acl():
	print("----Clone WebACLs....-----")
	command_get_web_acl_list = "aws wafv2 list-web-acls --scope %s --output json --region %s" % (_SRC_SCOPE,_SRC_REGION)
	web_acls = os.popen(command_get_web_acl_list)
	web_acls_list = json.loads(web_acls.read())
	for i in web_acls_list["WebACLs"]:
		Name = i["Name"]
		Id = i["Id"]

		command_get_web_acl = "aws wafv2 get-web-acl --scope %s --name %s --id %s --output json --region %s"%(_SRC_SCOPE,Name,Id,_SRC_REGION)
		web_acl = os.popen(command_get_web_acl)
		web_acl_res = json.loads(web_acl.read())
		waf_description = web_acl_res["WebACL"]["Description"]
		waf_json = web_acl_res["WebACL"]["Rules"]
		waf_json = update_ARN(waf_json)
		file = open("./json_file/%s.json"%Name,"w",encoding="utf-8")
		file.write(json.dumps(waf_json))
		file.close()
		if not waf_description:
			create_web_acl_cli = """aws wafv2 create-web-acl --name %s --scope %s --default-action Allow={} --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=%s --rules file://./json_file/%s.json --region %s --output json""" % (
			Name,_DST_SCOPE, Name, Name, _DST_REGION)
		else:
			create_web_acl_cli = """aws wafv2 create-web-acl --name %s --scope %s --description %s --default-action Allow={} --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=%s --rules file://./json_file/%s.json --region %s --output json""" % (
			Name,_DST_SCOPE,waf_description, Name,Name, _DST_REGION)
		print(create_web_acl_cli)
		res = os.popen(create_web_acl_cli)
		res_list = json.loads(res.read())
		print(res_list)


if len(sys.argv) < 5:
	print("Error: Missing AWS region paremeter"  )
	print("Usage: ./python3 wafv2_clone.py [Source AWS Region] [Source Scope] [Destination AWS Region] [Destination Scope]")
	print("Example: ./python3 wafv2_clone.py ap-southeast-1 REGIONAL us-west-2 REGIONAL")
	print("Example: ./python3 wafv2_clone.py ap-southeast-1 REGIONAL us-east-1 CLOUDFRONT")
	sys.exit(1)

_SRC_REGION = str(sys.argv[1])
_SRC_SCOPE = str(sys.argv[2])
_DST_REGION = str(sys.argv[3])
_DST_SCOPE = str(sys.argv[4])

print("-----Start WAF Clone from [ %s %s ] to [ %s %s ]-----" % (_SRC_REGION,_SRC_SCOPE,_DST_REGION, _DST_SCOPE))
create_ipset()
create_regex()
create_rule_group()
create_web_acl()
