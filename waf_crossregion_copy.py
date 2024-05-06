import os
import json
import boto3
import time
import uuid
import sys
from botocore.exceptions import ClientError
import pprint


def banner():
    text = "WAF CROSS REGION COPY SCRIPT START"
    width = 52  # 设置总宽度为 30 个字符

    banner = f""" 
    {'*' * width}
    {f'*  {text.center(width - 4, " ")}  *'}
    {'*' * width}
    """
    print(banner)


def validate_scope_region(pairs):
    for scope, region in pairs.items():
        if scope == "CLOUDFRONT" and region != "us-east-1":
            print('scope CLOUDFRONT must use region us-east-1, please adjust your input')
            sys.exit(1)
        else:
            continue
    return


def preprocess_dict(d):
    """
    :param d:字典对象
    :return:将其中的bytes类数据转换成string
    原因是，从boto3 wafv2 api导出的waf 配置，如果有匹配字符的条目，会使用bytes类数据体现，
    使用json.dump转化时会报错。因此使用函数对其中的bytes对象转化成str

    """
    if isinstance(d, dict):
        return {k: preprocess_dict(v) if isinstance(v, dict) else v.decode('utf-8') if isinstance(v, bytes) else v
                for k, v in d.items()}
    elif isinstance(d, list):
        return [preprocess_dict(v) for v in d]
    else:
        return d


# Function: Updated reference resource ARN
# Example ARN: arn:aws:wafv2:ap-northeast-1:123456789:regional/ipset/testip2/a1112334-8e07-4279-b7eb-a881224sdf
# def update_ARN(Rules):
#     """
#     :param Rules: 字典
#     :return: 字典
#
#     基于几个global变量中存储的ARN 键-值对，替换源waf acl的json配置中使用的资源的ARN为目的waf acl的region中新创建的对应资源的ARN
#     global 变量的ARN键值对的格式是
#     "源资源ARN"："目的资源ARN"
#
#     """
#     global REGEXSETARN
#     global RULEGROUPARN
#     global IPSETARN
#     for key in REGEXSETARN:
#         Rules = json.loads(json.dumps(Rules).replace(key, REGEXSETARN[key]))
#     for key in RULEGROUPARN:
#         Rules = json.loads(json.dumps(Rules).replace(key, RULEGROUPARN[key]))
#     for key in IPSETARN:
#         Rules = json.loads(json.dumps(Rules).replace(key, IPSETARN[key]))
#
#     return Rules

def update_ARN(Rules):
    """
    :param Rules: 字典
    :return: 字典

    基于几个global变量中存储的ARN 键-值对，替换源waf acl的json配置中使用的资源的ARN为目的waf acl的region中新创建的对应资源的ARN
    global 变量的ARN键值对的格式是
    "源资源ARN"："目的资源ARN"

    """
    global REGEXSETARN
    global RULEGROUPARN
    global IPSETARN
    for i in range(len(Rules)):
        rule = Rules[i]
        statement = rule['Statement']
        if 'IPSetReferenceStatement' in statement:
            src_ipset_arn = statement['IPSetReferenceStatement']['ARN']

            if src_ipset_arn in IPSETARN:
                dst_ipset_arn = IPSETARN[src_ipset_arn]
                Rules[i]['Statement']['IPSetReferenceStatement']['ARN'] = dst_ipset_arn
            else:
                continue
        if 'RuleGroupReferenceStatement' in statement:
            src_rule_group_arn = statement['RuleGroupReferenceStatement']['ARN']

            if src_rule_group_arn in RULEGROUPARN:
                dst_rule_group_arn = RULEGROUPARN[src_rule_group_arn]
                Rules[i]['Statement']['RuleGroupReferenceStatement']['ARN'] = dst_rule_group_arn
            else:
                continue
        if 'RegexPatternSetReferenceStatement' in statement:
            src_regex_arn = statement['RegexPatternSetReferenceStatement']['ARN']

            if src_regex_arn in REGEXSETARN:
                dst_regex_arn = REGEXSETARN[src_regex_arn]
                Rules[i]['Statement']['RegexPatternSetReferenceStatement']['ARN'] = dst_regex_arn
            else:
                continue

    return Rules


def modify_rules(src_scope, dst_scope, rules):
    """
    :param src_scope:
    :param dst_scope:
    :param rules:
    :return: rules

    此函数的目的是解决ATP和ACFP规则组只支持在cloudfront 的webacl上配置response inspection
    如果从cloudfront webacl 迁移到regional acl，如果有response inspection会报错
    因此在该场景下，去掉response inspection


    如果是从regional 拷贝到cloudfront，由于response inspection是必选参数，默认补充response inspection
    temp_res_inspection = {"StatusCode": {"SuccessCodes": [200], "FailureCodes": [401]}}
    """

    if src_scope == 'CLOUDFRONT' and dst_scope == 'REGIONAL':
        for i in range(len(rules)):
            if rules[i]['Name'] == 'AWS-AWSManagedRulesACFPRuleSet':
                managed_rule_group_configs = rules[i]['Statement']['ManagedRuleGroupStatement'][
                    'ManagedRuleGroupConfigs']
                for config in managed_rule_group_configs:
                    if 'AWSManagedRulesACFPRuleSet' in config:
                        config['AWSManagedRulesACFPRuleSet'].pop('ResponseInspection', None)

            if rules[i]['Name'] == 'AWS-AWSManagedRulesATPRuleSet':
                managed_rule_group_configs = rules[i]['Statement']['ManagedRuleGroupStatement'][
                    'ManagedRuleGroupConfigs']
                for config in managed_rule_group_configs:
                    if 'AWSManagedRulesATPRuleSet' in config:
                        config['AWSManagedRulesATPRuleSet'].pop('ResponseInspection', None)

    if src_scope == 'REGIONAL' and dst_scope == 'CLOUDFRONT':
        temp_res_inspection = {"StatusCode": {"SuccessCodes": [200], "FailureCodes": [401]}}
        for i in range(len(rules)):
            if rules[i]['Name'] == 'AWS-AWSManagedRulesACFPRuleSet':
                managed_rule_group_configs = rules[i]['Statement']['ManagedRuleGroupStatement'][
                    'ManagedRuleGroupConfigs']
                for config in managed_rule_group_configs:
                    if 'AWSManagedRulesACFPRuleSet' in config:
                        config['AWSManagedRulesACFPRuleSet']['ResponseInspection'] = temp_res_inspection

            if rules[i]['Name'] == 'AWS-AWSManagedRulesATPRuleSet':
                managed_rule_group_configs = rules[i]['Statement']['ManagedRuleGroupStatement'][
                    'ManagedRuleGroupConfigs']
                for config in managed_rule_group_configs:
                    if 'AWSManagedRulesATPRuleSet' in config:
                        config['AWSManagedRulesATPRuleSet']['ResponseInspection'] = temp_res_inspection

    return rules


def save_config_to_local(name, unique_id, wafconfig):
    """
    将获取的配置保存在本地一份，用于备份和比对，或者回退
    这里的unique——id，在每次执行脚本时生成，用于区别每次运行并区分每次获取的配置

    :param name: str
    :param unique_id: str
    :param wafconfig: dict
    :return:

    """
    filename = name + '_' + unique_id
    file = open("./json_file/%s.json" % filename, "w", encoding="utf-8")
    file.write(json.dumps(wafconfig))
    file.close()


def get_src_webacl_info(scope, webaclname):
    global src_waf_client
    global unique_id
    ipset = {}
    regset = {}
    rulegroup = {}
    webacl_info = {}
    aclid = ''
    response = src_waf_client.list_web_acls(
        Scope=scope
    )
    # get webacl Id
    for i in response["WebACLs"]:
        if i["Name"] == webaclname:
            aclid = i['Id']
            webacl_info['web_acl_name'] = {i["Name"]: aclid}
            break
    if aclid == '':
        print("ERROR! Web ACL name not exist, please check your input")
        sys.exit(1)
    web_acl_res = src_waf_client.get_web_acl(
        Scope=scope,
        Name=webaclname,
        Id=aclid
    )
    web_acl_details = web_acl_res['WebACL']
    rules = web_acl_details['Rules']
    rules = preprocess_dict(rules)
    web_acl_details['Rules'] = rules
    # formated_waf_acl=preprocess_dict(web_acl_details)
    # save config to local for backup and compare
    # save_config_to_local(webaclname,unique_id,formated_waf_acl)

    print('-----------Finding custom resources that used in Web ACL------------')
    for item in rules:
        statement = item['Statement']
        if 'IPSetReferenceStatement' in statement:
            ip_set_name, ip_set_id = statement['IPSetReferenceStatement']['ARN'].split('/')[-2:]
            if ip_set_name in ipset:
                continue
            else:
                print('IPSET:Name: %s, ID: %s ' % (ip_set_name, ip_set_id))
                ipset[ip_set_name] = ip_set_id
        if 'RuleGroupReferenceStatement' in statement:
            rule_group_name, rule_group_id = statement['RuleGroupReferenceStatement']['ARN'].split('/')[-2:]
            if rule_group_name in rulegroup:
                continue
            else:
                print('RULEGROUP:Name: %s, ID: %s ' % (rule_group_name, rule_group_id))
                rulegroup[rule_group_name] = [statement['RuleGroupReferenceStatement']['ARN'], rule_group_id]
        if 'RegexPatternSetReferenceStatement' in statement:
            regex_set_name, regex_set_id = statement['RegexPatternSetReferenceStatement']['ARN'].split('/')[-2:]
            if regex_set_name in regset:
                continue
            else:
                print('REGSET:Name: %s, ID: %s ' % (regex_set_name, regex_set_id))
                regset[regex_set_name] = regex_set_id

    webacl_info['ip_set'] = ipset
    webacl_info['rule_group'] = rulegroup
    webacl_info['regex_set'] = regset
    print('-----------get following info about the given web acl-----------')
    return webacl_info


def create_ipset_func(ip_set_info, src_scope, dst_scope):
    global src_waf_client
    global dst_waf_client

    ip_set_arn_output = {}

    print('-------------creating ipsets into target region : (%s) ----------------' % (dst_region))

    for ip_set in ip_set_info:
        # 获取需要创建的ipset的名字
        ip_set_name = ip_set
        ip_set_id = ip_set_info[ip_set_name]

        # 通过名字get配置
        src_ipset = src_waf_client.get_ip_set(
            Name=ip_set_name,
            Scope=src_scope,
            Id=ip_set_id

        )
        ipset = src_ipset["IPSet"]

        # 如果有重名会报错，这里后面加了toolcreated作为标识，防止重名。但是ipset名字最大128字符，超过也会报错，需要注意和后续优化
        Name = ipset["Name"] + '-toolcreated'
        ARN = ipset["ARN"]
        IPVestion = ipset["IPAddressVersion"]
        addresses = ipset['Addresses']
        option_params = {}
        if 'Description' in ipset:
            option_params['Description'] = ipset['Description']

        print('creating ipset ' + Name)
        try:
            dst_ipset = dst_waf_client.create_ip_set(
                Name=Name,
                Scope=dst_scope,
                IPAddressVersion=IPVestion,
                **option_params,
                Addresses=addresses
            )
            print('success create ipset ' + dst_ipset['Summary']['Name'])
            # Add into dict
            # 将创建好的资源的ARN和原先资源的ARN记录下来，用于在创建web acl时，替换源web acl的json配置中的arn部分。
            ip_set_arn_output[ARN] = dst_ipset["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建ipset时发生错误: {e}")
            exit(1)

    return ip_set_arn_output


def create_regex_func(regex_set_info, src_scope, dst_scope):
    global src_waf_client
    global dst_waf_client

    regex_arn_output = {}

    print('-------------creating regex set into target regions : (%s) ----------------' % (dst_region))
    for regex_set in regex_set_info:
        regex_set_name = regex_set
        regex_set_id = regex_set_info[regex_set_name]

        src_regex = src_waf_client.get_regex_pattern_set(
            Name=regex_set_name,
            Scope=src_scope,
            Id=regex_set_id
        )
        regexpatternset = src_regex['RegexPatternSet']

        option_params = {}
        if 'Description' in regexpatternset:
            option_params['Description'] = regexpatternset['Description']

        Name = regexpatternset["Name"] + '-toolcreated'
        ARN = regexpatternset["ARN"]
        RegexString = regexpatternset["RegularExpressionList"]
        # timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        try:
            dst_regex = dst_waf_client.create_regex_pattern_set(
                Name=Name,
                Scope=dst_scope,
                **option_params,
                RegularExpressionList=RegexString
            )
            print('Regex set: ' + Name + ' created')
            regex_arn_output[ARN] = dst_regex["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建 regex set 时发生错误: {e}")
            exit(1)

    return regex_arn_output


# def create_rule_group(rule_group_info, src_scope, src_region, dst_scope, dst_region): #old function
#     """
#     基于提供的rule group的名字来创建rule group
#     创建时，会在源名称后面添加'-toolcreated'做区分。
#     以下参数，在创建rule group时会以默认值来处理
#     1） visibility-config
#         默认
#         SampledRequestsEnabled=true
#     2） CloudWatchMetricsEnabled
#         默认为true
#         MetricName
#         默认为rule-group的名字
#     """
#     global src_waf_client
#     global dst_waf_client
#     rule_group_arn_output = {}
#
#     print('-------------creating rule group into target regions : (%s) ----------------' % (dst_region))
#
#     for rule_group in rule_group_info:
#         rule_group_name = rule_group
#         rule_group_id = rule_group_info[rule_group_name]
#
#         # 获取rule-group的json配置
#         # src_waf_client.get_rule_group(
#         #     Name=rule_group_name,
#         #     Scope=src_scope,
#         #     Id
#         # )
#         command_get_rule = "aws wafv2 get-rule-group --scope %s --region %s --output json --name %s --id %s" % (
#             src_scope, src_region, rule_group_name, rule_group_id)
#         # print(command_get_rule)
#         des_rule = os.popen(command_get_rule)
#         # print(des_rule.read())
#         rule_group = json.loads(des_rule.read())["RuleGroup"]
#         # print(rule_group)
#         # 新创建的rule-group后面添加'-toolcreated'做区分
#         Name = rule_group["Name"] + '-toolcreated'
#         Description = rule_group["Description"]
#         ARN = rule_group["ARN"]
#         # capacity的意义是？这个要确认一下。
#         Capacity = rule_group["Capacity"]
#         # rules_json = rule_group["Rules"][0]
#         rules_json = rule_group["Rules"]
#         rules_json = update_ARN(rules_json)
#         # rule的配置放置在本地，方便后续调用
#         # file = open("./json_file/%s.json" % Name, "w", encoding="utf-8")
#         # file.write(json.dumps(rules_json))
#         # file.close()
#         # 添加timeid变量，用于给rule添加个一个带时间戳的description
#         timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
#
#         # 创建基本cli
#         create_rule_group_cli = 'aws wafv2 create-rule-group --name %s --scope %s --capacity %s --rules ' \
#                                 'file://./json_file/%s.json --output json ' \
#                                 '--region %s --visibility-config SampledRequestsEnabled=true,' \
#                                 'CloudWatchMetricsEnabled=true,MetricName=%s' % (
#                                     Name, dst_scope, str(Capacity), Name, dst_region,
#                                     Name)
#
#         # 判断是否有 custom response bodies
#         if 'CustomResponseBodies' in rule_group:
#             custom_bodies = rule_group['CustomResponseBodies']
#             file = open("./json_file/%s.json" % (Name + '_custom_response'), "w", encoding="utf-8")
#             file.write(json.dumps(custom_bodies))
#             file.close()
#             create_rule_group_cli = create_rule_group_cli + ' --custom-response-bodies file://./json_file/%s.json' % (
#                     Name + '_custom_response')
#
#         # 添加Description
#
#         if Description:
#             create_rule_group_cli = create_rule_group_cli + ' --description %s' % (Description + timeid)
#         else:
#             create_rule_group_cli = create_rule_group_cli + ' --description %s' % ('create-by-pyscript' + timeid)
#
#         # print(create_rule_group_cli)
#         # 创建rule group
#         res = os.popen(create_rule_group_cli)
#         print('Rule group : ' + Name + ' created')
#         res_list = json.loads(res.read())
#         # print(res_list)
#         # 将新创建的rule group的ARN和源rule group的ARN存放并返回
#         rule_group_arn_output[ARN] = res_list["Summary"]["ARN"]
#     return rule_group_arn_output

# new function
def create_rule_group(rule_group_info, src_scope, dst_scope):
    """
    基于提供的rule group的名字来创建rule group
    创建时，会在源名称后面添加'-toolcreated'做区分。
    以下参数，在创建rule group时会以默认值来处理
    1） visibility-config
        默认
        SampledRequestsEnabled=true
    2） CloudWatchMetricsEnabled
        默认为true
        MetricName
        默认为rule-group的名字
    """
    global src_waf_client
    global dst_waf_client
    rule_group_arn_output = {}

    print('-------------creating rule group into target regions : (%s) ----------------' % (dst_region))

    for rule_group in rule_group_info:
        rule_group_name = rule_group
        rule_group_id = rule_group_info[rule_group_name][1]
        rule_group_arn = rule_group_info[rule_group_name][0]

        # 获取rule-group的json配置
        src_rule_group = src_waf_client.get_rule_group(
            Name=rule_group_name,
            Scope=src_scope,
            Id=rule_group_id,
            ARN=rule_group_arn
        )

        rule_group = src_rule_group["RuleGroup"]

        # 新创建的rule-group后面添加'-toolcreated'做区分
        option_params = {}
        Name = rule_group["Name"] + '-toolcreated'
        if 'Description' in rule_group:
            option_params['Description'] = rule_group['Description']

        ARN = rule_group["ARN"]
        # capacity的意义是？这个要确认一下。
        Capacity = rule_group["Capacity"]
        rules = rule_group["Rules"]
        rules_arn_updated = update_ARN(rules)

        # 添加timeid变量，用于给rule添加个一个带时间戳的description
        # timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())

        # 判断是否有 custom response bodies
        if 'CustomResponseBodies' in rule_group:
            option_params['CustomResponseBodies'] = rule_group['CustomResponseBodies']
        if 'VisibilityConfig' in rule_group:
            option_params['VisibilityConfig'] = rule_group['VisibilityConfig']
            option_params['VisibilityConfig']['MetricName'] = Name

        try:
            result = dst_waf_client.create_rule_group(
                Name=Name,
                Scope=dst_scope,
                Capacity=Capacity,
                Rules=rules_arn_updated,
                **option_params
            )

            # 创建rule group
            print('Rule group : ' + Name + ' created')
            # 将新创建的rule group的ARN和源rule group的ARN存放并返回
            rule_group_arn_output[ARN] = result["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建 rule group时发生错误: {e}")
            exit(1)
    return rule_group_arn_output


def create_web_acl(web_acl_info, src_scope, dst_scope):
    """
    基于提供的web acl的名字来创建web acl
    创建时，会在源名称后面添加'-toolcreated'做区分。
    以下参数，在创建rule group时会以默认值来处理
    1） visibility-config
        默认
        SampledRequestsEnabled=true
    2） CloudWatchMetricsEnabled
        默认为true
        MetricName
        默认为rule-group的名字
    3） 'ManagedByFirewallManager'
        默认为：False,
    4） 现在仅支持同帐户的同步，如果有不同帐户的情况，建议使用firewall manager
        也因此原因web acl中的label的namespace都是在同帐户id下。
    5) AWSManagedRulesACFPRuleSet或者AWSManagedRulesATPRuleSet,如果从cloudfront同步到regional的时候，如果有Response inspection，会将其删除，因为，其只在cloudfront资源的webacl上才支持。
    Response inspection is available only in web ACLs that protect Amazon CloudFront distributions.
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-awsmanagedrulesacfpruleset.html

    """
    global IPSETARN
    global REGEXSETARN
    global RULEGROUPARN
    global src_waf_client
    global dst_waf_client

    print('-------------creating web acl into target regions : (%s) ----------------' % (dst_region))
    web_acl_name, web_acl_id = web_acl_info.popitem()
    src_waf_info = src_waf_client.get_web_acl(Name=web_acl_name, Id=web_acl_id, Scope=src_scope)

    # pprint.pprint(src_waf_info)
    dst_web_acl_name = web_acl_name + '-toolcreated'
    src_web_acl = src_waf_info["WebACL"]
    default_action = src_web_acl['DefaultAction']
    timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())



    # create_web_acl_cli = create_web_acl_cli + ' --default-action ' + default_action

    visibility_config = src_web_acl['VisibilityConfig']
    visibility_config['MetricName'] = dst_web_acl_name


    option_params = {}
    if 'Description' in src_web_acl:
        if src_web_acl['Description'] == "":
            option_params['Description'] = 'script_created_at'+timeid
        option_params['Description'] = src_web_acl['Description']+'_script_created_at_'+timeid
    if 'Tags' in src_web_acl:
        option_params['Tags'] = src_web_acl['Tags']
    if 'CaptchaConfig' in src_web_acl:
        option_params['CaptchaConfig']=src_web_acl['CaptchaConfig']

    if 'ChallengeConfig' in src_web_acl:
        option_params['ChallengeConfig'] = src_web_acl['ChallengeConfig']

    if 'TokenDomains' in src_web_acl:
        option_params['TokenDomains'] = src_web_acl['TokenDomains']
    if 'CustomResponseBodies' in src_web_acl:
        option_params['CustomResponseBodies'] = src_web_acl['CustomResponseBodies']
    rules = src_web_acl['Rules']
    rules_arn_updated = update_ARN(rules)
    rules = modify_rules(src_scope, dst_scope, rules_arn_updated)

    try:
        response = dst_waf_client.create_web_acl(
            Name=dst_web_acl_name,
            Scope=dst_scope,
            DefaultAction=default_action,
            VisibilityConfig=visibility_config,
            **option_params,  # valid types: <class 'list'>, <class 'tuple'>
            Rules=rules
        )
        print('Web ACL ' + response['Summary']['Name'] + ' created')
    except ClientError as e:
        print(f"创建 web acl 时发生错误: {e}")
        exit(1)


# waf_info = {'custom_response_body': {'CustomResponseBodies': {'waf-test': {'Content': 'wrong '
#                                                                                       'request '
#                                                                                       'user '
#                                                                                       'agent ',
#                                                                            'ContentType': 'TEXT_PLAIN'}}},
#             'ip_set': {'automate-test-ipset-v4-global-region-1': '2521a918-d6b8-4380-a797-5661fad4cbfa'},
#             'regex_set': {'firefox-global-region': 'a8693e93-11fe-43dc-876f-34c32058af56'},
#             'rule_group': {'waf-automation-global-region-rulegroup1': '03531fc3-6800-4fe8-83c0-b7f8f903c45d'},
#             'web_acl_name': {'waf-automation-global-region-test-wacl-2': '1f739de7-d9d4-41bb-97cc-c9e6a2a95523'}}

if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("Usage: python script.py web-acl-name source-scope source-region dest-scope dest-region")
        sys.exit(1)

    try:
        web_acl_name = str(sys.argv[1])
        src_scope = str(sys.argv[2])
        src_region = str(sys.argv[3])
        dst_scope = str(sys.argv[4])
        dst_region = str(sys.argv[5])
    except ValueError:
        print("Error: All arguments must be strings.")
        sys.exit(1)

    input_check = {src_scope: src_region, dst_scope: dst_region}
    validate_scope_region(input_check)

    # global parameters and objects
    if not os.path.exists("./json_file"):
        os.makedirs("./json_file")
    unique_id = str(uuid.uuid4())
    print('-------------script execution id is %s------------------' % (unique_id))
    # src_scope = "CLOUDFRONT"
    # src_region = "us-east-1"
    # dst_scope = "REGIONAL"
    # dst_region = "us-west-1"
    IPSETARN = {}
    REGEXSETARN = {}
    RULEGROUPARN = {}
    src_waf_client = boto3.client('wafv2', region_name=src_region)
    dst_waf_client = boto3.client('wafv2', region_name=dst_region)

    banner()

    waf_info = get_src_webacl_info(src_scope, web_acl_name)

    if waf_info['ip_set'] != {}:
        IPSETARN = create_ipset_func(waf_info['ip_set'], src_scope, dst_scope)

    if waf_info['regex_set'] != {}:
        REGEXSETARN = create_regex_func(waf_info['regex_set'], src_scope, dst_scope)

    if waf_info['rule_group'] != {}:
        RULEGROUPARN = create_rule_group(waf_info['rule_group'], src_scope, dst_scope)

    create_web_acl(waf_info['web_acl_name'], src_scope, dst_scope)
