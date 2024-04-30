import os
import json
import pprint
import boto3
import time
import uuid
import sys


def banner():
    text = "WAF CROSS REGION COPY SCRIPT START"
    width = 50  # 设置总宽度为 30 个字符

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
    for key in REGEXSETARN:
        Rules = json.loads(json.dumps(Rules).replace(key, REGEXSETARN[key]))
    for key in RULEGROUPARN:
        Rules = json.loads(json.dumps(Rules).replace(key, RULEGROUPARN[key]))
    for key in IPSETARN:
        Rules = json.loads(json.dumps(Rules).replace(key, IPSETARN[key]))
    # print(Rules)
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


def save_config_to_local(name,unique_id,wafconfig):
    """

    :param name: str
    :param unique_id: str
    :param wafconfig: dict
    :return:

    """
    filename = name+'_'+unique_id
    file = open("./json_file/%s.json" % filename, "w", encoding="utf-8")
    file.write(json.dumps(wafconfig))
    file.close()


def get_src_webacl_info(scope, webaclname):

    global src_waf_client
    global unique_id
    ipset = {}
    regset = {}
    rulegroup = {}
    chalconfig = {}
    captchaconfig = {}
    customresponsebody = {}
    webacl_info = {}
    aclid = ''
    response = src_waf_client.list_web_acls(
        Scope=scope
    )
    # get webacl Id
    for i in response["WebACLs"]:
        if i["Name"] == webaclname:
            aclid = i['Id']
            webacl_info['web_acl_name'] = {i["Name"]:aclid}
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
    save_config_to_local(webaclname,unique_id,web_acl_details)

    # print('-----------Finding custom config that used in Web ACL------------')
    # if 'CaptchaConfig' in web_acl_details:
    #     print('CaptchaConfig exist-----------------')
    #     captchaconfig["CaptchaConfig"] = web_acl_details['CaptchaConfig']
    #     webacl_info['captcha_config'] = captchaconfig
    # if "ChallengeConfig" in web_acl_details:
    #     print('ChallengeConfig exist-----------------')
    #     chalconfig["ChallengeConfig"] = web_acl_details['ChallengeConfig']
    #     webacl_info['Challenge_Config'] = chalconfig
    # if "CustomResponseBodies" in web_acl_details:
    #     print('CustomResponseBodies exist-----------------')
    #     customresponsebody['CustomResponseBodies'] = web_acl_details['CustomResponseBodies']
    #     webacl_info['custom_response_body'] = customresponsebody

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
                rulegroup[rule_group_name] = rule_group_id
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
    # pprint.pprint(webacl_info)
    return webacl_info


def create_ipset_func(ip_set_info, src_scope, src_region, dst_scope, dst_region):
    ip_set_arn_output = {}

    print('-------------creating ipsets into target region : (%s) ----------------' % (dst_region))

    for ip_set in ip_set_info:
        # 获取需要创建的ipset的名字
        ip_set_name = ip_set
        ip_set_id = ip_set_info[ip_set_name]

        # 通过名字get配置
        command_get_ipset = "aws wafv2 get-ip-set --scope %s --region %s --output json --name %s --id %s" % (
            src_scope, src_region, ip_set_name, ip_set_id)
        d_ipset = os.popen(command_get_ipset)
        des_ipset = json.loads(d_ipset.read())
        Description = des_ipset["IPSet"]["Description"]
        # 如果有重名会报错，这里后面加了toolcreated作为标识，防止重名。但是ipset名字最大128字符，超过也会报错，需要注意和后续优化
        Name = des_ipset["IPSet"]["Name"] + '-toolcreated'
        ARN = des_ipset["IPSet"]["ARN"]
        IPVestion = des_ipset["IPSet"]["IPAddressVersion"]
        IPs = ""
        # 创建一个基于现在时间的时间戳，创建ipset时附加到description上，便于区分创建时间。
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        for ip in des_ipset["IPSet"]["Addresses"]:
            IPs = IPs + "\"" + ip + "\"" + " "

        if not Description:
            create_ipset = """aws wafv2 create-ip-set --region %s --output json --scope %s --description %s --name %s --ip-address-version %s --addresses %s """ % (
                dst_region, 'create-by-pyscript' + timeid, Name, IPVestion, IPs)
        else:
            create_ipset = """aws wafv2 create-ip-set --region %s --output json --scope %s --description %s --name %s --ip-address-version %s --addresses %s """ % (
                dst_region, dst_scope, Description + '-create-by-pyscript@' + timeid, Name, IPVestion, IPs)
        # print(create_ipset)
        print('creating ipset '+Name)
        res = os.popen(create_ipset)
        res_list = json.loads(res.read())
        print('success create ipset '+res_list['Summary']['Name'])
        # Add into dict
        # 将创建好的资源的ARN和原先资源的ARN记录下来，用于在创建web acl时，替换源web acl的json配置中的arn部分。
        ip_set_arn_output[ARN] = res_list["Summary"]["ARN"]

    return ip_set_arn_output


def create_regex_func(regex_set_info, src_scope, src_region, dst_scope, dst_region):
    regex_arn_output = {}

    print('-------------creating regex set into target regions : (%s) ----------------' % (dst_region))
    for regex_set in regex_set_info:
        regex_set_name = regex_set
        regex_set_id = regex_set_info[regex_set_name]

        command_get_regex = "aws wafv2 get-regex-pattern-set --scope %s --region %s --output json --name %s --id %s" % (
            src_scope, src_region, regex_set_name, regex_set_id)

        d_regex = os.popen(command_get_regex)
        des_regex = json.loads(d_regex.read())
        Description = des_regex["RegexPatternSet"]["Description"]
        Name = des_regex["RegexPatternSet"]["Name"] + '-toolcreated'
        ARN = des_regex["RegexPatternSet"]["ARN"]
        RegexString = des_regex["RegexPatternSet"]["RegularExpressionList"]
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        if not Description:
            create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope %s --description %s --name %s 
    			--regular-expression-list '%s'""" % (
                dst_region, dst_scope, 'create-by-pyscript' + timeid, Name, json.dumps(RegexString))
        else:
            create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope %s --description %s --name %s --regular-expression-list '%s'""" % (
                dst_region, dst_scope, Description + timeid, Name, json.dumps(RegexString))
        # create_regex = """aws wafv2 create-regex-pattern-set --region %s --output json --scope REGIONAL --description %s --name %s --regular-expression-list '[{"RegexString": %s}]'"""%(_DST_REGION,Description,Name,json.dumps(RegexString))
        # print(create_regex)
        res = os.popen(create_regex)
        print('Regex set: '+Name+' created')
        res_list = json.loads(res.read())
        # print(res_list)
        # Add into dict
        regex_arn_output[ARN] = res_list["Summary"]["ARN"]

    return regex_arn_output


def create_rule_group(rule_group_info, src_scope, src_region, dst_scope, dst_region):
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

    rule_group_arn_output = {}

    print('-------------creating rule group into target regions : (%s) ----------------' % (dst_region))

    for rule_group in rule_group_info:
        rule_group_name = rule_group
        rule_group_id = rule_group_info[rule_group_name]

        # 获取rule-group的json配置
        command_get_rule = "aws wafv2 get-rule-group --scope %s --region %s --output json --name %s --id %s" % (
            src_scope, src_region, rule_group_name, rule_group_id)
        # print(command_get_rule)
        des_rule = os.popen(command_get_rule)
        # print(des_rule.read())
        rule_group = json.loads(des_rule.read())["RuleGroup"]
        # print(rule_group)
        # 新创建的rule-group后面添加'-toolcreated'做区分
        Name = rule_group["Name"] + '-toolcreated'
        Description = rule_group["Description"]
        ARN = rule_group["ARN"]
        # capacity的意义是？这个要确认一下。
        Capacity = rule_group["Capacity"]
        # rules_json = rule_group["Rules"][0]
        rules_json = rule_group["Rules"]
        rules_json = update_ARN(rules_json)
        # rule的配置放置在本地，方便后续调用
        file = open("./json_file/%s.json" % Name, "w", encoding="utf-8")
        file.write(json.dumps(rules_json))
        file.close()
        # 添加timeid变量，用于给rule添加个一个带时间戳的description
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())

        # 创建基本cli
        create_rule_group_cli = 'aws wafv2 create-rule-group --name %s --scope %s --capacity %s --rules ' \
                                'file://./json_file/%s.json --output json ' \
                                '--region %s --visibility-config SampledRequestsEnabled=true,' \
                                'CloudWatchMetricsEnabled=true,MetricName=%s' % (
                                    Name, dst_scope, str(Capacity), Name, dst_region,
                                    Name)

        # 判断是否有 custom response bodies
        if 'CustomResponseBodies' in rule_group:
            custom_bodies = rule_group['CustomResponseBodies']
            file = open("./json_file/%s.json" % (Name + '_custom_response'), "w", encoding="utf-8")
            file.write(json.dumps(custom_bodies))
            file.close()
            create_rule_group_cli = create_rule_group_cli + ' --custom-response-bodies file://./json_file/%s.json' % (
                    Name + '_custom_response')

        # 添加Description

        if Description:
            create_rule_group_cli = create_rule_group_cli + ' --description %s' % (Description + timeid)
        else:
            create_rule_group_cli = create_rule_group_cli + ' --description %s' % ('create-by-pyscript' + timeid)

        # print(create_rule_group_cli)
        # 创建rule group
        res = os.popen(create_rule_group_cli)
        print('Rule group : ' + Name + ' created')
        res_list = json.loads(res.read())
        # print(res_list)
        # 将新创建的rule group的ARN和源rule group的ARN存放并返回
        rule_group_arn_output[ARN] = res_list["Summary"]["ARN"]
    return rule_group_arn_output


def create_web_acl(web_acl_info, src_scope, src_region, dst_scope, dst_region):
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

    default_action = src_waf_info["WebACL"]['DefaultAction']
    timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
    if 'Description' in src_waf_info["WebACL"]:
        waf_description = src_waf_info["WebACL"]['Description']
    else:
        waf_description = 'create-by-pyscript' + timeid

    # create_web_acl_cli = create_web_acl_cli + ' --default-action ' + default_action

    visibility_config = src_waf_info["WebACL"]['VisibilityConfig']
    if 'CustomResponseBodies' in src_waf_info["WebACL"]:
        custom_response_bodies = src_waf_info["WebACL"]['CustomResponseBodies']
    else:
        custom_response_bodies = {}

    tag_params = {}
    if 'Tags' in src_waf_info["WebACL"]:
        tag_params['Tags'] = src_waf_info["WebACL"]['Tags']

    if 'CaptchaConfig' in src_waf_info["WebACL"]:
        captcha_config = src_waf_info["WebACL"]['CaptchaConfig']
    else:
        captcha_config = {}

    if 'ChallengeConfig' in src_waf_info["WebACL"]:
        challenge_config = src_waf_info["WebACL"]['ChallengeConfig']
    else:
        challenge_config = {}

    if 'TokenDomains' in src_waf_info["WebACL"]:
        tag_params['TokenDomains'] = src_waf_info["WebACL"]['TokenDomains']

    rules = src_waf_info["WebACL"]['Rules']
    rules = preprocess_dict(rules)

    for i in range(0, len(rules)):
        rules[i] = update_ARN(rules[i])
    rules = modify_rules(src_scope, dst_scope, rules)

    file = open("./json_file/%s.json" % web_acl_name, "w", encoding="utf-8")
    file.write(json.dumps(rules))
    file.close()

    try:

        response = dst_waf_client.create_web_acl(
            Name=dst_web_acl_name,
            Scope=dst_scope,
            DefaultAction=default_action,
            Description=waf_description,
            VisibilityConfig=visibility_config,
            **tag_params,  # valid types: <class 'list'>, <class 'tuple'>
            CustomResponseBodies=custom_response_bodies,
            CaptchaConfig=captcha_config,
            ChallengeConfig=challenge_config,
            # **token_domains_params
            # valid types: <class 'list'>, <class 'tuple'>
            Rules=rules
        )
        print('Web ACL '+response['Summary']['Name']+' created')
    except dst_waf_client.exceptions.WAFInvalidOperationException as e:
        print(e.response)


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

    input_check = {src_scope:src_region,dst_scope:dst_region}
    validate_scope_region(input_check)

    # global parameters and objects
    if not os.path.exists("./json_file"):
        os.makedirs("./json_file")
    unique_id = str(uuid.uuid4())
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

    waf_info=get_src_webacl_info(src_scope, web_acl_name)

    if waf_info['ip_set'] != {}:
        IPSETARN = create_ipset_func(waf_info['ip_set'], src_scope, src_region, dst_scope, dst_region)

    if waf_info['regex_set'] != {}:
        REGEXSETARN = create_regex_func(waf_info['regex_set'], src_scope, src_region, dst_scope, dst_region)

    if waf_info['rule_group'] != {}:
        RULEGROUPARN = create_rule_group(waf_info['rule_group'], src_scope, src_region, dst_scope, dst_region, )


    create_web_acl(waf_info['web_acl_name'], src_scope, src_region, dst_scope, dst_region)
