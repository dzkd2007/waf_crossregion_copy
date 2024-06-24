import os
import json
import boto3
import time
import uuid
import sys
from botocore.exceptions import ClientError
import pprint
from waf_config_save import *
from waf_config_diff import *

def banner():
    text = "WAF CROSS REGION COPY SCRIPT START"
    width = len(text)+10  # 设置总宽度

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


def get_reference_resource_info(rules, ipset, regset, rulegroup, process_rulegroup=True):
    for item in rules:
        statement = item['Statement']
        if 'IPSetReferenceStatement' in statement:
            ip_set_name, ip_set_id = statement['IPSetReferenceStatement']['ARN'].split('/')[-2:]
            if ip_set_name in ipset:
                continue
            else:
                print('IPSET:Name: %s, ID: %s ' % (ip_set_name, ip_set_id))
                ipset[ip_set_name] = ip_set_id
        if 'RegexPatternSetReferenceStatement' in statement:
            regex_set_name, regex_set_id = statement['RegexPatternSetReferenceStatement']['ARN'].split('/')[-2:]
            if regex_set_name in regset:
                continue
            else:
                print('REGSET:Name: %s, ID: %s ' % (regex_set_name, regex_set_id))
                regset[regex_set_name] = regex_set_id
        if process_rulegroup and 'RuleGroupReferenceStatement' in statement:
            rule_group_name, rule_group_id = statement['RuleGroupReferenceStatement']['ARN'].split('/')[-2:]
            if rule_group_name in rulegroup:
                continue
            else:
                print('RULEGROUP:Name: %s, ID: %s ' % (rule_group_name, rule_group_id))
                rulegroup[rule_group_name] = [statement['RuleGroupReferenceStatement']['ARN'], rule_group_id]

    return ipset, regset, rulegroup



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


# def save_config_to_local(name, unique_id, wafconfig):
#     """
#     将获取的配置保存在本地一份，用于备份和比对，或者回退
#     这里的unique——id，在每次执行脚本时生成，用于区别每次运行并区分每次获取的配置
#
#     :param name: str
#     :param unique_id: str
#     :param wafconfig: dict
#     :return:
#
#     """
#     filename = name + '_' + unique_id
#     file = open("./json_file/%s.json" % filename, "w", encoding="utf-8")
#     file.write(json.dumps(wafconfig))
#     file.close()


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
        print("错误，web acl不存在，清检查输入")
        sys.exit(1)
    try:
        web_acl_res = src_waf_client.get_web_acl(
            Scope=scope,
            Name=webaclname,
            Id=aclid
        )
        save_config_to_local('WebACL',webaclname,unique_id,web_acl_res)
        web_acl_details = web_acl_res['WebACL']
        rules = web_acl_details['Rules']
    except ClientError as e:
        print(f"获取 web acl 信息时发生错误: {e}")
        exit(1)

    print('-----------Finding custom resources that used in Web ACL------------')
    ipset, regset, rulegroup = get_reference_resource_info(rules, ipset, regset, rulegroup)
    # 如果存在rule group，查看rule group是否引用了ipset 或者regex set，如果有，加入到ipset和regex的集合里
    if rulegroup:
        for item in rulegroup:
            rule_group_name = item
            rule_group_id = rulegroup[rule_group_name][1]
            rule_group_arn = rulegroup[rule_group_name][0]
            try:
                rule_group_response = src_waf_client.get_rule_group(
                    Name=rule_group_name,
                    Scope=src_scope,
                    Id=rule_group_id,
                    ARN=rule_group_arn
                )
                rule_group_rules = rule_group_response["RuleGroup"]['Rules']
                ipset, regset, rulegroup = get_reference_resource_info(rule_group_rules, ipset, regset, rulegroup,process_rulegroup=False)
            except ClientError as e:
                print(f"获取 rule group 信息时发生错误: {e}")
                exit(1)

    webacl_info['ip_set'] = ipset
    webacl_info['rule_group'] = rulegroup
    webacl_info['regex_set'] = regset
    print('-----------get following info about the given web acl-----------')
    return webacl_info


def create_ipset_func(ip_set_info, src_scope, dst_scope):
    global src_waf_client
    global dst_waf_client
    global CREATEDRESOURCE

    ip_set_arn_output = {}
    ipset_created = []

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
        if len(ipset["Name"]) <= 116:
            Name = ipset["Name"] + '-toolcreated'
        else:
            Name = ipset["Name"][:116]+ '-toolcreated'

        ARN = ipset["ARN"]
        IPVestion = ipset["IPAddressVersion"]
        addresses = ipset['Addresses']
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        option_params = {}
        if 'Description' in ipset:
            if ipset['Description'] == "":
                option_params['Description'] = 'script_created_at' + timeid
            else:
                if len(ipset['Description']) <= 222: # max length 256, 'script_created_at' + timeid total lenght is 34, so use 222 as threshold
                    option_params['Description'] = ipset['Description']+'script_created_at' + timeid
                else:
                    option_params['Description'] = ipset['Description'][:222]+'script_created_at' + timeid
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
            ipset_created.append(dst_ipset['Summary'])
            # Add into dict
            # 将创建好的资源的ARN和原先资源的ARN记录下来，用于在创建web acl时，替换源web acl的json配置中的arn部分。
            ip_set_arn_output[ARN] = dst_ipset["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建ipset时发生错误: {e}")
            CREATEDRESOURCE['ipset'] = ipset_created
            save_config_to_local('Resource', 'created', unique_id, CREATEDRESOURCE)
            exit(1)

    CREATEDRESOURCE['ipset'] = ipset_created
    return ip_set_arn_output


def create_regex_func(regex_set_info, src_scope, dst_scope):
    global src_waf_client
    global dst_waf_client
    global CREATEDRESOURCE

    regex_arn_output = {}
    regex_created = []

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
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        option_params = {}
        if 'Description' in regexpatternset:
            if regexpatternset['Description'] == "":
                option_params['Description'] = 'script_created_at' + timeid
            else:
                if len(regexpatternset['Description']) <= 222:  # max length 256, 'script_created_at' + timeid total lenght is 34, so use 222 as threshold
                    option_params['Description'] = regexpatternset['Description'] + 'script_created_at' + timeid
                else:
                    option_params['Description'] = regexpatternset['Description'][:222] + 'script_created_at' + timeid

        if len(regexpatternset["Name"]) <= 116:    # name max length is 128, '-toolcreated' is 12, so threshold is 116
            Name = regexpatternset["Name"] + '-toolcreated'
        else:
            Name = regexpatternset["Name"][:116] + '-toolcreated'
        ARN = regexpatternset["ARN"]
        RegexString = regexpatternset["RegularExpressionList"]
        try:
            print('creating regex set  ' + Name)
            dst_regex = dst_waf_client.create_regex_pattern_set(
                Name=Name,
                Scope=dst_scope,
                **option_params,
                RegularExpressionList=RegexString
            )
            print('Regex set: ' + Name + ' created')
            regex_created.append(dst_regex['Summary'])
            regex_arn_output[ARN] = dst_regex["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建 regex set 时发生错误: {e}")
            CREATEDRESOURCE['regexset'] = regex_created
            save_config_to_local('Resource', 'created', unique_id, CREATEDRESOURCE)
            exit(1)

    CREATEDRESOURCE['regexset'] = regex_created
    return regex_arn_output


def create_rule_group(rule_group_info, src_scope, dst_scope):
    """
    基于提供的rule group的名字来创建rule group
    创建时，会在源名称后面添加'-toolcreated'做区分。
    以下参数，在创建rule group时会以默认值来处理

        MetricName
        默认为rule-group的名字
    """
    global src_waf_client
    global dst_waf_client
    global CREATEDRESOURCE
    rule_group_arn_output = {}
    rule_group_created=[]

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
        timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())
        if len(rule_group["Name"]) <= 116:  # name max length is 128, '-toolcreated' is 12, so threshold is 116
            Name = rule_group["Name"] + '-toolcreated'
        else:
            Name = rule_group["Name"][:116] + '-toolcreated'

        if 'Description' in rule_group:
            if rule_group['Description'] == "":
                option_params['Description'] = 'script_created_at' + timeid
            else:
                if len(rule_group['Description']) <= 222:  # max length 256, 'script_created_at' + timeid total lenght is 34, so use 222 as threshold
                    option_params['Description'] = rule_group['Description'] + 'script_created_at' + timeid
                else:
                    option_params['Description'] = rule_group['Description'][:222] + 'script_created_at' + timeid

        ARN = rule_group["ARN"]
        # capacity的意义是？这个要确认一下。
        Capacity = rule_group["Capacity"]
        rules = rule_group["Rules"]
        rules_arn_updated = update_ARN(rules)
        # 判断是否有 custom response bodies
        if 'CustomResponseBodies' in rule_group:
            option_params['CustomResponseBodies'] = rule_group['CustomResponseBodies']
        if 'VisibilityConfig' in rule_group:
            option_params['VisibilityConfig'] = rule_group['VisibilityConfig']
            option_params['VisibilityConfig']['MetricName'] = Name

        try:
            print('creating rule group  ' + Name)
            result = dst_waf_client.create_rule_group(
                Name=Name,
                Scope=dst_scope,
                Capacity=Capacity,
                Rules=rules_arn_updated,
                **option_params
            )

            # 创建rule group
            print('Rule group : ' + Name + ' created')
            rule_group_created.append(result['Summary'])
            # 将新创建的rule group的ARN和源rule group的ARN存放并返回
            rule_group_arn_output[ARN] = result["Summary"]["ARN"]
        except ClientError as e:
            print(f"创建 rule group时发生错误: {e}")
            CREATEDRESOURCE['rulegroup'] = rule_group_created
            save_config_to_local('Resource','created',unique_id,CREATEDRESOURCE)
            exit(1)
    #保存所有创建了的资源的信息，用于后续回滚
    CREATEDRESOURCE['rulegroup'] = rule_group_created
    return rule_group_arn_output


def create_web_acl(web_acl_info, src_scope, dst_scope):
    """
    基于提供的web acl的名字来创建web acl
    创建时，会在源名称后面添加'-toolcreated'做区分。
    以下参数，在创建rule group时会以默认值来处理
    1） CloudWatchMetricsEnabled
        MetricName
        默认为rule-group的名字
    2） 'ManagedByFirewallManager'
        默认拷贝源webacl的配置
    3） 现在仅支持同帐户的同步，如果有不同帐户的情况，建议使用firewall manager
        也因此原因web acl中的label的namespace都是在同帐户id下，复用源waf-acl
    4) AWSManagedRulesACFPRuleSet或者AWSManagedRulesATPRuleSet,如果从cloudfront同步到regional的时候，
    如果有Response inspection，会将其删除，因为，其只在cloudfront资源的webacl上才支持。
    Response inspection is available only in web ACLs that protect Amazon CloudFront distributions.
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-wafv2-webacl-awsmanagedrulesacfpruleset.html

    """
    global IPSETARN
    global REGEXSETARN
    global RULEGROUPARN
    global CREATEDRESOURCE
    global src_waf_client
    global dst_waf_client

    print('-------------creating web acl into target regions : (%s) ----------------' % (dst_region))
    web_acl_name, web_acl_id = web_acl_info.popitem()
    src_waf_info = src_waf_client.get_web_acl(Name=web_acl_name, Id=web_acl_id, Scope=src_scope)

    dst_web_acl_name = web_acl_name + '-toolcreated'
    src_web_acl = src_waf_info["WebACL"]
    default_action = src_web_acl['DefaultAction']
    timeid = time.strftime("%Y%m%d-%H:%M:%S", time.localtime())


    visibility_config = src_web_acl['VisibilityConfig']
    visibility_config['MetricName'] = dst_web_acl_name

    option_params = {}
    if 'Description' in src_web_acl:
        if src_web_acl['Description'] == "":
            option_params['Description'] = 'script_created_at' + timeid
        option_params['Description'] = src_web_acl['Description'] + '_script_created_at_' + timeid
    if 'Tags' in src_web_acl:
        option_params['Tags'] = src_web_acl['Tags']
    if 'CaptchaConfig' in src_web_acl:
        option_params['CaptchaConfig'] = src_web_acl['CaptchaConfig']

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
        print('creating web acl ' + dst_web_acl_name)
        response = dst_waf_client.create_web_acl(
            Name=dst_web_acl_name,
            Scope=dst_scope,
            DefaultAction=default_action,
            VisibilityConfig=visibility_config,
            **option_params,  # valid types: <class 'list'>, <class 'tuple'>
            Rules=rules
        )
        print('Web ACL ' + response['Summary']['Name'] + ' created')
        CREATEDRESOURCE['webacl'] = response['Summary']
    except ClientError as e:
        print(f"创建 web acl 时发生错误: {e}")
        save_config_to_local('Resource', 'created', unique_id, CREATEDRESOURCE)
        exit(1)


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
    if not os.path.exists("./wafconfig"):
        os.makedirs("./wafconfig")
    unique_id = str(uuid.uuid4())
    IPSETARN = {}
    REGEXSETARN = {}
    RULEGROUPARN = {}
    CREATEDRESOURCE = {}
    src_waf_client = boto3.client('wafv2', region_name=src_region)
    dst_waf_client = boto3.client('wafv2', region_name=dst_region)

    banner()
    print('-------------script execution id is %s------------------' % (unique_id))
    CREATEDRESOURCE['dst_scope']=dst_scope
    CREATEDRESOURCE['dst_region']=dst_region

    waf_info = get_src_webacl_info(src_scope, web_acl_name)

    if waf_info['ip_set'] != {}:
        IPSETARN = create_ipset_func(waf_info['ip_set'], src_scope, dst_scope)

    if waf_info['regex_set'] != {}:
        REGEXSETARN = create_regex_func(waf_info['regex_set'], src_scope, dst_scope)

    if waf_info['rule_group'] != {}:
        RULEGROUPARN = create_rule_group(waf_info['rule_group'], src_scope, dst_scope)

    create_web_acl(waf_info['web_acl_name'], src_scope, dst_scope)
    save_config_to_local('Resource', 'created', unique_id, CREATEDRESOURCE)
    print('-------------following are difference between copied webacl and original webacl------------------')
    compare_src_dst(unique_id,web_acl_name,dst_scope,dst_waf_client,CREATEDRESOURCE['webacl'])


