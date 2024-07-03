import boto3
import json
from botocore.exceptions import ClientError
import sys


def get_rollback_info(unique_id,filepath='wafconfig'):
    """
    使用uuid 来get需要rollback的资源。
        webacl/rulegroup/ipset/regex的
        Name/Id/Scope/locktoken

    参数

    :param unique_id --> str
    :param scope --> str
    :param filepath --> str

    :return:
        dict =
        {
            'webacl':{
                'name':str,
                'id' : str,
                'Scope' : str,
                'locktoken':str
            }
            'rulegroup':[
                    {
                        'name':str,
                        'id' : str,
                        'Scope' : str,
                        'locktoken':str
                    },
                    {
                        ...
                    }
            ]
            'ipset':[
                    {
                        'name':str,
                        'id' : str,
                        'Scope' : str,
                        'locktoken':str
                    },
                    {
                        ...
                    }
            ]
            'regexset':[
                    {
                        'name':str,
                        'id' : str,
                        'Scope' : str,
                        'locktoken':str
                    },
                    {
                        ...
                    }
            ]
        }
    """
    filename = unique_id + '_Resource_Created'
    with open('./%s/%s.json'%(filepath,filename), 'r') as file:
        # 读取 JSON 文件内容
        data = json.load(file)
    return data


def get_lock_token(type,object_info_dict,client,scope):
    """
    基于资源的种类

    :return:
    """
    if type == 'WebACL':
        response = client.get_web_acl(
            Name=object_info_dict['Name'],
            Id=object_info_dict['Id'],
            Scope=scope
        )
        lock_token = response["LockToken"]
    elif type == 'RuleGroup':
        response = client.get_rule_group(
            Name=object_info_dict['Name'],
            Id=object_info_dict['Id'],
            Scope=scope,
            ARN=object_info_dict['ARN']
        )
        lock_token = response["LockToken"]

    elif type == 'RegexSet':
        response = client.get_regex_pattern_set(
            Name=object_info_dict['Name'],
            Id=object_info_dict['Id'],
            Scope=scope
        )
        lock_token = response["LockToken"]
    elif type == 'IPSet':
        response = client.get_ip_set(
            Name=object_info_dict['Name'],
            Id=object_info_dict['Id'],
            Scope=scope
        )
        lock_token = response["LockToken"]
    else:
        print('type not correct, please check the input parameter')
        sys.exit(1)

    return lock_token


def del_web_acl(web_acl_list,scope,client):
    """

    :param web_acl_list: dict
    :param client: boto3.client
    :return: None
    """
    lock_token = web_acl_list['LockToken']
    while True:
        try:
            response = client.delete_web_acl(
                Name=web_acl_list['Name'],
                Scope=scope,
                Id=web_acl_list['Id'],
                LockToken=lock_token
            )
            print('Successfully delete web acl : %s' %(web_acl_list['Name']))
            break
        except ClientError as error:
            if error.response['Error']['Code'] == 'WAFOptimisticLockException':
                lock_token = get_lock_token('WebACL',web_acl_list,client,scope)
                print('Using update token to delete web acl : %s' %(web_acl_list['Name']))
            else:
                print(f"Unexpected error: {error}")
                break
    return None




def del_rule_group(rule_group_list,scope,client):
    """

    :param rule_group_list: list
    :param client: boto3.client
    :return: None
    """
    for rule_group in rule_group_list:
        lock_token = rule_group['LockToken']
        while True:
            try:
                response = client.delete_rule_group(
                    Name=rule_group['Name'],
                    Scope=scope,
                    Id=rule_group['Id'],
                    LockToken=lock_token
                )
                print('Successfully delete rule group : %s' % (rule_group['Name']))
                break
            except ClientError as error:
                if error.response['Error']['Code'] == 'WAFOptimisticLockException':
                    lock_token = get_lock_token('RuleGroup', rule_group, client, scope)
                    print('Using update token to delete rule group : %s' % (rule_group['Name']))
                else:
                    print(f"Unexpected error: {error}")
                    break

    return None


def del_ip_set(ip_set_list,scope,client):
    """

    :param ip_set_list: list
    :param client: boto3.client
    :return: None
    """
    for ip_set in ip_set_list:
        lock_token = ip_set['LockToken']
        while True:
            try:
                response = client.delete_ip_set(
                    Name=ip_set['Name'],
                    Scope=scope,
                    Id=ip_set['Id'],
                    LockToken=lock_token
                )
                print('Successfully delete ip set : %s' % (ip_set['Name']))
                break
            except ClientError as error:
                if error.response['Error']['Code'] == 'WAFOptimisticLockException':
                    lock_token = get_lock_token('IPSet', ip_set, client, scope)
                    print('Using update token to delete IP set : %s' % (ip_set['Name']))
                else:
                    print(f"Unexpected error: {error}")
                    break
    return None


def del_regex_set(regex_set_list,scope,client):
    """

    :param regex_set_list: list
    :param client: boto3.client
    :return: None
    """
    for regex_set in regex_set_list:
        lock_token = regex_set['LockToken']
        while True:
            try:
                response = client.delete_regex_pattern_set(
                    Name=regex_set['Name'],
                    Scope=scope,
                    Id=regex_set['Id'],
                    LockToken=lock_token
                )
                print('Successfully delete regex pattern set : %s' % (regex_set['Name']))
                break
            except ClientError as error:
                if error.response['Error']['Code'] == 'WAFOptimisticLockException':
                    lock_token = get_lock_token('RegexSet', regex_set, client, scope)
                    print('Using update token to delete Regex pattern set : %s' % (regex_set['Name']))
                else:
                    print(f"Unexpected error: {error}")
                    break

    return None


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(len(sys.argv))
        print("Usage: python script.py uuid")
        sys.exit(1)

    try:
        unique_id = str(sys.argv[1])
    except ValueError:
        print("Error: All arguments must be strings.")
        sys.exit(1)

    print('****************STARTING ROLLBACK WAF COPY ID %s*********************' % unique_id)
    data = get_rollback_info(unique_id,'wafconfig')
    client = boto3.client('wafv2', data['dst_region'])
    if data['webacl']:
        del_web_acl(data['webacl'],data['dst_scope'],client)
    if data['rulegroup']:
        del_rule_group(data['rulegroup'],data['dst_scope'],client)
    if data['regexset']:
        del_regex_set(data['regexset'],data['dst_scope'],client)
    if data['ipset']:
        del_ip_set(data['ipset'],data['dst_scope'],client)
    print('****************FINISH ROLLBACK WAF COPY ID %s*********************' % unique_id)


