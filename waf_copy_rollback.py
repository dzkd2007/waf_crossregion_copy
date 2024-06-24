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


def get_lock_token():
    """
    基于资源的种类

    :return:
    """
    pass


def del_web_acl(web_acl_list,scope,client):
    """

    :param web_acl_list: dict
    :param client: boto3.client
    :return: None
    """
    try:
        response = client.delete_web_acl(
            Name=web_acl_list['Name'],
            Scope=scope,
            Id=web_acl_list['Id'],
            LockToken=web_acl_list['LockToken']
        )
        print(response)
    except botocore.exceptions. as e:
        if e =
        print(e)
    return None




def del_rule_group(rule_group_list,client):
    """

    :param rule_group_list: list
    :param client: boto3.client
    :return: None
    """
    pass


def del_ip_set(ip_set_list,client):
    """

    :param ip_set_list: list
    :param client: boto3.client
    :return: None
    """
    pass


def del_regex_set(regex_set_list,client):
    """

    :param regex_set_list: list
    :param client: boto3.client
    :return: None
    """
    pass


if __name__ == '__main__':
    if len(sys.argv) != 1:
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
        del_regex_set()
    if data['ipset']:
        del_ip_set()
    print('****************FINISH ROLLBACK WAF COPY ID %s*********************' % unique_id)


