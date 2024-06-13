import boto3
import json
from botocore.exceptions import ClientError
def get_rollback_info(unique_id,scope,filepath):
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
    except ClientError as e:
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


data = get_rollback_info('356ebb11-fde9-4a18-8c84-56ec119a91f6','test','wafconfig')
client = boto3.client('wafv2', region_name='us-west-1')
del_web_acl(data['webacl'],'REGIONAL',client)
