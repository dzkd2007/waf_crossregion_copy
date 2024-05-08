import os
import json
import boto3
import time
import uuid
import sys
from botocore.exceptions import ClientError
import pprint

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
    file = open("./test/%s" % filename, "w", encoding="utf-8")
    file.write(wafconfig)
    file.close()

"""

response = client.list_ip_sets(
    Scope='CLOUDFRONT'|'REGIONAL',
    NextMarker='string',
    Limit=123
)


response = client.delete_ip_set(
    Name='string',
    Scope='CLOUDFRONT'|'REGIONAL',
    Id='string',
    LockToken='string'
)
response = client.delete_regex_pattern_set(
    Name='string',
    Scope='CLOUDFRONT'|'REGIONAL',
    Id='string',
    LockToken='string'
)
response = client.delete_rule_group(
    Name='string',
    Scope='CLOUDFRONT'|'REGIONAL',
    Id='string',
    LockToken='string'
)x
response = client.delete_web_acl(
    Name='string',
    Scope='CLOUDFRONT'|'REGIONAL',
    Id='string',
    LockToken='string'
)

        {
            "Name": "testwebaclfromsamye",
            "Id": "7feb1049-7794-459c-ab3a-5f9e06b754d8",
            "Description": "",
            "LockToken": "af9c812e-e086-4755-b0c6-72cbe9a6c1e0",
            "ARN": "arn:aws:wafv2:us-east-1:652875617673:global/webacl/testwebaclfromsamye/7feb1049-7794-459c-ab3a-5f9e06b754d8"
        },


"""



src_waf_client = boto3.client('wafv2', region_name='us-east-1')
dst_waf_client = boto3.client('wafv2', region_name='us-west-1')

result = src_waf_client.get_web_acl(
    Name="testwebaclfromsamye",
    Id="7feb1049-7794-459c-ab3a-5f9e06b754d8",
    Scope='CLOUDFRONT'
)

pprint.pprint(result)


