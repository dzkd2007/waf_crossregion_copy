import pprint

import boto3
import os
import json
import sys
import time


def save_config_to_local(name,wafconfig):
    """
    将获取的配置保存在本地一份，用于备份和比对，或者回退
    这里的unique——id，在每次执行脚本时生成，用于区别每次运行并区分每次获取的配置

    :param name: str
    :param unique_id: str
    :param wafconfig: dict
    :return:

    """
    file = open("./jsonfile/%s.json" % name, "w", encoding="utf-8")
    file.write(json.dumps(wafconfig))
    file.close()

# 读取JSON文件
with open('./jsonfile/testconfig.json', 'r') as file:
    data = json.load(file)

# 将JSON数据转换为Python字典
print(type(data))
rules=data['Rules']

# save_config_to_local('testrules',rules)

src_waf_client = boto3.client('wafv2', region_name='us-east-1')
result=src_waf_client.create_web_acl(
    Name='testwebaclfromsamye',
    Scope='CLOUDFRONT',
    DefaultAction={'Allow':{}},
    Rules=rules,
    CustomResponseBodies={
        "block-by-waf": {
            "ContentType": "APPLICATION_JSON",
            "Content": "{\n\"error\": \"blocked by waf\"\n}"
    }},
    VisibilityConfig={
        'SampledRequestsEnabled': True | False,
        'CloudWatchMetricsEnabled': True | False,
        'MetricName': 'testwebaclfromsamye'}

)

