import os
import json
import boto3
import uuid



class BytesEncoder(json.JSONEncoder):
    """
    我们定义了一个自定义的 JSON 编码器 BytesEncoder。它继承自 json.JSONEncoder,并重写了 default 方法。
    在 default 方法中,我们检查对象是否为字节字符串类型。如果是,则将其解码为 UTF-8 字符串;否则,使用基类的 default 方法处理其他类型的对象。

    """
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.default(self, obj)


def save_config_to_local(type, name, unique_id, tmp_data):
    """
    将获取的配置保存在本地一份，用于备份和比对，或者回退
    这里的unique——id，在每次执行脚本时生成，用于区别每次运行并区分每次获取的配置

    :param name: str
    :param unique_id: str
    :param wafconfig: dict
    :return:

    """
    filename = unique_id + '_' + type + '_' + name
    file = open("./wafconfig/%s.json" % filename, "w", encoding="utf-8")
    file.write(json.dumps(tmp_data, indent=4, cls=BytesEncoder))
    file.close()

#
# if not os.path.exists("./wafconfig"):
#     os.makedirs("./wafconfig")
# unique_id = str(uuid.uuid4())
# src_waf_client = boto3.client('wafv2', region_name='us-east-1')
# dst_waf_client = boto3.client('wafv2', region_name='us-west-1')
#
# result = src_waf_client.get_web_acl(
#     Name="testwebaclfromsamye",
#     Id="7feb1049-7794-459c-ab3a-5f9e06b754d8",
#     Scope='CLOUDFRONT'
# )
#
# save_config_to_local('testwebaclfromsamye', unique_id, result)

# result = preprocess_dict(result['WebACL'][])



