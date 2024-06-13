import boto3
import json
from deepdiff import DeepDiff
import pprint

class BytesEncoder(json.JSONEncoder):
    """
    我们定义了一个自定义的 JSON 编码器 BytesEncoder。它继承自 json.JSONEncoder,并重写了 default 方法。
    在 default 方法中,我们检查对象是否为字节字符串类型。如果是,则将其解码为 UTF-8 字符串;否则,使用基类的 default 方法处理其他类型的对象。

    """
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8')
        return json.JSONEncoder.default(self, obj)


def compare_src_dst(unique_id,web_acl_name,dst_scope,dst_waf_client,temp_data):
    """

    :param unique_id: str
    :param web_acl_name: str
    :param dst_waf_client: boto3client
    :param temp_data: dict
    :return:
    """
    src_file_name = unique_id + '_WebACL_' + web_acl_name

    with open('./wafconfig/%s.json' % src_file_name, 'r') as f:
        src_json=json.load(f)
    dst = dst_waf_client.get_web_acl(
            Scope=dst_scope,
            Name=temp_data['Name'],
            Id=temp_data['Id']
        )
    ddiff = DeepDiff(src_json, dst, ignore_order=True,ignore_string_type_changes=True)
    pprint.pprint(ddiff)
    f.close()
    return None



