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

#cf12b28b-3683-442a-90f0-c8e25a207978_WebACL_waf-automation-global-region-test-wacl-2.json
# {
#     "ipset": [
#         {
#             "Name": "automate-test-ipset-v4-global-region-1-toolcreated",
#             "Id": "ea22863e-6e44-4944-a1cb-08eddd1104f1",
#             "Description": "automate-test-ipset-1script_created_at20240613-11:07:27",
#             "LockToken": "62c8cba9-8009-45ec-941d-1a4b41f1b423",
#             "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/ipset/automate-test-ipset-v4-global-region-1-toolcreated/ea22863e-6e44-4944-a1cb-08eddd1104f1"
#         },
#         {
#             "Name": "automate-test-ipset-v6-global-region-1-toolcreated",
#             "Id": "268a8e59-33d4-4b65-8f74-96a730b772ec",
#             "Description": "automate-test-ipset-v6-global-region-1script_created_at20240613-11:07:28",
#             "LockToken": "056d6e03-710b-49e7-a2cb-54ad84e6f24d",
#             "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/ipset/automate-test-ipset-v6-global-region-1-toolcreated/268a8e59-33d4-4b65-8f74-96a730b772ec"
#         }
#     ],
#     "regexset": [
#         {
#             "Name": "firefox-global-region-toolcreated",
#             "Id": "e5c184ff-850d-4a2a-b6f4-82bc6db4e410",
#             "Description": "firefox-global-regionscript_created_at20240613-11:07:30",
#             "LockToken": "faff8418-f0fb-4ba5-b3a9-79f6ec67bbc1",
#             "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/regexpatternset/firefox-global-region-toolcreated/e5c184ff-850d-4a2a-b6f4-82bc6db4e410"
#         }
#     ],
#     "rulegroup": [
#         {
#             "Name": "waf-automation-global-region-rulegroup1-toolcreated",
#             "Id": "a7193a08-3576-466d-af9f-abe272248bf3",
#             "Description": "waf-automation-global-region-rulegroup1script_created_at20240613-11:07:31",
#             "LockToken": "07388e1a-f054-4afb-94ac-984663ba9da6",
#             "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/rulegroup/waf-automation-global-region-rulegroup1-toolcreated/a7193a08-3576-466d-af9f-abe272248bf3"
#         }
#     ],
#     "webacl": {
#         "Name": "waf-automation-global-region-test-wacl-2-toolcreated",
#         "Id": "da8d66e1-afe1-4110-bfa2-50d933067c25",
#         "Description": "cli-test-for-custom-response_script_created_at_20240613-11:07:31",
#         "LockToken": "81d46ee9-f3ad-4c0c-aac2-242bfaeb51fd",
#         "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/webacl/waf-automation-global-region-test-wacl-2-toolcreated/da8d66e1-afe1-4110-bfa2-50d933067c25"
#     }
# }
temp_data={"Name": "waf-automation-global-region-test-wacl-2-toolcreated",
        "Id": "da8d66e1-afe1-4110-bfa2-50d933067c25",
        "Description": "cli-test-for-custom-response_script_created_at_20240613-11:07:31",
        "LockToken": "81d46ee9-f3ad-4c0c-aac2-242bfaeb51fd",
        "ARN": "arn:aws:wafv2:us-west-1:652875617673:regional/webacl/waf-automation-global-region-test-wacl-2-toolcreated/da8d66e1-afe1-4110-bfa2-50d933067c25"}

dst_waf_client = boto3.client('wafv2', region_name='us-west-1')
compare_src_dst('cf12b28b-3683-442a-90f0-c8e25a207978','waf-automation-global-region-test-wacl-2','REGIONAL',dst_waf_client,temp_data)




