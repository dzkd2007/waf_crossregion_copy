import boto3
from deepdiff import DeepDiff


def compare_src_dst(client,test):
    """

    :param client:
    :param test:
    :return:
    """

    src = open('/Users/fengepei/PycharmProject/wafautomation/jsonfile/config1.json', 'r')
    dst = open('/Users/fengepei/PycharmProject/wafautomation/jsonfile/config2.json', 'r')
    ddiff = DeepDiff(a, b, ignore_order=True)
    pprint.pprint(ddiff, indent=4)
    a.close()
    b.close()

