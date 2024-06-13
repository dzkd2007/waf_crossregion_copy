from deepdiff import DeepDiff
import pprint
import os
a=open('/Users/fengepei/PycharmProject/wafautomation/wafconfig/9dd620f5-37be-4c6d-9908-eb553b2c1cd5_WebACL_waf-automation-global-region-test-wacl-2.json','r')
b=open('/Users/fengepei/PycharmProject/wafautomation/jsonfile/config2.json','r')
ddiff=DeepDiff(a,b,ignore_order=True)
pprint.pprint(ddiff,indent=4)
a.close()
b.close()
