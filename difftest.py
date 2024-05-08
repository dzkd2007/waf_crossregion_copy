from deepdiff import DeepDiff
import pprint
import os
a=open('/Users/fengepei/PycharmProject/wafautomation/jsonfile/config1.json','r')
b=open('/Users/fengepei/PycharmProject/wafautomation/jsonfile/config2.json','r')
ddiff=DeepDiff(a,b,ignore_order=True)
pprint.pprint(ddiff,indent=4)
a.close()
b.close()
