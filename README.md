# waf_crossregion_copy

## Before usage

- Create an IAM user with get, list, and create permissions for WAF, and create its Access Key and Secret Access Key.

- In your local Python environment, install the required Python libraries. Please refer to the contents of the requirements.txt file.
>pip install -r requirements.txt
- Configure the AWS authentication credentials for boto3.Please follow the boto3 guide
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html

## How to use this script
You can use following format input to use the script

> Usage: python script.py web-acl-name source-scope source-region dest-scope dest-region

For example:

> python waf_crossregion_copy.py waf-test CLOUDFRONT us-east-1 REGIONAL us-west-1

If you want to roll back the copy, delete all created WAF resources in destination region. You can use waf_copy_rollback.py script.
All created resource are stored in local path ./wafconfig/, the script will create this path if not exist. 

Resource Type, Name, Id, ARN, LockToken will be save to local wafconfig/ path as JSON file, the example saved resource info as below:
<!-- json-content.json -->
```json
{
    "execution_id": "********-****-****-****-************",
    "dst_scope": "REGIONAL",
    "dst_region": "us-west-1",
    "ipset": [
        {
            "Name": "********-toolcreated",
            "Id": "****************",
            "Description": "**************script_created_at20240601-15:35:17",
            "LockToken": "********-****-****-****-************",
            "ARN": "arn:aws:wafv2:us-west-1:******:regional/ipset/************-toolcreated/***************"
        },
        {
            "Name": "********-toolcreated",
            "Id": "****************",
            "Description": "**************script_created_at20240601-15:35:17",
            "LockToken": "********-****-****-****-************",
            "ARN": "arn:aws:wafv2:us-west-1:******:regional/ipset/************-toolcreated/***************"
        }
    ],
    "regexset": [
        {
            "Name": "********-toolcreated",
            "Id": "*******************",
            "Description": "**************script_created_at20240601-15:35:20",
            "LockToken": "********-****-****-****-************",
            "ARN": "arn:aws:wafv2:us-west-1:********:regional/regexpatternset/*********-toolcreated/***********"
        }
    ],
    "rulegroup": [
        {
            "Name": "********-toolcreated",
            "Id": "*******************",
            "Description": "**************script_created_at20240601-15:35:20",
            "LockToken": "********-****-****-****-************",
            "ARN": "arn:aws:wafv2:us-west-1:********:regional/rulegroup/*********-toolcreated/***********"
        }
    ],
    "webacl": {
        "Name": "********-toolcreated",
        "Id": "*******************",
        "Description": "**************script_created_at20240601-15:35:20",
        "LockToken": "********-****-****-****-************",
        "ARN": "arn:aws:wafv2:us-west-1:********:regional/webacl/*********-toolcreated/***********"
    }
}
```

To roll back the creation, please get the execution_id from the json file that contain info of all created resources as above, using waf_copy_rollback.py script.

> python waf_copy_rollback.py <execution_id>

## This script has following limits

- don't support MODSEC and marketplace rule groups
- don't support rule-policy that managed by firewall manager
- only support single account copy,don't have cross account copy function