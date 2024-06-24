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

> python waf_crossregion_copy.py waf-test CLOUDFRONT us-east-1 REGIONAL us-west-1# waf_crossregion_copy

## This script has following limits

- don't support MODSEC and marketplace rule groups
- don't support rule-policy that managed by firewall manager
- only support single account copy,don't have cross account copy function