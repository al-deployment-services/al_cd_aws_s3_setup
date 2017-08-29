Wrapper for AWS S3 Log Source setup in Alert Logic (Log Manager)
===============================================================================
This script will setup AWS S3 log source link in Alert Logic (Log Manager). Three components that will be created:

- New Credentials based on the provided IAM role + external ID 
- New S3 collection policy based on the template type
- New S3 log source based on the given name

Full manual step by step reference can be found in here: https://docs.alertlogic.com/install/cloud/amazon-web-services-log-manager-S3.htm

Requirements
------------
* Alert Logic Account ID (CID)
* User API Key for Alert Logic Log Manager API
* IAM role for Log Manager (https://docs.alertlogic.com/install/cloud/amazon-web-services-log-manager-S3.htm#crossAccountAccess)
* Target S3 bucket that you want to collect the logs from

Deployment Mode
---------------
* ADD = will create the Log Manager AWS S3 log source
* DEL = will delete the existing AWS S3 log source

Sample ADD Usage
----------------
Replace the parameters to match your environment and run this command ::
  
    python cd_aws_s3_setup.py ADD --key USER_API_KEY --cid 10000 --iam arn:aws:iam::052672429986:role/Log_Manager_S3_Role --ext MY_EXT_ID --cred "S3 Credentials" --name "S3 Log Source" --pol "S3 Policy" --type "S3_Access" --s3 "MY_S3_BUCKET" --rgex ".*" --tz "US/Central" --int 300 --dc "defender-us-denver"

Take note of the output from the script, you will need to record the S3 log source ID if you wish to delete it later using this script (see below)

Sample DEL Usage
----------------
Replace the parameters to match your environment and run this command ::

    python cd_aws_s3_setup.py DEL --key USER_API_KEY --cid 10000 --uid 9563267B-5540-1005-870C-0050568532D4 --dc defender-us-denver

Note

* Deletion of S3 log source basically will archive the log source, but it never trully remove it (you can still query it via API)

* the S3 credentials (IAM role) registration and S3 collection policy will be removed as part of this process


Arguments
----------
  -h, --help   show this help message and exit
  --key KEY    Alert Logic Log Manager user API Key  
  --cid CID    Alert Logic Customer CID as target for this deployment  
  --arn ARN    Cross Account IAM role arn for Log Manager S3 collection
  --ext EXT    External ID specified in IAM role trust relationship
  --cred CRED  Credential name, free form label
  --name NAME  S3 source name, free form label
  --pol POL    S3 Collection Policy name, free form label
  --type TYPE  S3 Collection Policy Template (MsSQL, ELB, Redshift_Activity, Redshift_Con, Redshift_User, S3_Access)
  --s3 S3      S3 bucket name as target for log collection
  --rgex RGEX  File name or pattern, will use .* if not specified
  --tz TZ      Time zone for timestamp (https://docs.alertlogic.com/developer/content/z-sandbox/apitest/endpoint/logmgrapi/commonparameters.htm), default to US/Central
  --int INT    Collection interval (in seconds), will use 300 seconds if not specified
  --uid uid    S3 log source ID (add this only if you want to delete it)
  --dc DC      Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport

Exit Code
----------
If you going to integrate this script to another orchestration tool, you can use the exit code to detect the status:

* 0 = script run successfully
* 1 = missing or invalid argument
* 2 = environment issue such as invalid SQS arn or invalid API key
* 3 = timeout 

WARNING: This script will not revert back any changes due to timeout, any commands / API calls that it executed prior to timeout will run until completed, even if the script exit due to timeout.

License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors: 
Welly Siauw (welly.siauw@alertlogic.com)
