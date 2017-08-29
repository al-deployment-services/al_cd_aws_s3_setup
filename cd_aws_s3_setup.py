from __future__ import print_function
import os.path, json, requests, logging, datetime, argparse, sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API headers and url
HEADERS = {'content-type': 'application/json'}

TIME_ZONE_CHOICE = [
"Africa/Cairo", "Asia/Dhaka", "Asia/Yekaterinburg","Europe/London",
"Africa/Casablanca", "Asia/Hong_Kong", "Atlantic/Azores", "Europe/Madrid",
"Africa/Harare", "Asia/Irkutsk", "Atlantic/Cape_Verde",	"Europe/Moscow",
"Africa/Kinshasa", "Asia/Kabul", "Australia/Adelaide", "Europe/Prague",
"Africa/Nairobi", "Asia/Karachi", "Australia/Brisbane", "Europe/Rome",
"America/Buenos_Aires", "Asia/Katmandu", "Australia/Darwin", "Europe/Warsaw",
"America/Caracas", "Asia/Krasnoyarsk", "Australia/Hobart", "GMT",
"America/Chihuahua", "Asia/Magadan", "Australia/Perth", "Pacific/Auckland",
"America/Lima", "Asia/Muscat", "Australia/Sydney", "Pacific/Fiji"
"America/Mexico_City", "Asia/Rangoon", "Canada/Atlantic", "Pacific/Guam",
"America/Panama", "Asia/Riyadh", "Canada/Central", "Pacific/Midway",
"America/Phoenix", "Asia/Seoul", "Canada/Newfoundland",	"Pacific/Tongatapu",
"America/Santiago", "Asia/Singapore", "Etc/UTC+6", "US/Alaska",
"America/Sao_Paulo", "Asia/Taipei",	"Etc/UTC-12", "US/Central",
"Asia/Almaty", "Asia/Tehran", "Etc/UTC-2", "US/East-Indiana",
"Asia/Baghdad",	"Asia/Tel_Aviv", "Etc/UTC-3", "US/Eastern",
"Asia/Baku", "Asia/Tokyo", "Europe/Athens", "US/Hawaii",
"Asia/Bangkok", "Asia/Vladivostok", "Europe/Bucharest", "US/Mountain",
"Asia/Calcutta", "Asia/Yakutsk", "Europe/Helsinki", "US/Pacific"
]

#exit code standard:
#0 = OK
#1 = argument parser issue
#2 = environment issue such as invalid environment id, invalid password, or invalid scope
#3 = timeout
EXIT_CODE = 0

def get_api_endpoint(target_dc):
	if target_dc == "defender-us-denver":
		return "https://publicapi.alertlogic.net/api/lm/v1/"
	elif target_dc == "defender-us-ashburn":
		return "https://publicapi.alertlogic.com/api/lm/v1/"
	elif target_dc == "defender-uk-newport":
		return "https://publicapi.alertlogic.co.uk/api/lm/v1/"
	else:
		return False

def get_source_s3(token, endpoint, target_s3, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/sources/" + target_s3
	REQUEST = requests.get(API_ENDPOINT, headers=HEADERS, auth=(token,''))
	
	print ("Retrieving S3 Log source info status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 200:
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["s3"] = {}
		RESULT["s3"]["id"] = "n/a"
	return RESULT

def del_source_s3(token, endpoint, target_s3, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/sources/" + target_s3
	REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(token,''))	
	print ("Delete S3 log source status : " + str(REQUEST.status_code), str(REQUEST.reason))

def del_s3_policy(token, endpoint, target_policy, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/policies/" + target_policy
	REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(token,''))	
	print ("Delete S3 collection policy status : " + str(REQUEST.status_code), str(REQUEST.reason))

def del_credentials(token, endpoint, target_cred, target_cid):
	API_ENDPOINT = endpoint + target_cid + "/credentials/" + target_cred
	REQUEST = requests.delete(API_ENDPOINT, headers=HEADERS, auth=(token,''))	
	print ("Delete credentials status : " + str(REQUEST.status_code), str(REQUEST.reason))
	
def post_credentials(token, endpoint, payload, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/credentials/iam_role"
	REQUEST = requests.post(API_ENDPOINT, headers=HEADERS, auth=(token,''), data=payload)

	print ("Create Credentials status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["iam_role"]  = {}
		RESULT["iam_role"]["id"] = "n/a"
	return RESULT

def prep_credentials(iam_arn, iam_ext_id, cred_name):
	#Setup dictionary for credentials payload
	RESULT = {}
	RESULT["iam_role"]  = {}
	RESULT["iam_role"]["arn"] = str(iam_arn)
	RESULT["iam_role"]["external_id"] = str(iam_ext_id)	
	RESULT["iam_role"]["name"] = str(cred_name)	
	return RESULT

def post_s3_policy(token, endpoint, payload, target_cid):	
	API_ENDPOINT = endpoint + target_cid + "/policies/s3"
	REQUEST = requests.post(API_ENDPOINT, headers=HEADERS, auth=(token,''), data=payload)

	print ("Create S3 policy status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["s3"]  = {}
		RESULT["s3"]["id"] = "n/a"
	return RESULT

def prep_s3_policy(s3_policy_name, s3_policy_type):
	#Setup dictionary for s3 collection payload
	RESULT = {}
	RESULT["s3"]  = {}
	RESULT["s3"]["name"] = str(s3_policy_name)
	RESULT["s3"]["multiline"] = {}
	RESULT["s3"]["multiline"]["is_multiline"] = False

	if (s3_policy_type == "MsSQL"):
		RESULT["s3"]["template_id"] = "3A943EDF-FB2C-1004-963D-005056853D45"
	elif (s3_policy_type == "ELB"):
		RESULT["s3"]["template_id"] = "A3069F39-FB68-1004-B9EA-005056853D45"
	elif (s3_policy_type == "Redshift_Activity"):
		RESULT["s3"]["template_id"] = "7B85CAC3-FB68-1004-B9EA-005056853D45"
	elif (s3_policy_type == "Redshift_Con"):		
		RESULT["s3"]["template_id"] = "74173391-FB82-1004-B9EA-005056853D45"
	elif (s3_policy_type == "Redshift_User"):
		RESULT["s3"]["template_id"] = "D9675D68-FB93-1004-B9EA-005056853D45"
	elif (s3_policy_type == "S3_Access"):
		RESULT["s3"]["template_id"] = "AB51CD45-FB68-1004-B9EA-005056853D45"
	
	return RESULT

def post_s3_source(token, endpoint, payload, target_cid):
	API_ENDPOINT = endpoint + target_cid + "/sources/s3"
	REQUEST = requests.post(API_ENDPOINT, headers=HEADERS, auth=(token,''), data=payload)

	print ("Create S3 source status : " + str(REQUEST.status_code), str(REQUEST.reason))
	if REQUEST.status_code == 201:		
		RESULT = json.loads(REQUEST.text)
	else:		
		RESULT = {}
		RESULT["s3"]  = {}
		RESULT["s3"]["id"] = "n/a"

	return RESULT

def prep_s3_source(source_name, s3_bucket_name, file_pattern, time_zone, credential_id, policy_id):
	#Setup dictionary for s3 collection payload
	RESULT = {}
	RESULT["s3"]  = {}
	RESULT["s3"]["name"] = str(source_name)
	RESULT["s3"]["enabled"] = True
	RESULT["s3"]["bucket"] = s3_bucket_name
	RESULT["s3"]["file_pattern"] = file_pattern
	RESULT["s3"]["time_zone"] = time_zone
	RESULT["s3"]["credential_id"] = credential_id
	RESULT["s3"]["policy_id"] = policy_id

	return RESULT

#MAIN MODULE
if __name__ == '__main__':
	EXIT_CODE=0
	
	#Prepare parser and argument
	parent_parser = argparse.ArgumentParser()
	subparsers = parent_parser.add_subparsers(help="Select mode", dest="mode")
	
	#Add parser for both ADD and DELETE mode	
	add_parser = subparsers.add_parser("ADD", help="Add CloudTrail collection")
	del_parser = subparsers.add_parser("DEL", help="Delete CloudTrail collection")
	
	#Parser argument for Add scope
	add_parser.add_argument("--key", required=True, help="User Key for Alert Logic Log Manager API Authentication")	
	add_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target")
	add_parser.add_argument("--iam", required=True, help="Cross Account IAM role arn")
	add_parser.add_argument("--ext", required=True, help="External ID specified in IAM role trust relationship")
	add_parser.add_argument("--cred", required=True, help="Credential name, free form label, not visible in Alert Logic UI")
	add_parser.add_argument("--name", required=True, help="S3 source name, free form label")
	add_parser.add_argument("--pol", required=True, help="S3 Collection Policy name, free form label")
	add_parser.add_argument("--type", required=True, help="S3 Collection Policy Template", choices=["MsSQL", "ELB", "Redshift_Activity", "Redshift_Con", "Redshift_User", "S3_Access"])
	add_parser.add_argument("--s3", required=True, help="S3 bucket name as target for log collection")
	add_parser.add_argument("--rgex", required=False, help="File name or Pattern, will use .* if not specified", default=".*")
	add_parser.add_argument("--tz", required=False, help="Time zone (https://docs.alertlogic.com/developer/content/z-sandbox/apitest/endpoint/logmgrapi/commonparameters.htm)", choices=TIME_ZONE_CHOICE, default="US/Central")
	add_parser.add_argument("--int", required=False, help="Collection interval (in seconds), will use 300 seconds if not specified", default=300)	
	add_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")
	
	#Parser argument for Delete scope
	del_parser.add_argument("--key", required=True, help="User Key for Alert Logic Log Manager API Authentication")	
	del_parser.add_argument("--cid", required=True, help="Alert Logic Customer CID as target")	
	del_parser.add_argument("--uid", required=True, help="S3 log source ID that you wish to delete")
	del_parser.add_argument("--dc", required=True, help="Alert Logic Data center assignment, i.e. defender-us-denver, defender-us-ashburn or defender-uk-newport")
	
	try:
		args = parent_parser.parse_args()
	except:
		EXIT_CODE = 1
		sys.exit(EXIT_CODE)

	#Set argument to variables
	if args.mode == "ADD":
		print ("\n### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = ADD ###\n")

		APIKEY = args.key		
		TARGET_CID = args.cid		
		TARGET_IAM_ROLE_ARN = args.iam
		TARGET_EXT_ID = args.ext
		TARGET_CRED_NAME = args.cred
		TARGET_NAME = args.name
		TARGET_S3_POL = args.pol
		TARGET_S3_NAME = args.s3
		TARGET_S3_TYPE = args.type
		TARGET_S3_REGEX = args.rgex		
		TARGET_TIME_ZONE = args.tz
		TARGET_INTERVAL = args.int		
		TARGET_DEFENDER = args.dc

		#get API endpoint
		ALERT_LOGIC_LM = get_api_endpoint(TARGET_DEFENDER)

		if ALERT_LOGIC_LM != False:
			
			#Create credentials using the IAM role ARN and external ID	
			print ("### Creating IAM Role Link ###")
			CRED_PAYLOAD = prep_credentials(TARGET_IAM_ROLE_ARN, TARGET_EXT_ID, TARGET_CRED_NAME)			
			CRED_RESULT = post_credentials(APIKEY, ALERT_LOGIC_LM, str(json.dumps(CRED_PAYLOAD, indent=4)), TARGET_CID)
			CRED_ID = str(CRED_RESULT["iam_role"]["id"])
							
			if CRED_ID != "n/a":
				print ("Cred ID : " + CRED_ID)

				#Prep the S3 Collection Policy payload
				print ("### Creating S3 Collection Policy ###")				
				S3_POLICY_PAYLOAD = prep_s3_policy(TARGET_S3_POL, TARGET_S3_TYPE)				
				S3_POLICY_RESULT = post_s3_policy(APIKEY, ALERT_LOGIC_LM, str(json.dumps(S3_POLICY_PAYLOAD, indent=4)), TARGET_CID)
				S3_POLICY_ID = str(S3_POLICY_RESULT["s3"]["id"])
								
				if S3_POLICY_ID != "n/a":
					print ("S3 Collection Policy ID : " + S3_POLICY_ID)

					#Prep the S3 Log Source payload
					print ("### Creating S3 Log Source ###")
					S3_SOURCE_PAYLOAD = prep_s3_source(TARGET_NAME, TARGET_S3_NAME, TARGET_S3_REGEX, TARGET_TIME_ZONE, CRED_ID, S3_POLICY_ID)
					S3_SOURCE_RESULT = post_s3_source(APIKEY, ALERT_LOGIC_LM, str(json.dumps(S3_SOURCE_PAYLOAD, indent=4)), TARGET_CID)
					S3_SOURCE_ID = str(S3_SOURCE_RESULT["s3"]["id"])

					if S3_SOURCE_ID != "n/a":
						print ("S3 Source ID : " + S3_SOURCE_ID)

					else:
						EXIT_CODE=2
						print ("### Failed to create S3 Log Source, see response code + reason above, stopping .. ###")

				else:
					EXIT_CODE=2
					print ("### Failed to create S3 Collection Policy, see response code + reason above, stopping .. ###")	

			else:
				EXIT_CODE=2
				print ("### Failed to create credentials, see response code + reason above, stopping .. ###")

		else:
			EXIT_CODE=2
			print ("Invalid data center assignment, use -h for more details, stopping ...")

	elif args.mode == "DEL":
		print ("\n### Starting script - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + " - Deployment Mode = DEL ###\n")

		APIKEY = args.key		
		TARGET_CID = args.cid				
		TARGET_S3_SOURCE_ID = args.uid
		TARGET_DEFENDER = args.dc

		#get API endpoint
		ALERT_LOGIC_LM = get_api_endpoint(TARGET_DEFENDER)

		S3_SOURCE_RESULT = get_source_s3(APIKEY, ALERT_LOGIC_LM, TARGET_S3_SOURCE_ID, TARGET_CID)
		if S3_SOURCE_RESULT["s3"]["id"] != "n/a":
			#Get the credentials ID and Policy ID
			TARGET_CRED_ID = S3_SOURCE_RESULT["s3"]["credential_id"]
			TARGET_POLICY_ID = S3_SOURCE_RESULT["s3"]["policy_id"]

			#Delete S3 log source
			del_source_s3(APIKEY, ALERT_LOGIC_LM, TARGET_S3_SOURCE_ID, TARGET_CID)

			#Delete S3 collection policy
			del_s3_policy(APIKEY, ALERT_LOGIC_LM, TARGET_POLICY_ID, TARGET_CID)

			#Delete S3 credentials
			del_credentials(APIKEY, ALERT_LOGIC_LM, TARGET_CRED_ID, TARGET_CID)
		else:
			EXIT_CODE=2
			print ("Failed to find the S3 log source ID, see response code + reason above, stopping ..")


	print ("\n### Script stopped - " + str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M")) + "###\n")	
	sys.exit(EXIT_CODE)