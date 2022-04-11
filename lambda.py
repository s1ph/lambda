# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import boto3
import json
import email
import sys
import chilkat
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)




    
def get_jira_api_token():
    """Returns the Jira API token from AWS SecretsManager"""
    try:
        logger.info("Trying 'get_jira_api_token()'")
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name='us-east-1')
        get_secret_value_response = client.get_secret_value(SecretId='arn:aws:secretsmanager:us-east-1:accountid:secret:key')
        secret = get_secret_value_response['SecretString']
        return secret
    except Exception:
        logger.error("Error at getting API token", exc_info=True)
        logger.error("Failed at 'get_jira_api_token()'", exc_info=True)
        
def create_ticket (data):
    JIRA_API_TOKEN=json.loads(get_jira_api_token())
    email_message_raw = email.message_from_bytes(data)
    subject = str(email.header.make_header(email.header.decode_header(email_message_raw['Subject'])))
    rest = chilkat.CkRest()
    bTls = True
    port = 443
    bAutoReconnect = True
    success = rest.Connect("jira.server.com",port,bTls,bAutoReconnect)
    if (success != True):
        print("ConnectFailReason: " + str(rest.get_ConnectFailReason()))
        print(rest.lastErrorText())
        sys.exit()
    

    rest.SetAuthBasic("email@domain.com",JIRA_API_TOKEN['apikey'])
    json1 = chilkat.CkJsonObject()
    json1.UpdateString("fields.project.id","1000")
    json1.UpdateString("fields.summary",subject)
    json1.UpdateString("fields.issuetype.id","1300")
    json1.UpdateString("fields.description",message)
    rest.AddHeader("Content-Type","application/json")
    rest.AddHeader("Accept","application/json")
    sbRequestBody = chilkat.CkStringBuilder()
    json1.EmitSb(sbRequestBody)
    sbResponseBody = chilkat.CkStringBuilder()
    success = rest.FullRequestSb("POST","/rest/api/2/issue",sbRequestBody,sbResponseBody)
    if (success != True):
        print(rest.lastErrorText())
        sys.exit()
    respStatusCode = rest.get_ResponseStatusCode()
    if (respStatusCode >= 400):
        print("Response Status Code = " + str(respStatusCode))
        print("Response Header:")
        print(rest.responseHeader())
        print("Response Body:")
        print(sbResponseBody.getAsString())
        sys.exit()
    jsonResponse = chilkat.CkJsonObject()
    jsonResponse.LoadSb(sbResponseBody)
    id = jsonResponse.stringOf("id")
    key = jsonResponse.stringOf("key")
    self = jsonResponse.stringOf("self")
    return jsonResponse
    
    
def lambda_handler(event, context):
    # first code will fetch fromaddress, subject and messageId
    # then it will call workmail API to fetch actual message using this messageId
    # and then it will parse the message properly to convert it into text message
    workmail = boto3.client('workmailmessageflow', region_name='us-east-1')
    from_addr = event['envelope']['mailFrom']['address']
    subject = event['subject']
    flowDirection = event['flowDirection']
    msg_id = event['messageId']
    # calling workmail API to fetch message body
    raw_msg = workmail.get_raw_message_content(messageId=msg_id)
    t = raw_msg['messageContent'].read()
    parsed_msg = email.message_from_bytes(t)
    create_ticket (data=parsed_msg)
    if parsed_msg.is_multipart():
        for part in parsed_msg.walk():
            payload = part.get_payload(decode=True) #returns a bytes object
            if type(payload) is bytes:
                msg_text = payload.decode('utf-8') #utf-8 is default
                print('*** Multipart payload ****', msg_text)
                break
    else:
        payload = parsed_msg.get_payload(decode=True)
        if type(payload) is bytes:
            msg_text = payload.decode('utf-8') #utf-8 is default
            print('*** Single payload ****', msg_text)
    # Return value is ignored when Lambda is configured asynchronously at Amazon WorkMail
    # For more information, see https://docs.aws.amazon.com/workmail/latest/adminguide/lambda.html
    ## return msg_text