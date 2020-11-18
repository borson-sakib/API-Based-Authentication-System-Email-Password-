from __future__ import print_function
import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import json
import uuid

# MODIFY
USER_POOL_ID = 'us-east-2_pJZXfuJjD'
CLIENT_ID = '2l4kiccs0kff3oif62t5ddkln5'
CLIENT_SECRET = '1v9091kj9ckbn60er7dc6gq7b7lnk8s170kackcj950la3rfnvu7'
client = None



def get_secret_hash(email):
    msg = email + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'),
                   msg=str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


def initiate_auth(email, password):
    try:
        resp = client.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'SECRET_HASH': get_secret_hash(email),
                'PASSWORD': password
            },
            ClientMetadata={
                'email': email,
                'password': password
            })
    except client.exceptions.NotAuthorizedException as e:
        return None, "The username or password is incorrect"
    except Exception as e:
        print(e)
        return None, "Unknown error"
    return resp, None


def lambda_handler(event, context):
    global client
    if client == None:
        client = boto3.client('cognito-idp')

    print(event)
    body = event
    email = body['email']
    password = body['password']
    is_new = "false"


    resp, msg = initiate_auth(email, password)
    if msg != None:
        return {'status': 'fail', 'msg': msg}
    id_token = resp['AuthenticationResult']['IdToken']
    refresh_token = resp['AuthenticationResult']['RefreshToken']
    access_token = resp['AuthenticationResult']['AccessToken']
    print('id token: ' + id_token)

    response = client.admin_get_user(
        UserPoolId=USER_POOL_ID,
        Username=email
    )


    user_id = response['Username']
    print(resp)


    # return response

    return {
        "statusCode": 200,
        "body": json.dumps(
            {'status': 'Successfully Signed In', 'id_token': id_token, 'user_id': user_id,
             'RefreshToken': refresh_token,
             'access_token': access_token, 'resp': resp}
        ),
    }


