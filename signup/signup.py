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

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('UserData')

def get_secret_hash(email):
    msg = email + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'),
                   msg=str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2


ERROR = 0
SUCCESS = 1
USER_EXISTS = 2


def sign_up(email, password,name,location):
    try:
        resp = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=get_secret_hash(email),
            Username=email,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'name',
                    'Value': name
                },
                {
                    'Name': 'custom:location',
                    'Value': location
                },
            ]
        )

        print(resp)
    except client.exceptions.UsernameExistsException as e:
        return USER_EXISTS
    except Exception as e:
        print(e)
        return ERROR
    return SUCCESS





def lambda_handler(event, context):
    global client
    if client == None:
        client = boto3.client('cognito-idp')

    print(event)
    body = event
    email = body['email']
    password = body['password']
    name= body['name']
    location= body['location']

    is_new = "false"
    user_id = str(uuid.uuid4())
    signed_up = sign_up(email, password,name,location)

    if signed_up == ERROR:
        return {
        "statusCode": 200,
        "body": json.dumps({'status': 'fail', 'msg': 'failed to sign up'}),
    }
    if signed_up == SUCCESS:

        response = client.admin_get_user(
            UserPoolId=USER_POOL_ID,
            Username=email
        )
        user_att = response['UserAttributes']

        name = []
        value = []
        for i in user_att:
            name.append(i['Name'])
            value.append(i['Value'])

        k = dict(zip(iter(name), iter(value)))
        k.pop('email')
        k.pop('email_verified')
        k.pop('name')

        table.put_item(Item=k)

        is_new = "true"
        return {
        "statusCode": 200,
        "body": json.dumps({'status':'Successfully signed up'}),
    }
        # user_id = str(uuid.uuid4())
    if signed_up == USER_EXISTS:
        return {
        "statusCode": 200,
        "body": json.dumps({'status':'User Already exists'}),
    }
