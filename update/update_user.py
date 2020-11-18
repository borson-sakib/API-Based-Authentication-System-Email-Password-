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
    sub = body['sub']
    #name= body['name']
    location= body['location']
    address= body['address']
    access_token = body['access_token']


    response_updated = client.update_user_attributes(
        UserAttributes=[
            {
                'Name': 'custom:location',
                'Value': location
            },
        ],
        AccessToken=access_token
    )



    """
    update_resp = table.update_item(
        Key={
            'sub': sub
        },
        UpdateExpression="set custom:location=:l",
        ExpressionAttributeNames={
            ':l': 'custom:location'
        },
        ExpressionAttributeValues={
            ':l': location
        },
        ReturnValues="UPDATED_NEW"
    )
    
    update_resp = table.update_item(
        Key={'sub':sub},
        AttributeUpdates={'custom:location': location,'name': name,},
    )
    """

    # get item
    update_resp = table.get_item(Key={'sub': sub})
    item = update_resp['Item']

    # update
    item['custom:location'] = location
   # item['name'] = name
    item["address"] = address

    # put (idempotent)
    table.put_item(Item=item)

    print(item)
    print(sub)
    print(update_resp)


    return {
        "statusCode": 200,
        "body": json.dumps(
            {'status': 'Successfully Updated'}
        ),
    }


