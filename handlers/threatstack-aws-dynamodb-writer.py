# Publish a Threat Stack alert received via SNS to S3.
import boto3
import json
import logging
import os

log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.root.setLevel(logging.getLevelName(log_level))
_logger = logging.getLogger(__name__)

# Initialize DDT resoruces
AWS_DYNAMODB_TABLE_NAME = os.environ.get('AWS_DYNAMODB_TABLE_NAME')
AWS_DYNAMODB_HASH_KEY =os.environ.get('AWS_DYNAMODB_HASH_KEY')

# NOTE: Using the resource instead of the client makes writing data easier
# because the Table resource will convert our JSON to DDT JSON.
dynamodb = boto3.resource('dynamodb')
ddt = dynamodb.Table('AWS_DYNAMODB_TABLE_NAME')

def _sanitize_alert_data(value):
    '''DynamoDB can't handle empty strings so convert to null'''
    if isinstance(value, dict):
        for k, v in value.items():
            value[k] = _sanitize_alert_data(v)
    elif isinstance(value, list) or isinstance(value, tuple):
        # copy alert and create new list or something...
        new_value = []
        for v in value:
            new_value.append(_sanitize_alert_data(v))
        value = new_value
    else:
        if value == "":
            value = None
    return value

def _put_ddt_item(event_message):
    '''Write an alert to DynamoDB.'''
    message = json.loads(event_message)
    alert_id = message.get('alert').get('id')
    message[AWS_DYNAMODB_HASH_KEY] = alert_id

    # Handle DynamoDBisms until DynamoDB can handle empty strings
    message = _sanitize_alert_data(message)
    _logger.debug('sanitized message: {}'.format(json.dumps(message)))

    resp = ddt.put_item(
        TableName=AWS_DYNAMODB_TABLE_NAME,
        Item=message
    )

    return resp

def handler(event, context):
    _logger.debug('handler(): event={}'.format(json.dumps(event)))
    event_message = event.get('Records')[0].get('Sns').get('Message')
    _logger.info('handler(): event.message={}'.format(event_message))

    # Put item.
    dynamodb_response = _put_ddt_item(event_message)

    # Return repsonse
    response = {
        'dynamodb': dynamodb_response
    }

    _logger.info('handler(): response={}'.format(json.dumps(response)))
    return response

