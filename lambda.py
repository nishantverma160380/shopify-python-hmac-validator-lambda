import json
import hmac
import hashlib
import base64

SECRET = 'shpss_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

def lambda_handler(event, context):
    body, hmac = get_body_and_hmac(json.loads(json.dumps(event)))
    verified = verify_webhook(body.encode(), hmac.encode())
    print(verified)
    return {
        'statusCode': 200,
        'body': json.dumps('Webhook successfully verified!')
    }


def verify_webhook(data, hmac_header):
    secret = SECRET.encode()
    digest = hmac.new(key=secret, msg=data, digestmod=hashlib.sha256).digest()
    computed_hmac = base64.b64encode(digest)
    return hmac.compare_digest(computed_hmac, hmac_header)


def get_body_and_hmac(event_json):
    for key, value in event_json.items():
        if key == 'headers':
            headers_event = json.loads(json.dumps(value))
            headers_event = eval(str(headers_event).replace('",','').replace('"',''))
            for key, value in headers_event.items():
                if key.strip() == 'x-shopify-hmac-sha256':
                    hmac = json.loads(json.dumps(value.strip()))
        if key == 'body':
            body_event = json.loads(json.dumps(value))
    return body_event, hmac

