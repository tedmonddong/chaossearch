import argparse
import json
import logging
import requests
import time
import xmltodict
from lowercase_booleans import true, false
from requests_aws4auth import AWS4Auth


host = ""
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}
force = false


def parse_args():
    parser = argparse.ArgumentParser(description='Call ChaosSearch API')
    parser.add_argument('--host', required=True, help='The hostname')
    parser.add_argument('--accesskey', required=True, help='Your AWS access key id')
    parser.add_argument('--secretkey', required=True, help='Your AWS secret key id')
    parser.add_argument('--region', required=True, help='The AWS region')
    parser.add_argument('--action', required=False, choices=('create', 'update', 'delete', 'list'), default='list',
                        help='The action to take')
    parser.add_argument('--type', required=False, choices=('object-group', 'view'), default='view')
    parser.add_argument('--key', required=False, help='The name of the object group or view')
    parser.add_argument('--name', required=False, help='New name for the view')
    parser.add_argument('--sources', required=False, help='Comma separated list of object groups for the view')
    parser.add_argument('--force', action="store_true", required=False, help='Forces delete (will recursively delete indexes)')
    return parser.parse_args()


def main():
    logging.info("Main: Start")
    args = parse_args()
    global host
    global force
    host = args.host
    access_key = args.accesskey
    secret_key = args.secretkey
    region = args.region
    service = "s3"
    action = args.action
    type = args.type
    key = args.key
    name = args.name
    sources = args.sources
    force = args.force
    aws_auth = AWS4Auth(access_key, secret_key, region, service)
    if action == "list":
        print("Retrieving key details...")
        key_json = get_key(aws_auth=aws_auth, name=key, type=type)
        logging.info(f"Key json: {key_json}")
    elif action == "create":
        print("Create action has not been implemented")
    elif action == "update":
        print(f"Starting update of {key}...")
        key_json = get_key(aws_auth=aws_auth, name=key, type=type)
        logging.info(f"Key json: {key_json}")
        if type == "view":
            print("Creating view payload...")
            view_payload = create_view_payload(name=key, view_json=key_json, name_update=name, source_update=sources)
            logging.info(f"View payload: {view_payload}")
            print("Updating view...")
            update_view(aws_auth=aws_auth, payload=view_payload, name=key, type=type)
            if name is not None:
                print("Deleting old view...")
                results = delete_key(aws_auth=aws_auth, name=key, type="view", stop=True)
    elif action == "delete":
        print(f"Starting delete of {key}...")
        if force:
            print(f"Deleting indexes in {key}", end='', flush=True)
            indexes_json = get_index(aws_auth=aws_auth, name=key)
            logging.info(f"Indexes as json: {indexes_json}")
            key_count = int(indexes_json["ListBucketResult"]["KeyCount"])
            if key_count > 0:
                delete_index(aws_auth=aws_auth, keys=indexes_json["ListBucketResult"]["Contents"])
                print(".")
                # wait 30 seconds for the system to finish deleting the last few indexes
                print("Finalizing delete...")
                time.sleep(30)
            else:
                print(".")
        print("Deleting key...")
        results = delete_key(aws_auth=aws_auth, name=key, type=type, stop=True)
        if results is not None:
            for result in results:
                # update views to remove the og
                key_json = get_key(aws_auth=aws_auth, name=result, type="view")
                logging.info(f"Key json: {key_json}")
                print("Creating view payload...")
                view_payload = create_view_payload(name=result, view_json=key_json, name_update=None, source_update=sources)
                logging.info(f"View payload: {view_payload}")
                print("Updating view...")
                update_view(aws_auth=aws_auth, payload=view_payload, name=key, type=type)

    print("Done!")
    logging.info("Main: End")


def get_key(aws_auth, name, type):
    url = f"https://{host}/V1/{name}"
    if type == "view":
        url = url + "?tagging"
    logging.info(f"Posting request {url}")
    response = requests.request("GET", url, headers=headers, auth=aws_auth)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    return json.loads(json.dumps(xmltodict.parse(response.text), indent=3))


def get_index(aws_auth, name):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-amz-chaossumo-bucket-transform": "indexed"
    }
    url = f"https://{host}/V1/{name}?list-type=2&delimiter=%2F&max-keys=1000"
    logging.info(f"Posting request {url}")
    response = requests.request("GET", url, headers=headers, auth=aws_auth)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    return json.loads(json.dumps(xmltodict.parse(response.text), indent=3))


def delete_key(aws_auth, name, type, stop):
    url = f"https://{host}/V1/{name}"
    logging.info(f"Posting request {url}")
    response = requests.request("DELETE", url, headers=headers, auth=aws_auth)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        if response.status_code == 409:
            error_json = json.loads(json.dumps(xmltodict.parse(response.text), indent=3))
            error_message = error_json["Error"]["Message"]
            logging.info(f"Error message: {error_message}")
            if type == "object-group":
                message = error_message.split("bucket:")
                if len(message) == 2:
                    view_keys = message[1].split(",")
                    print(view_keys)
                    return view_keys
        if stop:
            raise Exception(f"non-200 response code: {error_message}")
    else:
        logging.info(f"Successful request: {type} {name} deleted")
    return None


def delete_index(aws_auth, keys):
    for key in keys:
        print(".", end='', flush=True)
        results = delete_key(aws_auth=aws_auth, name=key["Key"], type="index", stop=False)


def create_view_payload(name, view_json, name_update, source_update):
    transform, time_field, index_pattern = "", "", ""
    case_insensitive, cacheable = false, false
    tags = view_json["Tagging"]["TagSet"]["Tag"]
    for tag in tags:
        key_name = tag["Key"]
        key_value = tag["Value"]
        if key_name == "cs3.transform":
            transform = json.loads(key_value)
        elif key_name == "cs3.case-insensitive":
            if key_value == "true":
                case_insensitive = true
            else:
                case_insensitive = false
        elif key_name == "cs3.index-retention":
            index_retention = int(key_value)
        elif key_name == "cs3.time-field":
            time_field = key_value
        elif key_name == "cs3.index-pattern":
            index_pattern = key_value
        elif key_name == "cs3.cacheable":
            if key_value == "true":
                cacheable = true
            else:
                cacheable = false
        elif key_name == "cs3.parent":
            source_list = key_value.split(",")
    # apply updates
    if source_update is not None:
        source_list_update = source_update.split(",")
    else:
        source_list_update = source_list
    if name_update is not None:
        new_name = name_update
    else:
        new_name = name
    view_payload = {
        "bucket": new_name,
        "transforms": transform,
        "caseInsensitive": case_insensitive,
        "indexRetention": index_retention,
        "timeFieldName": time_field,
        "indexPattern": index_pattern,
        "cacheable": cacheable,
        "sources": source_list_update,
        "overwrite": true
    }
    return json.loads(json.dumps(view_payload))


def update_view(aws_auth, payload, name, type):
    url = f"https://{host}/Bucket/createView"
    logging.info(f"Posting request {url}")
    response = requests.request("POST", url, headers=headers, auth=aws_auth, json=payload)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info(f"Successful request: {type} {name} updated")


def get_bucket_metadata(aws_auth, name):
    url = f"https://{host}/Bucket/metadata"
    logging.info(f"Posting request {url}")
    payload = {"BucketNames": [name]}
    logging.info(f"Payload: {payload}")
    response = requests.request("POST", url, headers=headers, auth=aws_auth, data=payload)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")


if __name__ == '__main__':
    try:
        fmt = "%(asctime)s: %(message)s"
        logging.basicConfig(format=fmt, level=logging.INFO, filename='chaos-api.log')
        main()
    except (KeyboardInterrupt, EOFError):
        print("CTRL+C caught, exiting")
    except Exception as e:
        print("Failed. Reason %s" % str(e))