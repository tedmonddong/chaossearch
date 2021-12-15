import argparse
import json
import logging
import os.path
import requests
import time
import xmltodict
from dotenv import dotenv_values
from lowercase_booleans import true, false
from requests_aws4auth import AWS4Auth
from xml.etree import ElementTree as ET


host = ""
object_group_region = ""
view_region = ""
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}
force = false


def parse_args():
    parser = argparse.ArgumentParser(description='Call ChaosSearch API')
    # parser.add_argument('--host', required=True, help='The hostname')
    # parser.add_argument('--access_key', required=True, help='Your AWS access key')
    # parser.add_argument('--secret_key', required=True, help='Your AWS secret key')
    # parser.add_argument('--object_group_region', required=True, help='The AWS region where object groups are stored')
    # parser.add_argument('--view_region', required=True, help='The AWS region where views are stored')
    parser.add_argument('--env', required=False, help='Name of the environment to run against')
    parser.add_argument('--action', required=True, choices=('create', 'update', 'delete', 'list', 'partition'),
                        default='list', help='The action to take')
    parser.add_argument('--type', required=True, choices=('object-group', 'view'), default='view')
    parser.add_argument('--keys', required=False, help='Comma separated list of object groups or views')
    parser.add_argument('--name', required=False, help='New name for the view')
    parser.add_argument('--sources', required=False, help='Comma separated list of object groups for the view')
    parser.add_argument('--payload', required=False, help='Payload of object group or view to create')
    parser.add_argument('--force', action="store_true", required=False, help='Forces recursive delete')
    return parser.parse_args()


def main():
    logging.info("Main: Start")
    args = parse_args()
    global host
    global object_group_region
    global view_region
    global force
    env = args.env
    env_file = ".env"
    if env is not None:
        env_file = env_file + "." + env
    config = dotenv_values(env_file)
    if "host" in config.keys():
        host = config["host"]
    else:
        print(f"host is missing in {env_file}")
        logging.info(f"The host setting is missing in {env_file}")
        exit()
    if "access_key" in config.keys():
        access_key = config["access_key"]
    else:
        print(f"access_key is missing in {env_file}")
        logging.info(f"The access_key setting is missing in {env_file}")
        exit()
    if "secret_key" in config.keys():
        secret_key = config["secret_key"]
    else:
        print(f"secret_key is missing in {env_file}")
        logging.info(f"The secret_key setting is missing in {env_file}")
        exit()
    if "object_group_region" in config.keys():
        object_group_region = config["object_group_region"]
    else:
        print(f"object_group_region is missing in {env_file}")
        logging.info(f"The object_group_region setting is missing in {env_file}")
        exit()
    if "view_region" in config.keys():
        view_region = config["view_region"]
    else:
        print(f"view_region is missing in {env_file}")
        logging.info(f"The view_region setting is missing in {env_file}")
        exit()
    service = "s3"
    action = args.action
    type = args.type
    key_list = args.keys
    keys = key_list.split(",")
    name = args.name
    sources = args.sources
    payload = args.payload
    force = args.force
    aws_og_auth = AWS4Auth(access_key, secret_key, object_group_region, service)
    aws_v_auth = AWS4Auth(access_key, secret_key, view_region, service)
    if type == "view":
        aws_auth = aws_v_auth
    else:
        aws_auth = aws_og_auth
    if action == "list":
        print("Retrieving key details...")
        for key in keys:
            key_json = get_key(aws_auth=aws_auth, name=key, type=type)
            logging.info(f"Key json: {key_json}")
    elif action == "create":
        print("Starting create...")
        try:
            if os.path.exists(payload):
                with open(payload, mode='r') as file:
                    create_resp = create_key(aws_auth=aws_auth, type=type, payload=payload)
                    logging.info(f"Create response: {create_resp}")
                    file.close()
            else:
                print("The payload file is not found")
                logging.info(f"Payload file {payload} not found")
        except Exception as ex:
            print("Failed. Reason %s" % str(ex))
    elif action == "partition":
        for key in keys:
            key_json = get_partition(aws_auth=aws_auth, name=key)
            logging.info(f"Key json: {key_json}")
    elif action == "update":
        for key in keys:
            print(f"Starting update of {key}...")
            key_json = get_key(aws_auth=aws_auth, name=key, type=type)
            logging.info(f"Key json: {key_json}")
            if type == "view":
                print("Creating view payload...")
                view_payload = create_view_payload(name=key, view_json=key_json, name_update=name, source_update=sources,
                                                   source_delete=None)
                logging.info(f"View payload: {view_payload}")
                print("Updating view...")
                aws_auth = aws_v_auth
                update_view(aws_auth=aws_auth, payload=view_payload, name=key, type=type)
                if name is not None:
                    print("Deleting old view...")
                    results = delete_key(aws_auth=aws_auth, name=key, type="view", stop=True)
    elif action == "delete":
        for key in keys:
            print(f"Starting delete of {key}...")
            if force and type == "object-group":
                print(f"Deleting indexes in {key}", end='', flush=True)
                indexes_json = get_index(aws_auth=aws_auth, name=key)
                logging.info(f"Indexes as json: {indexes_json}")
                key_count = int(indexes_json["ListBucketResult"]["KeyCount"])
                if key_count > 0:
                    delete_index(aws_auth=aws_auth, keys=indexes_json["ListBucketResult"]["Contents"], num_keys=key_count)
                    print(".")
                    # wait 30 seconds for the system to finish deleting the last few indexes
                    print("Finalizing delete...")
                    time.sleep(60)
                else:
                    print(".")
            print("Deleting key...")
            results = delete_key(aws_auth=aws_auth, name=key, type=type, stop=True)
            if results is not None:
                print("One or more views is using this object group")
                for result in results:
                    # update views to remove the og
                    aws_auth = aws_v_auth
                    view_key = result.strip()
                    key_json = get_key(aws_auth=aws_auth, name=view_key, type="view")
                    logging.info(f"Key json: {key_json}")
                    print("Creating view payload...")
                    view_payload = create_view_payload(name=view_key, view_json=key_json, name_update=None,
                                                       source_update=None, source_delete=key)
                    logging.info(f"View payload: {view_payload}")
                    if len(view_payload["sources"]) > 0:
                        print("Updating view...")
                        update_view(aws_auth=aws_auth, payload=view_payload, name=view_key, type="view")
                    else:
                        print("Deleting view...")
                        delete_view_results = delete_key(aws_auth=aws_auth, name=view_key, type="view", stop=True)
                time.sleep(30)
                print("Deleting key...")
                if type == "object-group":
                    aws_auth = aws_og_auth
                results = delete_key(aws_auth=aws_auth, name=key, type=type, stop=True)
    print("Done!")
    logging.info("Main: End")


def create_key(aws_auth, type, payload):
    if type == "view":
        obj_type = "createView"
        region = view_region
    else:
        obj_type = "createObjectGroup"
        region = object_group_region
    url = f"https://{region}-{host}/Bucket/{obj_type}"
    logging.info(f"Sending request {url}")
    # payload = {
    #     "bucket": name,
    #     "source": "chaosdemo-datasets",
    #     "format":{
    #         "_type": "JSON",
    #         "stripPrefix": true,
    #         "horizontal": false
    #     },
    #     "interval": {
    #         "mode": 0,
    #         "column": 0
    #     },
    #     "indexRetention":{
    #         "overall":-1,
    #         "forPartition": [
    #             {
    #                 "key": ["DescribeLoadBalancers", "DescribeEnvironments", "DescribeVpcs", "GetDomainNames", "DescribeVpcEndpoints"],
    #                 "days": -1
    #             }
    #        ]
    #     },
    #     "filter": [
    #         {
    #            "field": "key",
    #            "prefix": "cloudtrail/AWSLogs/250787501321/CloudTrail/us-west-2"
    #         },
    #         {
    #            "field": "key",
    #            "regex": ".*"
    #         }
    #     ],
    #     "options":{
    #        "ignoreIrregular": true,
    #        "compression": "GZIP"
    #     },
    #     "partitionBy": "eventName\":\"(\w*)",
    #     "overwrite": true
    # }
    response = requests.request("POST", url, headers=headers, auth=aws_auth, json=payload)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    return response.text


def get_partition(aws_auth, name):
    url = f"https://{host}/Bucket/partitionKeys"
    logging.info(f"Sending request {url}")
    body = {
        "bucket": name
    }
    response = requests.request("POST", url, headers=headers, auth=aws_auth, json=body)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    return response.text


def get_region(aws_auth):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-amz-chaossumo-bucket-tagging": "true"
    }
    url = f"https://{object_group_region}={host}/V1/"
    logging.info(f"Sending get request {url}")
    response = requests.request("GET", url, headers=headers, auth=aws_auth)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    bucketsjson = []
    xmldoc = ET.fromstring(response.text)
    bucketsxml = xmldoc.findall('.//{http://s3.amazonaws.com/doc/2006-03-01}Buckets/')
    for bucket in bucketsxml:
        bucketinfo = {}
        foundtype = false
        foundvisible = false
        name = bucket.find('.//{http://s3.amazonaws.com/doc/2006-03-01}Name').text
        creationdate = bucket.find('.//{http://s3.amazonaws.com/doc/2006-03-01}CreationDate').text
        bucketinfo["name"] = name
        bucketinfo["creationdate"] = creationdate
        tags = bucket.findall('.//{http://s3.amazonaws.com/doc/2006-03-01}Tag')
        for tag in tags:
            key = tag.find('.//{http://s3.amazonaws.com/doc/2006-03-01}Key').text
            value = tag.find('.//{http://s3.amazonaws.com/doc/2006-03-01}Value').text
            if key == "cs3.bucket-type" and value == "object-group":
                foundtype = true
            if key == "cs3.visible":
                foundvisible = true
            bucketinfo[key] = value
        if foundtype and foundvisible:
            bucketsjson.append(bucketinfo)
    objectgroups = [b for b in bucketsjson]
    for objectgroup in objectgroups:
        region = objectgroup["cs3.region"]
    return response.text


def get_key(aws_auth, name, type):
    if type == "object-group":
        region = object_group_region
    else:
        region = view_region
    url = f"https://{region}-{host}/V1/{name}"
    if type == "view":
        url = url + "?tagging"
    logging.info(f"Sending get {type} request {url}")
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
    url = f"https://{object_group_region}-{host}/V1/{name}?list-type=2&delimiter=%2F&max-keys=1000"
    logging.info(f"Sending get request {url}")
    response = requests.request("GET", url, headers=headers, auth=aws_auth)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info("Successful request")
    return json.loads(json.dumps(xmltodict.parse(response.text), indent=3))


def delete_key(aws_auth, name, type, stop):
    if type == "object-group" or type == "index":
        region = object_group_region
    else:
        region = view_region
    url = f"https://{region}-{host}/V1/{name}"
    logging.info(f"Sending delete {type} request {url}")
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
                    return view_keys
        if stop:
            raise Exception(f"non-200 response code: {response.text}")
    else:
        logging.info(f"Successful request: {type} {name} deleted")
    return None


def delete_index(aws_auth, keys, num_keys):
    if num_keys == 1:
        print(".", end='', flush=True)
        results = delete_key(aws_auth=aws_auth, name=keys["Key"], type="index", stop=False)
    else:
        for key in keys:
            print(".", end='', flush=True)
            results = delete_key(aws_auth=aws_auth, name=key["Key"], type="index", stop=False)


def create_view_payload(name, view_json, name_update, source_update, source_delete):
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
        elif key_name == "cs3.filter":
            view_filter = json.loads(key_value)
    # apply updates
    if source_update is not None:
        source_list_update = source_update.split(",")
    elif source_delete is not None:
        source_list_delete = [source_delete]
        source_list_update = list(set(source_list) ^ set(source_list_delete))
    else:
        source_list_update = source_list
    logging.info(f"Updated source list: {source_list_update}")
    if name_update is not None:
        new_name = name_update
    else:
        new_name = name
    logging.info(f"Updated name: {new_name}")
    view_payload = {
        "bucket": new_name,
        "transforms": transform,
        "caseInsensitive": case_insensitive,
        "indexRetention": index_retention,
        "timeFieldName": time_field,
        "indexPattern": index_pattern,
        "cacheable": cacheable,
        "sources": source_list_update,
        "filter": view_filter,
        "overwrite": true
    }
    return json.loads(json.dumps(view_payload))


def update_view(aws_auth, payload, name, type):
    url = f"https://{view_region}-{host}/Bucket/createView"
    logging.info(f"Sending post request {url}")
    response = requests.request("POST", url, headers=headers, auth=aws_auth, json=payload)
    if response.status_code != 200:
        logging.info(f"Request failed: http response code = {response.status_code}, response text = {response.text}")
        raise Exception("non-200 response code")
    else:
        logging.info(f"Successful request: {type} {name} updated")


if __name__ == '__main__':
    try:
        fmt = "%(asctime)s: %(message)s"
        logging.basicConfig(format=fmt, level=logging.INFO, filename='chaos-api.log')
        main()
    except (KeyboardInterrupt, EOFError):
        print(",")
        print("CTRL+C caught, exiting")
    except Exception as e:
        print(".")
        print("Failed. Reason %s" % str(e))