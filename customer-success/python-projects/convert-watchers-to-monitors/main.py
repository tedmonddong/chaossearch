#!/usr/bin/env python
import argparse
import json
import logging
import re
import requests
from os.path import exists
from elasticsearch import Elasticsearch
from ssl import create_default_context
# from elasticsearch.client import WatcherClient


monitor_api_url = None
destination_api_url = None
api = False
cs_route_token = None
cs_security_token = None
cs_jwt_token_url = None
cs_creds_file = None
export_watchers_to_file = False


def parse_args():
    parser = argparse.ArgumentParser(description='Convert Elastic Alerts to CS Monitors')
    parser.add_argument('--es_auth_type', required=True, choices=('http_auth', 'http_auth_ssl', 'api_key', 'none'), default='none', help='The type of ES authentication')
    parser.add_argument('--es_http_auth_user', required=False, help='The ES user id')
    parser.add_argument('--es_http_auth_secret', required=False, help='The ES user secret')
    parser.add_argument('--es_ssl_cafile', required=False, help='The full path to the private certificate file')
    parser.add_argument('--es_api_key_id', required=False, help='The ES API key id')
    parser.add_argument('--es_api_key', required=False, help='The ES API key')
    parser.add_argument('--es_host', required=True, help='The ES host')
    parser.add_argument('--es_port', required=False, default='9200', help='The ES port (9200 - default')
    parser.add_argument('--es_scheme', required=False, choices=('http', 'https'), default='http', help='The ES scheme (http - default)')
    parser.add_argument('--monitor_api_url', required=False, default='', help='The CS api url for creating monitors')
    parser.add_argument('--destination_api_url', required=False, default='', help='The CS api url for creating destinations')
    parser.add_argument('--cs_route_token', required=False, help='The CS route token for the x-amz-chaossumo-route-token header')
    parser.add_argument('--cs_jwt_token_url', required=False, help='The CS url to retrieve the security token from')
    parser.add_argument('--cs_creds_file', required=False, help='The file containing the login credentials for CS')
    parser.add_argument('--api', action='store_true', required=False, help='Indicates if the monitors/destinations should be created using api calls')
    parser.add_argument('--export_watchers_to_file', action='store_true', required=False, help='Export each ES watcher as a json file')
    return parser.parse_args()


def main():
    logging.info("Starting main")
    args = parse_args()
    logging.info(f'arguments: {args}')
    global monitor_api_url
    global destination_api_url
    global api
    global cs_route_token
    global cs_security_token
    global cs_jwt_token_url
    global cs_creds_file
    global export_watchers_to_file
    es_auth_type = args.es_auth_type
    es_http_auth_user = args.es_http_auth_user
    es_http_auth_secret = args.es_http_auth_secret
    es_ssl_cafile = args.es_ssl_cafile
    es_api_key_id = args.es_api_key_id
    es_api_key = args.es_api_key
    es_host = args.es_host
    es_port = args.es_port
    es_scheme = args.es_scheme
    monitor_api_url = args.monitor_api_url
    destination_api_url = args.destination_api_url
    api = args.api
    cs_route_token = args.cs_route_token
    cs_jwt_token_url = args.cs_jwt_token_url
    cs_creds_file = args.cs_creds_file
    if cs_jwt_token_url is not None and cs_jwt_token_url != '' \
            and cs_creds_file is not None and cs_creds_file != '':
        cs_security_token = get_security_token(cs_jwt_token_url, cs_creds_file)
    export_watchers_to_file = args.export_watchers_to_file
    # Find out about authentication at EFX
    if es_auth_type == 'none':
        es = Elasticsearch([es_host], scheme=es_scheme, port=es_port)
    elif es_auth_type == 'http_auth':
        es = Elasticsearch([es_host], scheme=es_scheme, port=es_port,
                           http_auth=(es_http_auth_user, es_http_auth_secret))
    elif es_auth_type == 'http_auth_ssl':
        context = create_default_context(cafile=es_ssl_cafile)
        es = Elasticsearch([es_host], scheme=es_scheme, port=es_port,
                           http_auth=(es_http_auth_user, es_http_auth_secret),
                           ssl_context=context)
    elif es_auth_type == 'api_key':
        es = Elasticsearch([es_host], scheme=es_scheme, port=es_port,
                           api_key=(es_api_key_id, es_api_key))
    # es = Elasticsearch([es_host], scheme=es_scheme, port=es_port)
    res = es.search(index=".watches", query={"match_all": {}})
    logging.info(f'Elasticsearch response: {res}')
    convert_watcher(res)
    logging.info("Ending main")


def get_security_token(token_url, creds_file):
    logging.info('Getting security token')
    file_exists = exists(creds_file)
    if file_exists:
        with open(creds_file, 'r') as file:
            creds_data = json.loads(file.read())
            header = {"x-amz-chaossumo-route-token": "login",
                      "Content-Type": "application/json"}
            logging.info(f'   Posting json: {creds_data}')
            response = requests.post(token_url, json=creds_data, verify=False, headers=header)
            response_status_code = response.status_code
            logging.info(f'cs jwt token response code: {response_status_code}')
            logging.info(f'cs jwt token api response: {response.text}')
            if response_status_code == 200:
                token = json.loads(response.text)['Token']
                return token
            else:
                raise Exception('Response code %s received while attempting to retrieve CS token', response_status_code)
    else:
        logging.info(f'Creds file {cs_creds_file} not found')
    return ""


def convert_watcher(watches):
    logging.info('Converting ES Watcher to CS Alert')
    json_obj = json.loads(json.dumps(watches))
    hits_total = json_obj['hits']['total']['value']
    logging.info(f'Total number of watchers found: {hits_total}')
    if hits_total > 0:
        hits = json_obj['hits']['hits']
        logging.info(f'hits: {hits}')
        for hit in hits:
            logging.info(f'hit: {hit}')
            hit_source = hit['_source']
            watcher_name = hit_source['metadata']['name']
            monitor_name = watcher_name + '-monitor'
            watcherui = hit_source['metadata']['watcherui']
            request = hit_source['input']['search']['request']

            # Write the original ES json if specified
            if export_watchers_to_file:
                file_name = watcher_name + ".json"
                logging.info(f'Exporting original ES json file: {file_name}')
                with open(file_name, 'w') as file:
                    file.write(json.dumps(hit, indent=3))

            logging.info(f'Extracting data from ES json:')
            logging.info(f'   monitor_name: {monitor_name}')
            interval = hit_source['trigger']['schedule']['interval']
            logging.info(f'   interval: {interval}')
            interval_regex = "(?P<interval>\d+)(?P<unit>\w+)"
            match = re.match(r"%s" % interval_regex, interval)
            if match:
                match_dict = match.groupdict()
                logging.info(f'   match_dict: {match_dict}')
                interval_value = match_dict['interval']
                logging.info(f'   interval_value: {interval_value}')
                interval_unit = match_dict['unit']
                logging.info(f'   interval_unit: {interval_unit}')
                if interval_unit == "s":
                    interval_unit_name = "SECONDS"
                elif interval_unit == "m":
                    interval_unit_name = "MINUTES"
                elif interval_unit == "h":
                    interval_unit_name = "HOURS"
                elif interval_unit == "d":
                    interval_unit_name = "DAYS"
                logging.info(f'   interval_unit_name: {interval_unit_name}')
            indices = request['indices']
            logging.info(f'   indices: {indices}')
            size = request['body']['size']
            logging.info(f'   size: {size}')
            timestamp_field = next(iter(request['body']['query']['bool']['filter']['range']))
            logging.info(f'   timestamp_field: {timestamp_field}')
            timestamp_gte = request['body']['query']['bool']['filter']['range'][f'{timestamp_field}']['gte']
            logging.info(f'   timestamp_gte: {timestamp_gte}')
            timestamp_from = timestamp_gte.replace('ctx.trigger.scheduled_time', 'period_end')
            logging.info(f'   timestamp_from: {timestamp_from}')
            timestamp_lte = request['body']['query']['bool']['filter']['range'][f'{timestamp_field}']['lte']
            logging.info(f'   timestamp_lte: {timestamp_lte}')
            timestamp_to = timestamp_lte.replace('ctx.trigger.scheduled_time', 'period_end')
            logging.info(f'   timestamp_to: {timestamp_to}')
            trigger_name = monitor_name + "-trigger"
            logging.info(f'   trigger_name: {trigger_name}')
            trigger_source = hit_source['condition']['script']['source']
            logging.info(f'   trigger_source: {trigger_source}')
            trigger_source_regex = "if \((?P<source>.*)\)"
            match = re.match(r"%s" % trigger_source_regex, trigger_source)
            if match:
                match_dict = match.groupdict()
                logging.info(f'   match_dict: {match_dict}')
                source = match_dict['source']
                logging.info(f'   source: {source}')
                source_conv = source.replace('ctx.payload.hits.total', 'ctx.results[0].hits.total.value')
                # triggers only support ABOVE, BELOW, and EXACTLY
                source_split = source.split()
                logging.info(f'   source_split: {source_split}')
                source_comparator = source_split[1]
                if source_comparator == ">" or source_comparator == ">=":
                    trigger_enum = "ABOVE"
                elif source_comparator == "<" or source_comparator == "<=":
                    trigger_enum = "BELOW"
                elif source_comparator == "=":
                    trigger_enum = "EXACTLY"
                logging.info(f'   trigger_enum: {trigger_enum}')
            else:
                logging.info(f'   ***** Watcher contains a group over top that cannot be converted... skipping {monitor_name}')
                continue
            trigger_threshold = hit_source['condition']['script']['params']['threshold']
            logging.info(f'   trigger_threshold: {trigger_threshold}')
            source_conv = source_conv.replace('params.threshold', str(trigger_threshold))
            logging.info(f'   source_conv: {source_conv}')
            aggregation_type = watcherui['agg_type']
            logging.info(f'   aggregation_type: {aggregation_type}')
            time_field = watcherui['time_field']
            logging.info(f'   time_field: {time_field}')
            bucket_value = watcherui['time_window_size']
            logging.info(f'   bucket_value: {bucket_value}')
            bucket_uot = watcherui['time_window_unit']
            logging.info(f'   bucket_uot: {bucket_uot}')
            if 'agg_field' in watcherui and watcherui['agg_field'] is not None:
                field_name = watcherui['agg_field']
            else:
                field_name = ""
            logging.info(f'   field_name: {field_name}')
            term_size = watcherui['term_size']
            logging.info(f'   term_size: {term_size}')
            if 'term_field' in watcherui and watcherui['term_field'] is not None:
                term_field = watcherui['term_field']
            else:
                term_field = ""
            logging.info(f'   term_field: {term_field}')

            # Read in the json monitor template file
            with open('monitor-template.json', 'r') as file:
                file_data = file.read()

            # Read in the json template for actions
            with open('action-template.json', 'r') as file:
                action_template = file.read()

            # handle the actions
            conv_actions = []
            actions = iter(hit_source['actions'])
            for action in actions:
                logging.info(f'   Processing action: {action}')
                destination_name = watcher_name + '-' + action + '-destination'
                destination_template = ""
                action_json = action_template
                if action.startswith("email"):
                    email = hit_source['actions'][f'{action}']['email']
                    subject = email['subject']
                    logging.info(f'      subject: {subject}')
                    message = email['body']['text']
                    logging.info(f'      message: {message}')
                    action_json = action_json.replace('{{action_name}}', action)
                    action_json = action_json.replace('{{subject}}', subject)
                    action_json = action_json.replace('{{message}}', message)
                    #logging.info(f'      action_json: {action_json}')
                    #conv_actions.append(json.loads(action_json))
                    #continue
                elif action.startswith("index"):
                    action_index = hit_source['actions'][f'{action}']['index']['index']
                    logging.info(f'      action_index: {action_index}')
                    logging.info(f'      The action {action} is not supported. Excluding from the monitor trigger {monitor_name}')
                    continue
                elif action.startswith("logging"):
                    logging_action = hit_source['actions'][f'{action}']['logging']
                    logging_level = logging_action['level']
                    logging.info(f'      logging_level: {logging_level}')
                    logging_text = logging_action['text']
                    logging.info(f'      logging_text: {logging_text}')
                    logging.info(f'      The action {action} is not supported. Excluding from the monitor trigger {monitor_name}')
                    continue
                elif action.startswith("webhook"):
                    #webhook_name = watcher_name + '-' + action
                    webhook = hit_source['actions'][f'{action}']['webhook']
                    webhook_schema = webhook['scheme']
                    logging.info(f'      webhook_schema: {webhook_schema}')
                    webhook_host = webhook['host']
                    logging.info(f'      webhook_host: {webhook_host}')
                    webhook_port = webhook['port']
                    logging.info(f'      webhook_port: {webhook_port}')
                    webhook_method = webhook['method']
                    logging.info(f'      webhook_method: {webhook_method}')
                    webhook_path = webhook['path']
                    logging.info(f'      webhook_path: {webhook_path}')
                    if 'auth' in webhook and webhook['auth'] is not None:
                        webhook_auth_basic_username = webhook['auth']['basic']['username']
                        logging.info(f'      webhook_auth_basic_username: {webhook_auth_basic_username}')
                        webhook_auth_basic_password = webhook['auth']['basic']['password']
                        logging.info(f'      webhook_auth_basic_password: {webhook_auth_basic_password}')
                    webhook_body = json.loads(webhook['body'])['message']
                    logging.info(f'      webhook_body: {webhook_body}')
                    action_json = action_json.replace('{{message}}', webhook_body)
                    action_json = action_json.replace('{{subject}}', '')
                    with open('destination-webhook-template.json', 'r') as file:
                        destination_template = file.read()
                    #destination_webhook_name = webhook_name + '-destination'
                    webhook_url = webhook_schema.lower() + '://' + webhook_host + ':' + str(webhook_port) + '/' + webhook_path
                    destination_template = destination_template.replace('{{webhook_name}}', destination_name)
                    destination_template = destination_template.replace('{{webhook_scheme}}', webhook_schema.upper())
                    destination_template = destination_template.replace('{{webhook_method}}', webhook_method.upper())
                    destination_template = destination_template.replace('{{webhook_host}}', webhook_host)
                    destination_template = destination_template.replace('{{webhook_port}}', str(webhook_port))
                    destination_template = destination_template.replace('{{webhook_path}}', webhook_path)
                    #destination_template = destination_template.replace('{{webhook_url}}', webhook_url)
                elif action.startswith("slack"):
                    slack = hit_source['actions'][f'{action}']['slack']['message']
                    slack_to = slack['to']
                    logging.info(f'      slack_to: {slack_to}')
                    slack_text = slack['text']
                    logging.info(f'      slack_text: {slack_text}')
                    action_json = action_json.replace('{{subject}}', '')
                    action_json = action_json.replace('{{message}}', slack_text)
                    # The slack url is not available from any api call so it will have to be set in the template
                    with open('destination-slack-template.json', 'r') as file:
                        destination_template = file.read()
                    destination_template = destination_template.replace('{{slack_name}}', destination_name)
                elif action.startswith("chime"):
                    # TODO
                    continue

                # Create the destination
                destination_id = ""
                if destination_template != "":
                    file_name = destination_name + ".json"
                    logging.info(f'      Saving destination json file: {file_name}')
                    with open(file_name, 'w') as file:
                        file.write(destination_template)

                    # Make the api request to create the destination
                    if api:
                        logging.info("   Execute api call to create the new destination")
                        json_d = json.loads(destination_template)
                        # header = {"sgtenant": "privateTenant"}
                        header = {"x-amz-chaossumo-route-token": f"{cs_route_token}",
                                  "x-amz-security-token": f"{cs_security_token}"}
                        logging.info(f'   Posting json: {json_d}')
                        response = requests.post(destination_api_url, json=json_d, verify=False, headers=header)
                        response_status_code = response.status_code
                        logging.info(f'   destination api response code: {response.status_code}')
                        logging.info(f'   destination api response: {response.text}')
                        if response_status_code == 200:
                            destination_id = json.loads(response.text)['id']
                            logging.info(f'   destination id: {destination_id}')
                        else:
                            raise Exception('Response code %s received while attempting to create destination',
                                            response_status_code)


                action_json = action_json.replace('{{action_name}}', action)
                action_json = action_json.replace('{{destination_id}}', destination_id)
                logging.info(f'   action_json: {action_json}')
                conv_actions.append(json.loads(action_json))
                logging.info('   action added')

            # Replace the target strings
            file_data = file_data.replace('{{monitor_name}}', monitor_name)
            file_data = file_data.replace('{{interval_value}}', interval_value)
            file_data = file_data.replace('{{interval_unit_name}}', interval_unit_name)
            file_data = file_data.replace('{{indices}}', str(indices).replace('\'', '"'))
            file_data = file_data.replace('{{size}}', str(size))
            file_data = file_data.replace('{{timestamp_from}}', timestamp_from)
            file_data = file_data.replace('{{timestamp_to}}', timestamp_to)
            file_data = file_data.replace('{{trigger_name}}', trigger_name)
            file_data = file_data.replace('{{aggregation_type}}', aggregation_type)
            file_data = file_data.replace('{{time_field}}', time_field)
            file_data = file_data.replace('{{bucket_value}}', str(bucket_value))
            file_data = file_data.replace('{{bucket_uot}}', bucket_uot)
            file_data = file_data.replace('{{trigger_threshold}}', str(trigger_threshold))
            file_data = file_data.replace('{{trigger_enum}}', trigger_enum)
            file_data = file_data.replace('{{source_conv}}', source_conv)
            if field_name is not None:
                file_data = file_data.replace('{{field_name}}', field_name)
            file_data = file_data.replace('{{term_size}}', str(term_size))
            if term_field is not None:
                file_data = file_data.replace('{{term_field}}', term_field)
            if aggregation_type == "count":
                updated_json = json.loads(file_data)
                aggs = updated_json['inputs'][0]['search']['query']['aggregations']
                aggs.pop('when', None)
                logging.info('   Deleting the when node from aggregations')
                updated_json.update(aggs)
                logging.info(f'   updated_json: {updated_json}')
                file_data = json.dumps(updated_json, indent=3)

            # Add the actions
            conv_json = json.loads(file_data)
            logging.info(f'   Converted actions: {conv_actions}')
            conv_json['triggers'][0]['actions'].extend(conv_actions)

            # Write the monitor json file
            file_name = monitor_name + ".json"
            logging.info(f'   Saving monitor json file: {file_name}')
            with open(file_name, 'w') as file:
                file.write(json.dumps(conv_json, indent=3))

            # Make the api request to create the monitor
            if api:
                logging.info("   Execute api call to create the new monitor")
                json_d = json.loads(file_data)
                # header = {"sgtenant": "privateTenant"}
                header = {"x-amz-chaossumo-route-token": f"{cs_route_token}",
                          "x-amz-security-token": f"{cs_security_token}"}
                logging.info(f'   Posting json: {json_d}')
                response = requests.post(monitor_api_url, json=json_d, verify=False, headers=header)
                response_status_code = response.status_code
                logging.info(f'   monitor api response code: {response.status_code}')
                logging.info(f'   monitor api response: {response.text}')
                if response_status_code == 200:
                    monitor_id = json.loads(response.text)['resp']['_id']
                    logging.info(f'   monitor id: {monitor_id}')
                else:
                    raise Exception('Response code %s received while attempting to create monitor',
                                    response_status_code)

                logging.info("   Execute api call to create trigger/action")
                json_d = conv_json
                trigger_action_api_url = monitor_api_url + '/' + monitor_id
                logging.info(f'   Posting json: {json_d}')
                response = requests.put(trigger_action_api_url, json=json_d, verify=False, headers=header)
                response_status_code = response.status_code
                logging.info(f'   trigger/action api response code: {response.status_code}')
                logging.info(f'   trigger/action api response: {response.text}')
                if response_status_code == 200:
                    logging.info(f'   trigger/action api response: {response.text}')
                else:
                    raise Exception('Response code %s received while attempting to create monitor',
                                    response_status_code)

            logging.info('##########################################################################')


if __name__ == '__main__':
    try:
        fmt = "%(asctime)s: %(message)s"
        logging.basicConfig(format=fmt, level=logging.INFO, filename='convert-watcher.log')
        main()
    except (KeyboardInterrupt, EOFError):
        print("CTRL+C caught, exiting")
    except Exception as e:
        print("Failed. Reason %s" % str(e))
