# ElasticSearch Watcher Converter

This python application connects to an ElasticSearch cluster and queries the `.watches` index for all watchers. It can also optionally connect to a CHAOSSEARCH environment and create the watchers as monitors.

## Requirements

This application has been tested on Python 3.9.7 and should function on any Python 3+ version. The elasticsearch python library version 7.15.1 has been tested with this code.

## Parameters

The following parameters are available:

| Parameter | Required? | Description |
|-----------|-----------|-------------|
| es_auth_type | Yes | The type of authentication to use for connecting to the ElasticSearch cluster. Options are: `http_auth`, `http_auth_ssl`, `api_key`, and `none` |
| es_http_auth_user | No | The ElasticSearch user id when the `es_auth_type` is `http_auth` or `http_auth_ssl` |
| es_http_auth_secret | No | The ElasticSearch secret (password) for the user id |
| es_ssl_cafile | No | The full path to the private key file when the `es_auth_type` is `http_auth_ssl` |
| es_api_key_id | No | The api key id when the `es_auth_type` is `api_key` |
| es_api_key | No | The api key when the `es_auth_type` is `api_key` |
| es_host | Yes | The ElasticSearch host to connect to |
| es_port | No | The ElasticSearch port. Default is 9200 |
| es_scheme | No | The ElasticSearch scheme (method). Options are `http` and `https` with `http` being the default |
| monitor_api_url | No | The CHAOSSEARCH api url for creating monitors |
| destination_api_url | No | The CHAOSSEARCH api url for creating destinations |
| cs_route_token | No | The CHAOSSEARCH route token for the x-amz-chaossumo-route-token header |
| cs_jwt_token_url | No | The CHAOSSEARCH url for retrieving a jwt token |
| cs_creds_file | No | The json file containing credentials for authenticating into CHAOSSEARCH |
| api | No | Indicates if api calls will be made to CHAOSSEARCH to create the monitors and destinations |
| export_watchers_to_file | No | Indicates if the ElasticSearch watchers will be exported as json files |

## Examples

### Connect to a local ElasticSearch instance with no authentication and export watchers as json files

`python main.py --es_auth_type none --es_host localhost --export_watchers_to_file`

### Connect to a local ElasticSearch instance with no authentication and create the monitors and destinations in CHAOSSEARCH lab

`python main.py --es_auth_type none --es_host localhost --monitor_api_url https://lab.chaossearch.io/kibana/api/alerting/monitors --destination_api_url https://lab.chaossearch.io/kibana/api/alerting/destinations --cs_route_token 52c1bb5a-553c-4987-a2d9-d3b2f6c49769 --cs_jwt_token_url https://lab.chaossearch.io/User/login --cs_creds_file /Users/teddong/Downloads/creds.json --api`

## Limitations

ElasticSearch watchers support threshold alerts and custom advanced watches in JSON. This code has only been tested with threshold alerts. Additionally, ElasticSearch watches support the following actions:

* Email
* Logging
* Slack
* Webhook
* Index
* PagerDuty
* Jira

CHAOSSEARCH adds another layer called destinations and only the following destinations can be created:

* Amazon Chime
* Slack
* Custom Webhook

As such, not all actions in an ElasticSearch watcher will be able to be converted to a destination (action) in CHAOSSEARCH
