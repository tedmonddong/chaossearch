# Chaos API

This python application uses ChaosSearch API's to perform various operations on object groups and views.

The following can be performed:
- Get a list of object groups / views
- Create an object group / view
- Delete object group(s) / view(s)
- Update a view
    - Modify the object group(s) for the view
    - Modify the name of the view

## Requirements

This application has been tested on Python 3.9.7 and should function on any Python 3+ version. 

## Setup 

This application can be configured to point to different environments via `.env` files. The env files must contain the following information:
- host - The name of the host to execute the api call
- access_key - The CHAOSSEARCH Access Key ID
- secret_key - The CHAOSSEARCH Secret Access Key
- object_group_region - The AWS region where object groups are stored
- view_region - The AWS region where views are stored

Note that in most cases the object_group_region and the view_region will be the same region but there are rare instances where they also may be different, hence the different settings.

Here is a sample of what the `.env` file should look like:
```buildoutcfg
host=lab.chaossearch.io
access_key=<redacted>
secret_key=<redacted>
object_group_region=us-east-1
view_region=us-east-1
```
You can have multiple `.env` files that point to different environments. For example, an env file can be configured to point to the development environment. To do this simply create an env file in the format:
```commandline
.env.<name>
```
Where name is the identifier for the environment parameter (see next section)
## Parameters

The following parameters are available:

| Parameter | Required? | Description |
|-----------|-----------|-------------|
| environment | No | The name of the environment file |
| action | No | The action to take. Options are: `list`, `update`, `delete`, `create` |
| type | Yes | The type of object. Options are: `object-group`, `view` |
| keys | Yes | Comma separated list of object groups or views |
| name | No | The new name for the view |
| sources | No | A comma separated list of object groups for the updated view |
| payload | No | Full path to a JSON file containing the payload of the object group or view to create |
| force | No | Option to recursively delete indexes when deleting an object group |

## Examples

### Get the details of an object group or view
The response from the api call will be logged in the chaos-api.log file.
```commandline
python main.py --action list --type object-group --keys my-object-group
```
#### Multiple object groups / views
You can pass in a comma separated list of multiple object groups or views to execute the `/V1` api 
```commandline
python main.py --action list --type object-group --keys my-object-group-1,my-object-group-2,my-object-group-3
```
#### Test environment
You can point to a different `.env` file by using the `--environment` parameter. This example will look for the `.env.test` file
```commandline
python main.py --env test --action list --type object-group --keys my-object-group-1
```
### Create an object group
Pass in the json payload containing the definition of the object group to be created
```commandline
python main.py --action create --type object-group --payload /path/to/payload.json
```
### Create a view
Pass in the json payload containing the definition of the view to be created
```commandline
python main.py --action create --type view --payload /path/to/payload.json
```
### Delete an object group
If the object group contains indexes those will be deleted recursively if the `--force` flag is used. Additionally, if the object group is used in any view(s), those views will be modified to remove reference to the objedt group being deleted or will be deleted if the object group is the only one in the view.
```commandline
python main.py --action delete --type object-group --keys my-object-group --force
```
#### Multiple object groups
You can pass in a comma separated list of multiple object groups to delete
```commandline
python main.py. --action delete --type object-group --keys my-og-1,my-og-2,my-og-3 --force 
```
### Delete a view
If the view being deleted is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view.
```commandline
python main.py --action delete --type view --keys my-view
```
#### Multiple views
You can pass in a comma separated list of multiple views to delete
```commandline
python main.py. --action delete --type view --keys my-view-1,my-view-2,my-view-3 --force 
```
### Update a view and change its sources (object groups)
The new list of sources (object groups) are passed in as a comma separated list via the `sources` parameter. If the view being modified is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view. This is because the original view is not actually renamed but rather a new view is created and the old view is deleted.
```commandline
python main.py --action update --type view --keys my-view --sources "object-group-1,object-group-2"
```
### Update a view and change its name
The new name is passed in via the `name` parameter. If the view being modified is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view. This is because the original view is not actually renamed but rather a new view is created and the old view is deleted.
```commandline
python main.py --action update --type view --keys my-view --name my-new-name-view
```
### Update a view and change its name and its sources (object groups)
The new list of sources (object groups) are passed in as a comma separated list via the `sources` parameter and the new name is passed in via the `name` parameter. If the view being modified is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view. This is because the original view is not actually renamed but rather a new view is created and the old view is deleted.
```commandline
python main.py --action update --type view --keys my-view --name my-new-name-view --sources "object-group-1,object-group-2"
```
