# Chaos API

This python application uses ChaosSearch API's to perform various operations on object groups and views.

The following can be performed:
- Get a list of object groups / views
- Delete an object group / view
- Update a view
    - Modify the object group(s) for the view
    - Modify the name of the view

## Requirements

This application has been tested on Python 3.9.7 and should function on any Python 3+ version. 

## Parameters

The following parameters are available:

| Parameter | Required? | Description |
|-----------|-----------|-------------|
| host | Yes | The name of the host |
| accesskey | Yes | The ChaosSearch API access key |
| secretkey | Yes | The ChaosSearch API secret key |
| region | Yes | The AWS region |
| action | No | The action to take. Options are: `list`, `update`, `delete` |
| type | No | The type of object. Options are: `object-group`, `view` |
| key | Yes | The name of the object to take action on |
| name | No | The new name for the view |
| sources | No | A comma separated list of object groups for the updated view |
| force | No | Option to recursively delete indexes when deleting an object group |

## Examples

### Get the details of an object group or view

The response from the api call will be logged in the chaos-api.log file.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action list --key my-object-group
```

### Delete an object group

If the object group contains indexes those will be deleted recursively if the `--force` flag is used. Additionally, if the object group is used in any view(s), those views will be modified to remove reference to the objedt group being deleted or will be deleted if the object group is the only one in the view.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action delete --type object-group --key my-object-group --force
```

### Delete a view

If the view being deleted is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action delete --type view --key my-view
```

### Modify a view and change its sources (object groups)

The list of sources (object groups) are passed in as a comma separated list.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action update --type view --key my-view --sources "object-group-1, object-group-2"
```

### Modify a view and change its name

If the view being modified is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view. This is because the original view is not actually renamed but rather a new view is created and the old view is deleted.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action update --type view --key my-view --name my-new-name-view
```

### Modify a view and change its name and its sources (object groups)

If the view being modified is referenced in any visualization or saved search then this api call will fail. As a workaround, visualizations and saved searches need to be modified to temporarily point to a different or dummy view. This is because the original view is not actually renamed but rather a new view is created and the old view is deleted.

```
python main.py --host lab.chaossearch.io --accesskey <redacted> --secretkey <redacted> --region us-east-1 --action update --type view --key my-view --name my-new-name-view --sources "object-group-1, object-group-2"
```
