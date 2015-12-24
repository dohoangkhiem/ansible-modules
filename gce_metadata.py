#!/usr/bin/python
from ast import literal_eval

__author__ = 'khiem'

import json

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.common.google import GoogleBaseError, QuotaExceededError, \
        ResourceExistsError, ResourceNotFoundError, InvalidRequestError

    _ = Provider.GCE
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False


def update_metadata(gce, module, instance_name, metadata):
    """Add tags to instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not metadata:
        module.fail_json(msg='Must supply metadata', changed=False)

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_metadata = node.extra['metadata']['items']
    changed = False
    changed_items = []

    metadata_dict = {}

    for item in node_metadata:
        metadata_dict[item['key']] = item['value']

    for key in metadata:
        value = metadata[key]
        if key not in metadata_dict or (key in metadata_dict and value != metadata_dict[item['key']]):
            changed = True
            changed_items.append(key)

        metadata_dict[key] = value

    if not changed:
        return False, None

    try:
        gce.ex_set_node_metadata(node, metadata_dict)
        return True, changed_items
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)



def main():
    module = AnsibleModule(
        argument_spec=dict(
            instance_name=dict(required=True),
            metadata=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            zone=dict(default='us-central1-a'),
            service_account_email=dict(),
            pem_file=dict(),
            project_id=dict(),
        )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud with GCE support is required.')

    instance_name = module.params.get('instance_name')
    state = module.params.get('state')
    metadata = module.params.get('metadata')
    zone = module.params.get('zone')
    changed = False

    if not zone:
        module.fail_json(msg='Must specify a "zone"', changed=False)

    if state == 'absent':
        module.fail_json(msg='Not support state=absent', changed=False)

    if isinstance(metadata, str):
        try:
            metadata = literal_eval(metadata)
            if not isinstance(metadata, dict):
                module.fail_json(msg='metadata must be a dict', changed=False)
        except ValueError, e:
            module.fail_json(msg='bad metadata: {}'.format(e), changed=False)
        except SyntaxError, e:
            module.fail_json(msg='bad metadata syntax', changed=False)
    elif not isinstance(metadata, dict):
        module.fail_json(msg='metadata must be a dict', changed=False)

    gce = gce_connect(module)

    if state == 'present':
        changed, changed_items = update_metadata(gce, module, instance_name, metadata)

    module.exit_json(changed=changed, instance_name=instance_name, changed_items=changed_items, zone=zone)
    sys.exit(0)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.gce import *

if __name__ == '__main__':
    main()