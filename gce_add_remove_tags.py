#!/usr/bin/python

__author__ = 'khiem'

import re

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.common.google import GoogleBaseError, QuotaExceededError, \
        ResourceExistsError, ResourceNotFoundError, InvalidRequestError

    _ = Provider.GCE
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False


def add_remove_tags(gce, module, instance_name, tags_add, tags_remove):
    """Add tags to instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not tags_add and not tags_remove:
        module.fail_json(msg='Must supply tags_add or tags_remove', changed=False)

    tags_add = [x.lower() for x in tags_add]
    tags_remove = [x.lower() for x in tags_remove]

    # remove same items in two lists
    for t in tags_add[:]:
        if t in tags_remove:
            tags_add.remove(t)
            tags_remove.remove(t)

    if not tags_add and not tags_remove:
        return False, None, None  # no change needed

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_tags = node.extra['tags']
    changed = False
    tags_add_changed = []
    tags_remove_changed = []

    for t in tags_add:
        if t not in node_tags:
            changed = True
            node_tags.append(t)
            tags_add_changed.append(t)

    for t in tags_remove:
        if t in node_tags:
            changed = True
            node_tags.remove(t)
            tags_remove_changed.append(t)

    if not changed:
        return False, None, None

    try:
        gce.ex_set_node_tags(node, node_tags)
        return True, tags_add_changed, tags_remove_changed
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            instance_name=dict(required=True),
            tags_add=dict(type='list'),
            tags_remove=dict(type='list'),
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
    tags_add = module.params.get('tags_add')
    tags_remove = module.params.get('tags_remove')
    zone = module.params.get('zone')
    changed = False

    if not zone:
        module.fail_json(msg='Must specify a "zone"', changed=False)

    if not tags_add and not tags_remove:
        module.fail_json(msg='Must specify "tags_add" or "tags_remove"', changed=False)

    gce = gce_connect(module)

    results = add_remove_tags(gce, module, instance_name, tags_add, tags_remove)
    changed = results[0]
    tags_add_changed = results[1]
    tags_remove_changed = results[2]

    module.exit_json(changed=changed, instance_name=instance_name, tags_add=tags_add_changed,
                     tags_remove=tags_remove_changed, zone=zone)
    sys.exit(0)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.gce import *

if __name__ == '__main__':
    main()