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


def add_tags(gce, module, instance_name, tags):
    """Add tags to instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not tags:
        module.fail_json(msg='Must supply tags', changed=False)

    tags = [x.lower() for x in tags]

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_tags = node.extra['tags']
    changed = False
    tags_changed = []

    for t in tags:
        if t not in node_tags:
            changed = True
            node_tags.append(t)
            tags_changed.append(t)

    if not changed:
        return False, None

    try:
        gce.ex_set_node_tags(node, node_tags)
        return True, tags_changed
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def remove_tags(gce, module, instance_name, tags, regex):
    """Remove tags from instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not tags:
        module.fail_json(msg='Must supply tags', changed=False)

    tags = [x.lower() for x in tags]

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_tags = node.extra['tags']

    changed = False
    tags_changed = []

    for t in tags:
        if t in node_tags:
            node_tags.remove(t)
            changed = True
            tags_changed.append(t)

    if regex and node_tags:
        try:
            for t in node_tags:
                if re.match(regex, t):
                    node_tags.remove(t)
                    changed = True
                    tags_changed.append(t)
        except re.error as e:
            module.fail_json(msg='Regex error: {}'.format(e), changed=False)

    if not changed:
        return False, None

    try:
        gce.ex_set_node_tags(node, node_tags)
        return True, tags_changed
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            instance_name=dict(required=True),
            tags=dict(type='list'),
            regex=dict(default=None, required=False),
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
    tags = module.params.get('tags')
    zone = module.params.get('zone')
    regex = module.params.get('regex')
    changed = False

    if not zone:
        module.fail_json(msg='Must specify a "zone"', changed=False)

    if state == 'present' and not tags:
        module.fail_json(msg='Must specify "tags"', changed=False)

    if state == 'absent' and not tags and not regex:
        module.fail_json(msg='Must specify "tags" or "regex"', changed=False)

    gce = gce_connect(module)

    # add tags to instance.
    if state == 'present':
        changed, tags_changed = add_tags(gce, module, instance_name, tags)

    # remove tags from instance
    if state == 'absent':
        changed, tags_changed = remove_tags(gce, module, instance_name, tags, regex)

    module.exit_json(changed=changed, instance_name=instance_name, tags=tags_changed, zone=zone)
    sys.exit(0)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.gce import *

if __name__ == '__main__':
    main()