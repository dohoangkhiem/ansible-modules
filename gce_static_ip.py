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


def get_instance_info(inst):
    """Retrieves instance information from an instance object and returns it
    as a dictionary.

    """
    metadata = {}
    if 'metadata' in inst.extra and 'items' in inst.extra['metadata']:
        for md in inst.extra['metadata']['items']:
            metadata[md['key']] = md['value']

    try:
        netname = inst.extra['networkInterfaces'][0]['network'].split('/')[-1]
    except:
        netname = None
    if 'disks' in inst.extra:
        disk_names = [disk_info['source'].split('/')[-1]
                      for disk_info
                      in sorted(inst.extra['disks'],
                                key=lambda disk_info: disk_info['index'])]
    else:
        disk_names = []

    if len(inst.public_ips) == 0:
        public_ip = None
    else:
        public_ip = inst.public_ips[0]

    return({
        'image': not inst.image is None and inst.image.split('/')[-1] or None,
        'disks': disk_names,
        'machine_type': inst.size,
        'metadata': metadata,
        'name': inst.name,
        'network': netname,
        'private_ip': inst.private_ips[0],
        'public_ip': public_ip,
        'status': ('status' in inst.extra) and inst.extra['status'] or None,
        'tags': ('tags' in inst.extra) and inst.extra['tags'] or [],
        'zone': ('zone' in inst.extra) and inst.extra['zone'].name or None,
        'region': ('zone' in inst.extra) and inst.extra['zone'].name[:-2] or None,
   })


def create_new_address(gce, module, address_name, region):
    try:
        return gce.ex_create_address(name=address_name, region=region)
    except ResourceExistsError as e:
        module.fail_json(msg=str(e), changed=False)
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def associate_address(gce, module, instance_name, zone, address_name=None):
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)
    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError as e:
        module.fail_json(msg=str(e), changed=False)

    if node.extra['networkInterfaces'] and 'accessConfigs' in node.extra['networkInterfaces'][0]:
        access_config_name = node.extra['networkInterfaces'][0]['accessConfigs'][0]['name']
    else:
        access_config_name = None

    try:
        if access_config_name:
            # delete current access config
            gce.ex_delete_access_config(node=node, name=access_config_name, nic='nic0')

        # create new static address
        region = ('zone' in node.extra) and node.extra['zone'].name[:-2] or None
        if not address_name:
            address_name = node.name
        address = create_new_address(gce, module, address_name, region)

        # add new access config
        gce.ex_add_access_config(node=node, name=(access_config_name or "External NAT"), nic='nic0',
                                 nat_ip=address.address)
        return True, address.address
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(),
            instance_name=dict(required=False),
            static_ip=dict(default=None),
            state=dict(default='present', choices=['present', 'absent']),
            zone=dict(default='us-central1-a'),
            service_account_email=dict(),
            pem_file=dict(),
            project_id=dict(),
        )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud with GCE support is required.')

    address_name = module.params.get('name')
    instance_name = module.params.get('instance_name')
    state = module.params.get('state')
    static_ip = module.params.get('static_ip')
    zone = module.params.get('zone')
    changed = False

    if not zone or len(zone) < 3:
        module.fail_json(msg='Must specify a valid "zone"', changed=False)

    region = zone[:-2]

    if state == 'present' and not address_name and not instance_name:
        module.fail_json(msg='Must specify address "name" or "instance_name"')

    if state == 'absent' and not static_ip:
        module.fail_json(msg='Must specify "static_ip" to disassociate', changed=False)

    gce = gce_connect(module)

    if state == 'present':
        if instance_name:
            changed, static_ip = associate_address(gce, module, instance_name, zone)
        else:
            static_ip = create_new_address(gce, module, address_name, region)
            changed = True if static_ip else False

    # remove tags from instance
    if state == 'absent':
        module.fail_json(msg='Not supported state="absent" yet', changed=False)

    module.exit_json(changed=changed, static_ip=static_ip, region=region, instance_name=instance_name, zone=zone)
    sys.exit(0)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.gce import *

if __name__ == '__main__':
    main()