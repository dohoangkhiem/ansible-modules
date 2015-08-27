#!/usr/bin/python

import time
import xml.etree.ElementTree as ET
import re

try:
    import boto.ec2
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def assign_new_private_ip(ec2, module, eni_id, private_address_count):
    # retrieve Elastic Network Interface
    try:
        enis = ec2.get_all_network_interfaces(network_interface_ids=[eni_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if not enis:
        module.fail_json(msg="Couldn't find Elastic Network Interface {}".format(eni_id))

    try:
        if ec2.assign_private_ip_addresses(network_interface_id=eni_id, secondary_private_ip_address_count=private_address_count):
            enis_after = ec2.get_all_network_interfaces(network_interface_ids=[eni_id])
            eni = enis_after[0]
            new_ips = eni.private_ip_addresses[-private_address_count:]
            new_ips_info = [get_private_address_info(addr) for addr in new_ips]
            module.exit_json(changed=True, count=private_address_count, private_ip_addresses=new_ips_info)
        else:
            module.exit_json(changed=False)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))


def get_private_address_info(private_ip_address):
    private_address_info = {
        "private_ip_address": private_ip_address.private_ip_address,
        "primary": private_ip_address.primary if hasattr(private_ip_address, 'primary') else False
    }

    return private_address_info


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            network_interface_id=dict(required=True),
            private_ip_address=dict(required=False),
            state=dict(default='present', choices=['present', 'absent']),
            private_ip_address_count=dict(default=1, type='int')
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    ec2 = ec2_connect(module)

    state = module.params.get('state')
    network_interface_id = module.params.get('network_interface_id')
    private_ip_address = module.params.get('private_ip_address')
    private_ip_address_count = module.params.get('private_ip_address_count')

    if state == 'present':
        assign_new_private_ip(ec2, module, network_interface_id, private_ip_address_count)

    if state == 'absent':
        module.fail_json(msg='not supported yet')

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *


if __name__ == '__main__':
    main()