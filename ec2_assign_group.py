#!/usr/bin/python

__author__ = 'khiem'

DOCUMENTATION = '''
---
module: ec2_assign_group
short_description: associate/disassociate EC2 security group from instance
description:
    - This module associates/disassociates EC2 security group from instance
options:
  instance_id:
    description:
      - The EC2 instance id
    required: true
  group_id:
    description:
      - The security group ID
    required: false
  group_name:
    description:
      - The security group name, must be specified if group_id is not specified
    required: false
  vpc_id:
    description:
      - VPC ID, must be specified in case using group_name
    required: false
  state:
    description:
      - If present, associate the security group with the instance.
      - If absent, disassociate the security group with the instance.
    required: false
    choices: ['present', 'absent']
    default: present

author: Do Hoang Khiem <dohoangkhiem@gmail.com>
'''

EXAMPLES = '''
- name: detach security group from instance
      ec2_assign_group: instance_id={{ instance_id }}
                        group_name="PRODUCTION/CUSTOMERS/{{ customer_name }}"
                        vpc_id="{{ ec2_vpc }}"
                        region="{{ ec2_region | default('us-east-1') }}"
                        state=absent
'''

try:
    import boto.ec2
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def get_vpc_groups(ec2, module, group_names, vpc_id):
    try:
        return ec2.get_all_security_groups(filters={'group-name': group_names, 'vpc_id': vpc_id})
    except boto.exception.EC2ResponseError, e:
        #module.fail_json(msg=str(e))
        return None

def assign_group(ec2, module, instance_id, group_id=None, group_name=None, vpc_id=None):
    # retrieve instance
    try:
        instances = ec2.get_only_instances(instance_ids=[instance_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if not instances:
        module.fail_json(msg="Could not find instance with id '{}'".format(instance_id))

    instance = instances[0]

    # get group_id from group_name
    if not group_id:
        sgs = get_vpc_groups(ec2, module, [group_name], vpc_id)

        if not sgs:
            module.fail_json(msg="Could not find group name '{}' in VPC '{}'".format(group_name, vpc_id))
        group_id = sgs[0].id

    groups = instance.groups
    group_ids = [gr.id for gr in groups]

    if group_id in group_ids:
        module.exit_json(changed=False)
        return

    group_ids.append(group_id)

    try:
        return ec2.modify_instance_attribute(instance_id, 'groupSet', group_ids)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))


def de_assign_group(ec2, module, instance_id, group_id=None, group_name=None, vpc_id=None):
    # retrieve instance
    try:
        instances = ec2.get_only_instances(instance_ids=[instance_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if not instances:
        module.fail_json(msg="Could not find instance with id '{}'".format(instance_id))

    instance = instances[0]

    # get group_id from group_name
    if not group_id:
        sgs = get_vpc_groups(ec2, module, [group_name], vpc_id)

        if not sgs:
            # module.fail_json(msg="Could not find group name '{}' in VPC '{}'".format(group_name, vpc_id))
            module.exit_json(changed=False, msg="Could not find group name '{}' in VPC '{}'".format(group_name, vpc_id))

        group_id = sgs[0].id

    groups = instance.groups
    group_ids = [gr.id for gr in groups]

    if group_id not in group_ids:
        module.exit_json(changed=False)
        return

    group_ids.remove(group_id)

    try:
        return ec2.modify_instance_attribute(instance_id, 'groupSet', group_ids)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            instance_id=dict(required=True),
            group_id=dict(),
            group_name=dict(),
            vpc_id=dict(),
            state=dict(default='present', choices=['present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    ec2 = ec2_connect(module)

    state = module.params.get('state')
    instance_id = module.params.get('instance_id')
    group_id = module.params.get('group_id')
    group_name = module.params.get('group_name')
    vpc_id = module.params.get('vpc_id')

    if not group_id and not group_name:
        module.fail_json(msg="Must specify either group_id or group_name")

    if not group_id and group_name and not vpc_id:
        module.fail_json(msg="Must specify vpc_id with group_name")

    if state == 'present':
        result = assign_group(ec2, module, instance_id, group_id, group_name, vpc_id)

    if state == 'absent':
        result = de_assign_group(ec2, module, instance_id, group_id, group_name, vpc_id)

    if not result:
        module.exit_json(changed=False, msg="No exception occurred but EC2 returned unsuccessful code")

    module.exit_json(changed=True)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *


if __name__ == '__main__':
    main()