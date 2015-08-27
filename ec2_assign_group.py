#!/usr/bin/python

__author__ = 'khiem'

try:
    import boto.ec2
    from boto.exception import BotoServerError
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False


def assign_group(ec2, module, instance_id, group_id):
    # retrieve instance
    try:
        instances = ec2.get_only_instances(instance_ids=[instance_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if not instances:
        module.fail_json(msg="Could not find instance with id '{}'".format(instance_id))

    instance = instances[0]

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


def de_assign_group(ec2, module, instance_id, group_id):
    # retrieve instance
    try:
        instances = ec2.get_only_instances(instance_ids=[instance_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if not instances:
        module.fail_json(msg="Could not find instance with id '{}'".format(instance_id))

    instance = instances[0]

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
            group_id=dict(required=True),
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

    if state == 'present':
        result = assign_group(ec2, module, instance_id, group_id)

    if state == 'absent':
        result = de_assign_group(ec2, module, instance_id, group_id)

    if not result:
        module.exit_json(changed=False, msg="No exception occurred but EC2 returned unsuccessful code")

    module.exit_json(changed=True)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *


if __name__ == '__main__':
    main()