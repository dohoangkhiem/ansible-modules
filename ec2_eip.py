#!/usr/bin/python
DOCUMENTATION = '''
---
module: ec2_eip
short_description: associate an EC2 elastic IP with an instance.
description:
    - This module associates AWS EC2 elastic IP addresses with instances
version_added: 1.4
options:
  instance_id:
    description:
      - The EC2 instance id
    required: false
  public_ip:
    description:
      - The elastic IP address to associate with the instance.
      - If absent, allocate a new address
    required: false
  state:
    description:
      - If present, associate the IP with the instance.
      - If absent, disassociate the IP with the instance.
    required: false
    choices: ['present', 'absent']
    default: present
  region:
    description:
      - the EC2 region to use
    required: false
    default: null
    aliases: [ ec2_region ]
  in_vpc:
    description:
      - allocate an EIP inside a VPC or not
    required: false
    default: false
    version_added: "1.4"
  reuse_existing_ip_allowed:
    description:
      - Reuse an EIP that is not associated to an instance (when available), instead of allocating a new one.
    required: false
    default: false
    version_added: "1.6"
  wait_timeout:
    description:
      - how long to wait in seconds for newly provisioned EIPs to become available
    default: 300
    version_added: "1.7"

extends_documentation_fragment: aws
author: Lorin Hochstein <lorin@nimbisservices.com>
notes:
   - This module will return C(public_ip) on success, which will contain the
     public IP address associated with the instance.
   - There may be a delay between the time the Elastic IP is assigned and when
     the cloud instance is reachable via the new address. Use wait_for and pause
     to delay further playbook execution until the instance is reachable, if
     necessary.
'''

EXAMPLES = '''
- name: associate an elastic IP with an instance
  ec2_eip: instance_id=i-1212f003 ip=93.184.216.119

- name: disassociate an elastic IP from an instance
  ec2_eip: instance_id=i-1212f003 ip=93.184.216.119 state=absent

- name: allocate a new elastic IP and associate it with an instance
  ec2_eip: instance_id=i-1212f003

- name: allocate a new elastic IP without associating it to anything
  action: ec2_eip
  register: eip
- name: output the IP
  debug: msg="Allocated IP is {{ eip.public_ip }}"

- name: another way of allocating an elastic IP without associating it to anything
  ec2_eip: state='present'

- name: provision new instances with ec2
  ec2: keypair=mykey instance_type=c1.medium image=ami-40603AD1 wait=yes group=webserver count=3
  register: ec2
- name: associate new elastic IPs with each of the instances
  ec2_eip: "instance_id={{ item }}"
  with_items: ec2.instance_ids

- name: allocate a new elastic IP inside a VPC in us-west-2
  ec2_eip: region=us-west-2 in_vpc=yes
  register: eip
- name: output the IP
  debug: msg="Allocated IP inside a VPC is {{ eip.public_ip }}"
'''

try:
    import boto.ec2
    HAS_BOTO = True
except ImportError:
    HAS_BOTO = False

wait_timeout = 0  

def associate_ip_and_instance(ec2, address, instance_id, module):
    if ip_is_associated_with_instance(ec2, address.public_ip, instance_id, module):
        module.exit_json(changed=False, public_ip=address.public_ip)

    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(changed=True)

    try:
        if address.domain == "vpc":
            res = ec2.associate_address(instance_id, allocation_id=address.allocation_id)
        else:
            res = ec2.associate_address(instance_id, public_ip=address.public_ip)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))
    
    if res:
        module.exit_json(changed=True, public_ip=address.public_ip)
    else:
        module.fail_json(msg="association failed")


def disassociate_ip_and_instance(ec2, address, instance_id, module):
    if not ip_is_associated_with_instance(ec2, address.public_ip, instance_id, module):
        module.exit_json(changed=False, public_ip=address.public_ip)

    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(changed=True)

    try:
        if address.domain == "vpc":
            res = ec2.disassociate_address(association_id=address.association_id)
        else:
            res = ec2.disassociate_address(public_ip=address.public_ip)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if res:
        module.exit_json(changed=True)
    else:
        module.fail_json(msg="disassociation failed")


def associate_ip_and_eni(ec2, module, address, eni_id, private_ip_address=None):
    if ip_is_associated_with_eni(ec2, address.public_ip, eni_id, module):
        module.exit_json(changed=False, public_ip=address.public_ip)

    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(changed=True)


    try:
        if address.domain == "vpc":
            res = ec2.associate_address(network_interface_id=eni_id,
                                        allocation_id=address.allocation_id,
                                        private_ip_address=private_ip_address)
        else:
            res = ec2.associate_address(network_interface_id=eni_id,
                                        public_ip=address.public_ip,
                                        private_ip_address=private_ip_address)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if res:
        module.exit_json(changed=True, public_ip=address.public_ip)
    else:
        module.fail_json(msg="association failed")


def disassociate_ip_and_eni(ec2, address, eni_id, module):
    if not ip_is_associated_with_eni(ec2, address.public_ip, eni_id, module):
        module.exit_json(changed=False, public_ip=address.public_ip)

    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(changed=True)

    try:
        if address.domain == "vpc":
            res = ec2.disassociate_address(association_id=address.association_id)
        else:
            res = ec2.disassociate_address(public_ip=address.public_ip)
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if res:
        module.exit_json(changed=True)
    else:
        module.fail_json(msg="disassociation failed")

def find_address(ec2, public_ip, module, fail_on_not_found=True):
    """ Find an existing Elastic IP address """  
    if wait_timeout != 0:
        timeout = time.time() + wait_timeout
        while timeout > time.time():
            try:
                addresses = ec2.get_all_addresses([public_ip])
                break
            except boto.exception.EC2ResponseError, e:
                if "Address '%s' not found." % public_ip in e.message :
                    if not fail_on_not_found:
                        return None
                else:
                    module.fail_json(msg=str(e.message))
            time.sleep(5)
        
        if timeout <= time.time():
            module.fail_json(msg = "wait for EIPs timeout on %s" % time.asctime())    
    else:
        try:
            addresses = ec2.get_all_addresses([public_ip])
        except boto.exception.EC2ResponseError, e:
            if "Address '%s' not found." % public_ip in e.message :
                if not fail_on_not_found:
                    return None
            module.fail_json(msg=str(e.message))

    return addresses[0]


def ip_is_associated_with_instance(ec2, public_ip, instance_id, module):
    """ Check if the elastic IP is currently associated with the instance """
    address = find_address(ec2, public_ip, module)
    if address:
        return address.instance_id == instance_id
    else:
        return False


def ip_is_associated_with_eni(ec2, public_ip, eni_id, module):
    address = find_address(ec2, public_ip, module)
    if address:
        return address.network_interface_id == eni_id
    else:
        return False

def instance_is_associated(ec2, instance, module):
    """
    Check if the given instance object is already associated with an
    elastic IP
    """
    instance_ip = instance.ip_address
    if not instance_ip:
        return False
    eip = find_address(ec2, instance_ip, module, fail_on_not_found=False)
    return (eip and (eip.public_ip == instance_ip))


def eni_is_associated(ec2, eni, module):
    pass

def allocate_address(ec2, domain, module, reuse_existing_ip_allowed):
    """ Allocate a new elastic IP address (when needed) and return it """
    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(change=True)

    if reuse_existing_ip_allowed:
      if domain:
        domain_filter = { 'domain' : domain }
      else:
        domain_filter = { 'domain' : 'standard' }
      all_addresses = ec2.get_all_addresses(filters=domain_filter)

      unassociated_addresses = filter(lambda a: not a.instance_id, all_addresses)
      if unassociated_addresses:
        address = unassociated_addresses[0];
      else:
        address = ec2.allocate_address(domain=domain)
    else:
      address = ec2.allocate_address(domain=domain)

    return address


def release_address(ec2, public_ip, module):
    """ Release a previously allocated elastic IP address """
    
    address = find_address(ec2, public_ip, module)
    
    # If we're in check mode, nothing else to do
    if module.check_mode:
        module.exit_json(change=True)
    
    res = address.release()    
    if res:
        module.exit_json(changed=True)
    else:
        module.fail_json(msg="release failed")


def find_instance(ec2, instance_id, module):
    """ Attempt to find the EC2 instance and return it """
    
    try:
        reservations = ec2.get_all_reservations(instance_ids=[instance_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))
    
    if len(reservations) == 1:
        instances = reservations[0].instances
        if len(instances) == 1:
            return instances[0]
    
    module.fail_json(msg="could not find instance" + instance_id)

def find_eni(ec2, eni_id, module):
    try:
        enis = ec2.get_all_network_interfaces(network_interface_ids=[eni_id])
    except boto.exception.EC2ResponseError, e:
        module.fail_json(msg=str(e))

    if enis:
        return enis[0]

    module.fail_json(msg="could not find network interface {}".format(eni_id))

def allocate_eip(ec2, eip_domain, module, reuse_existing_ip_allowed, new_eip_timeout):
    # Allocate a new elastic IP
    address = allocate_address(ec2, eip_domain, module, reuse_existing_ip_allowed)
    # overriding the timeout since this is a a newly provisioned ip
    global wait_timeout
    wait_timeout = new_eip_timeout
    return address


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
            instance_id = dict(required=False),
            eni_id = dict(required=False),
            private_ip_address = dict(required=False, default=None),
            public_ip = dict(required=False, aliases= ['ip']),
            state = dict(required=False, default='present',
                         choices=['present', 'absent']),
            in_vpc = dict(required=False, type='bool', default=False),
            reuse_existing_ip_allowed = dict(required=False, type='bool', default=False),
            wait_timeout = dict(default=300),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    if not HAS_BOTO:
        module.fail_json(msg='boto required for this module')

    ec2 = ec2_connect(module)

    instance_id = module.params.get('instance_id')
    eni_id = module.params.get('eni_id')
    private_ip_address = module.params.get('private_ip_address')
    public_ip = module.params.get('public_ip')
    state = module.params.get('state')
    in_vpc = module.params.get('in_vpc')
    domain  = "vpc" if in_vpc else None
    reuse_existing_ip_allowed = module.params.get('reuse_existing_ip_allowed')
    new_eip_timeout = int(module.params.get('wait_timeout'))

    if state == 'present':
        # If both instance_id and public_ip are not specified, allocate a new
        # elastic IP, and exit.
        if not instance_id and not public_ip and not eni_id:
            address = allocate_eip(ec2, domain, module,
                                   reuse_existing_ip_allowed, new_eip_timeout)
            module.exit_json(changed=True, public_ip=address.public_ip)

        # Return the EIP object since we've been given a public IP
        if public_ip:
            address = find_address(ec2, public_ip, module)

        if instance_id:
            if not public_ip:
                instance = find_instance(ec2, instance_id, module)

                if instance.vpc_id:
                    domain = "vpc"

                # Do nothing if the instance is already associated with an
                # elastic IP.
                if instance_is_associated(ec2, instance, module):
                    module.exit_json(changed=False, public_ip=instance.ip_address)

                # If the instance is not already associated with an elastic IP,
                # allocate a new one.
                address = allocate_eip(
                    ec2, domain, module, reuse_existing_ip_allowed, new_eip_timeout)

            # Associate address object (provided or allocated) with instance
            associate_ip_and_instance(ec2, address, instance_id, module)

        if eni_id:
            if not public_ip:
                eni = find_eni(ec2, eni_id, module)

                if eni.vpc_id:
                    domain = "vpc"

                # lacks a check if eni already associated with an eip

                address = allocate_eip(ec2, domain, module, reuse_existing_ip_allowed, new_eip_timeout)
            associate_ip_and_eni(ec2, module, address, eni_id, private_ip_address)

    else:
        #disassociating address from instance
        if instance_id:
            address = find_address(ec2, public_ip, module)
            disassociate_ip_and_instance(ec2, address, instance_id, module)

        elif eni_id:
            address = find_eni(ec2, public_ip, module)
            disassociate_ip_and_eni(ec2, address, eni_id, module)
        #releasing address
        else:
            release_address(ec2, public_ip, module)


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
