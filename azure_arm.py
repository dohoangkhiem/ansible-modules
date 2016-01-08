#!/usr/bin/env python
# -*- coding: utf-8 -*-


__author__ = 'khiem'


import os
import requests


from distutils.version import LooseVersion

try:
    import azure

    from azure.common import AzureException as AzureException
    from azure.common import AzureMissingResourceHttpError as AzureMissingException

    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.network import NetworkResourceProviderClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute import OSProfile, LinuxConfiguration, SshConfiguration, SshPublicKey, \
        OSDisk, VirtualHardDisk, StorageProfile, NetworkProfile, VirtualMachineSizeTypes

    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


def check_azure_result(module, result, operation=None, info=None):
    if result.status_code != 200 and result.status_code != 201:
        module.fail_json(msg='Got Azure error code, status code = {}, operation = {}, {}'
                         .format(result.status_code, operation, info))


def get_azure_creds(module):
    subscription_id = module.params.get('subscription_id')
    if not subscription_id:
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
    if not subscription_id:
        module.fail_json(msg="No subscription_id provided. Please set 'AZURE_SUBSCRIPTION_ID' or use the 'subscription_id' parameter")

    oauth2_token_endpoint = module.params.get('oauth2_token_endpoint')
    if not oauth2_token_endpoint:
        oauth2_token_endpoint = os.environ.get('AZURE_OAUTH2_TOKEN_ENDPOINT', None)
    if not oauth2_token_endpoint:
        module.fail_json(msg="No OAuth2 token endpoint provided. Please set 'AZURE_OAUTH2_TOKEN_ENDPOINT' or "
                             "use the 'oauth2_token_endpoint' parameter")

    client_id = module.params.get('client_id')
    if not client_id:
        client_id = os.environ.get('AZURE_CLIENT_ID', None)
    if not client_id:
        module.fail_json(msg="No client_id provided. Please set 'AZURE_CLIENT_ID' or use the 'client_id' parameter")

    client_secret = module.params.get('client_secret')
    if not client_secret:
        client_secret = os.environ.get('AZURE_CLIENT_SECRET', None)
    if not client_secret:
        module.fail_json(msg="No client_secret provided. Please set 'AZURE_CLIENT_SECRET' environment variable or "
                             "use the 'client_secret' parameter")

    return subscription_id, oauth2_token_endpoint, client_id, client_secret


def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/',
    }
    response = requests.post(endpoint, data=payload).json()
    return response['access_token']


def create_network_interface(module, network_client):
    location = module.params.get('location')
    group_name = module.params.get('resource_group')
    network_name = module.params.get('virtual_network')
    subnet_name = module.params.get('subnet')
    interface_name = module.params.get('name') + '_nic'
    ip_name = module.params.get('name') + '_ip'
    static_public_ip = module.params.get('static_public_ip')

    result = network_client.subnets.get(group_name, network_name, subnet_name)
    check_azure_result(module, result)

    subnet = result.subnet

    result = network_client.public_ip_addresses.create_or_update(
        group_name,
        ip_name,
        azure.mgmt.network.PublicIpAddress(
            location=location,
            public_ip_allocation_method='Static' if static_public_ip else 'Dynamic',
            idle_timeout_in_minutes=4,
        ),
    )
    check_azure_result(module, result, 'create_or_update_public_ip_address',
                       'ip_name={} is_static={}'.format(ip_name, static_public_ip))

    result = network_client.public_ip_addresses.get(group_name, ip_name)
    check_azure_result(module, result, 'get_public_ip_address', 'ip_name=' + ip_name)

    public_ip = result.public_ip_address
    public_ip_id = public_ip.id

    result = network_client.network_interfaces.create_or_update(
        group_name,
        interface_name,
        azure.mgmt.network.NetworkInterface(
            name=interface_name,
            location=location,
            ip_configurations=[
                azure.mgmt.network.NetworkInterfaceIpConfiguration(
                    name='default',
                    private_ip_allocation_method=azure.mgmt.network.IpAllocationMethod.dynamic,
                    subnet=subnet,
                    public_ip_address=azure.mgmt.network.ResourceId(
                        id=public_ip_id,
                    ),
                ),
            ],
        ),
    )
    check_azure_result(module, result, 'create_or_update_network_interface',
                       'interface_name={} subnet={} public_ip_id={}'.format(interface_name, subnet, public_ip_id))

    result = network_client.network_interfaces.get(
        group_name,
        interface_name,
    )
    check_azure_result(module, result, 'get_network_interface', 'interface_name={}'.format(interface_name))

    return result.network_interface, public_ip


def build_os_profile(admin_username, admin_password, computer_name,
                     admin_ssh_public_key_file=None, disable_password_auth=True):
    if admin_password:
        os_profile = OSProfile(admin_username=admin_username,
                                                  admin_password=admin_password,
                                                  computer_name=computer_name)
    elif admin_ssh_public_key_file:
        with open(admin_ssh_public_key_file, 'r') as f:
            public_key_data = f.read()
            ssh_config = SshConfiguration(public_keys=[SshPublicKey(key_data=public_key_data,
                                                                    path='/home/{}/.ssh/authorized_keys'
                                                                         .format(admin_username))])
            linux_configuration = LinuxConfiguration(disable_password_authentication=disable_password_auth,
                                                     ssh_configuration=ssh_config)
            os_profile = OSProfile(admin_username=admin_username,
                                   linux_configuration=linux_configuration,
                                   computer_name=computer_name)
    return os_profile


def build_storate_profile(os_disk_name, storage_name, source_image_uri, os_type, image_publisher, image_offer, image_sku, image_version):
    if source_image_uri:
        storage_profile=azure.mgmt.compute.StorageProfile(
            os_disk=azure.mgmt.compute.OSDisk(
                operating_system_type=os_type,
                caching=azure.mgmt.compute.CachingTypes.none,
                create_option=azure.mgmt.compute.DiskCreateOptionTypes.from_image,
                name=os_disk_name,
                virtual_hard_disk=azure.mgmt.compute.VirtualHardDisk(
                    uri='https://{0}.blob.core.windows.net/vhds/{1}.vhd'.format(
                        storage_name,
                        os_disk_name,
                    ),
                ),
                source_image=azure.mgmt.compute.VirtualHardDisk(
                    uri=source_image_uri,
                ),
            ),
        )
    else:
        storage_profile=azure.mgmt.compute.StorageProfile(
            os_disk=azure.mgmt.compute.OSDisk(
                caching=azure.mgmt.compute.CachingTypes.none,
                create_option=azure.mgmt.compute.DiskCreateOptionTypes.from_image,
                name=os_disk_name,
                virtual_hard_disk=azure.mgmt.compute.VirtualHardDisk(
                    uri='https://{0}.blob.core.windows.net/vhds/{1}.vhd'.format(
                        storage_name,
                        os_disk_name,
                    ),
                ),
            ),
            image_reference = azure.mgmt.compute.ImageReference(
                publisher=image_publisher,
                offer=image_offer,
                sku=image_sku,
                version=image_version,
            ),
        )
    return storage_profile


def create_virtual_machine(module, compute_client, nic):
    location = module.params.get('location')
    group_name = module.params.get('resource_group')
    vm_name = module.params.get('name')
    tags = module.params.get('tags')
    vm_size = module.params.get('vm_size')

    admin_username = module.params.get('username')
    admin_password = module.params.get('password')
    computer_name = module.params.get('computer_name') or vm_name
    admin_ssh_public_key_file = module.params.get('ssh_public_key_file')
    disable_password_auth = module.params.get('disable_password_auth')

    os_disk_name = vm_name + '_disk'
    storage_account = module.params.get('storage_account')

    source_image_uri = module.params.get('source_image_uri')
    os_type = module.params.get('os_type')
    image_publisher = module.params.get('image_publisher')
    image_offer = module.params.get('image_offer')
    image_sku = module.params.get('image_sku')
    image_version = module.params.get('image_version')

    if not admin_password and not admin_ssh_public_key_file:
        module.fail_json(msg='Either password or ssh_public_key_file must be specified')

    os_profile = build_os_profile(admin_username, admin_password, computer_name,
                                  admin_ssh_public_key_file, disable_password_auth)

    storage_profile = build_storate_profile(os_disk_name, storage_account, source_image_uri, os_type, image_publisher, image_offer, image_sku, image_version)

    network_profile = azure.mgmt.compute.NetworkProfile(
        network_interfaces=[
            azure.mgmt.compute.NetworkInterfaceReference(
                reference_uri=nic.id,
            ),
        ],
    )

    result = compute_client.virtual_machines.create_or_update(
        group_name,
        azure.mgmt.compute.VirtualMachine(
            location=location,
            name=vm_name,
            os_profile=os_profile,
            hardware_profile=azure.mgmt.compute.HardwareProfile(
                virtual_machine_size=vm_size
            ),
            network_profile=network_profile,
            storage_profile=storage_profile,
            tags=tags
        ),
    )

    check_azure_result(module, result, 'create_or_update_virtual_machine', 'vm_name={}'.format(vm_name))

    result = compute_client.virtual_machines.get(group_name, vm_name)
    check_azure_result(module, result, 'get_virtual_machine', 'vm_name={}'.format(vm_name))

    return result.virtual_machine


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            username=dict(required=True),
            password=dict(),
            computer_name=dict(),
            ssh_public_key_file=dict(),
            disable_password_auth=dict(type='bool', default=True),
            tags=dict(),
            static_public_ip=dict(type='bool', default=True),
            vm_size=dict(default='Standard_A2', choices=[VirtualMachineSizeTypes.basic_a0,
                                                         VirtualMachineSizeTypes.basic_a1,
                                                         VirtualMachineSizeTypes.basic_a2,
                                                         VirtualMachineSizeTypes.basic_a3,
                                                         VirtualMachineSizeTypes.basic_a4,
                                                         VirtualMachineSizeTypes.standard_a0,
                                                         VirtualMachineSizeTypes.standard_a1,
                                                         VirtualMachineSizeTypes.standard_a2,
                                                         VirtualMachineSizeTypes.standard_a3,
                                                         VirtualMachineSizeTypes.standard_a4,
                                                         VirtualMachineSizeTypes.standard_a5,
                                                         VirtualMachineSizeTypes.standard_a6,
                                                         VirtualMachineSizeTypes.standard_a7,
                                                         VirtualMachineSizeTypes.standard_a8,
                                                         VirtualMachineSizeTypes.standard_a9,
                                                         VirtualMachineSizeTypes.standard_g1,
                                                         VirtualMachineSizeTypes.standard_g2,
                                                         VirtualMachineSizeTypes.standard_g3,
                                                         VirtualMachineSizeTypes.standard_g4,
                                                         VirtualMachineSizeTypes.standard_g5,
                                                         ]),

            # vm image
            source_image_uri=dict(),
            os_type=dict(default='Linux', choices=['Linux', 'Windows']),
            image_publisher=dict(),
            image_offer=dict(),
            image_sku=dict(),
            image_version=dict(),

            state=dict(default='present', choices=['present', 'absent']),
            wait=dict(type='bool', default=False),
            wait_timeout=dict(default=600),
            wait_timeout_redirects=dict(default=300),

            # prerequisite resources
            resource_group=dict(required=True),
            virtual_network=dict(),
            subnet=dict(),
            security_group=dict(),
            storage_account=dict(required=True),
            location=dict(default='eastus'),

            # for credentials
            subscription_id=dict(no_log=True),
            oauth2_token_endpoint=dict(no_log=True),
            client_id=dict(no_log=True),
            client_secret=dict(no_log=True),
        )
    )

    if not HAS_AZURE:
        module.fail_json(msg='azure python module required for this module')

    source_image_uri = module.params.get('source_image_uri')
    image_publisher = module.params.get('image_publisher')
    image_offer = module.params.get('image_offer')
    image_sku = module.params.get('image_sku')
    image_version = module.params.get('image_version')

    state = module.params.get('state')
    if state == 'absent':
        module.fail_json(changed=False, msg='Unsupported state')

    if not source_image_uri:
        if not image_publisher or not image_offer or not image_sku or not image_version:
            module.fail_json(changed=False, msg='Either (source_image_uri, os_type) or (image_publisher, image_offer, image_sku, image_version) must be specified')

    subscription_id, oauth2_token_endpoint, client_id, client_secret = get_azure_creds(module)
    auth_token = get_token_from_client_credentials(oauth2_token_endpoint, client_id, client_secret)

    creds = SubscriptionCloudCredentials(subscription_id, auth_token)

    compute_client = ComputeManagementClient(creds)
    network_client = NetworkResourceProviderClient(creds)

    nic, public_ip = create_network_interface(module, network_client)
    vm = create_virtual_machine(module, compute_client, nic)
    public_ip = network_client.public_ip_addresses\
        .get(module.params.get('resource_group'), public_ip.name).public_ip_address

    module.exit_json(changed=True, vm_name=vm.name, network_interface=nic.name, public_ip_name=public_ip.name,
                     public_ip_address=public_ip.ip_address)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()