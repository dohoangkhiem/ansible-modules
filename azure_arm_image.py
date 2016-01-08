#!/usr/bin/env python
# -*- coding: utf-8 -*-


__author__ = 'khiem'


import os
import requests
import json

from distutils.version import LooseVersion

try:
    import azure

    from azure.common import AzureException as AzureException
    from azure.common import AzureMissingResourceHttpError as AzureMissingException

    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.compute import ComputeManagementClient, VirtualMachineCaptureParameters

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


def capture_vm_image(module, compute_client):
    location = module.params.get('location')
    group_name = module.params.get('resource_group')
    vm_name = module.params.get('vm_name')
    vhd_prefix = module.params.get('vhd_prefix')
    container_name = module.params.get('container_name')
    overwrite_vhds = module.params.get('overwrite_vhds')

    # check vm existence
    result = compute_client.virtual_machines.get(group_name, vm_name)
    check_azure_result(module, result, 'get_virtual_machine', 'vm_name={}'.format(vm_name))

    vm = result.virtual_machine

    result = compute_client.virtual_machines.deallocate(group_name, vm_name)
    check_azure_result(module, result, 'deallocate_virtual_machine', 'vm_name={}'.format(vm_name))

    result = compute_client.virtual_machines.generalize(group_name, vm_name)
    check_azure_result(module, result, 'generalize_virtual_machine', 'vm_name={}'.format(vm_name))

    result = compute_client.virtual_machines.capture(group_name, vm_name,
                                                     VirtualMachineCaptureParameters(
                                                         virtual_hard_disk_name_prefix=vhd_prefix,
                                                         destination_container_name=container_name,
                                                         overwrite=overwrite_vhds,
                                                     ))

    check_azure_result(module, result, 'capture_vm_image', 'vm_name={}'.format(vm_name))

    try:
        os_disk = json.loads(result.output)['resources'][0]['properties']['storage_profile']['osDisk']
        image_name = os_disk['name']
        image_uri = os_disk['image']['uri']
        module.exit_json(changed=True, vm_name=vm_name, image_name=image_name, image_uri=image_uri)
    except ValueError, e:
        module.fail_json(msg='Failed to parse capture result output, the output is below\n{}'.format(result.output))

def main():
    module = AnsibleModule(
        argument_spec=dict(
            vm_name=dict(required=True),
            vhd_prefix=dict(required=True),
            container_name=dict(required=True),
            overwrite_vhds=dict(type='bool', default=False),

            state=dict(default='present'),

            # prerequisite resources
            resource_group=dict(required=True),
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

    state = module.params.get('state')
    if state == 'absent':
        module.fail_json(msg='Unsupported state')

    subscription_id, oauth2_token_endpoint, client_id, client_secret = get_azure_creds(module)
    auth_token = get_token_from_client_credentials(oauth2_token_endpoint, client_id, client_secret)

    creds = SubscriptionCloudCredentials(subscription_id, auth_token)

    compute_client = ComputeManagementClient(creds)
    capture_vm_image(module, compute_client)


# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()