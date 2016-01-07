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
    from azure.mgmt.compute import ComputeManagementClient

    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False


def check_azure_result(module, result):
    if result.status_code != 200:
        module.fail_json(msg='Got error code from Azure, status code = {}'.format(result.status_code))


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


def update_vm_tags(module, compute_client):
    location = module.params.get('location')
    group_name = module.params.get('resource_group')
    vm_name = module.params.get('name')
    tags = module.params.get('tags')

    # check vm existence
    result = compute_client.virtual_machines.get(group_name, vm_name)
    if result.status_code != 200:
        module.fail_json(msg='Found no VM named \'{}\' in resource group \'{}\''.format(vm_name, group_name))

    vm = result.virtual_machine

    changed = False
    for tag in tags:
        if tag not in vm.tags or vm.tags[tag] != tags[tag]:
            changed = True
            vm.tags[tag] = tags[tag]

    if not changed:
        module.exit_json(changed=False, vm_name=vm.name, vm_tags=vm.tags)

    result = compute_client.virtual_machines.create_or_update(
        group_name,
        azure.mgmt.compute.VirtualMachine(
            location=location,
            name=vm_name,
            tags=vm.tags
        ),
    )

    if result.status_code != 200:
        module.fail_json(msg='Failed to update virtual machine tags, status code = {}'.format(result.status_code))

    result = compute_client.virtual_machines.get(group_name, vm_name)
    if result.status_code != 200:
        module.fail_json(msg='Failed to get back the virtual machine, status code = {}'.format(result.status_code))

    return result.virtual_machine


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            tags=dict(required=True),

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
    vm = update_vm_tags(module, compute_client)

    module.exit_json(changed=True, vm_name=vm.name, vm_tags=vm.tags)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()