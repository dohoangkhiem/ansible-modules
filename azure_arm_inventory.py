#!/usr/bin/env python

__author__ = 'khiem'

import sys
import ConfigParser
import os
import requests
import json

try:
    import azure as windows_azure

    from azure.common import AzureException as AzureException
    from azure.common import AzureMissingResourceHttpError as AzureMissingException

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
except ImportError, e:
    print e
    print('Azure Inventory requires \'azure\' package installed\n')
    sys.exit(1)


class AzureInventory():

    def __init__(self):
        self.read_settings()
        subscription_id, oauth2_token_endpoint, client_id, client_secret = self.get_azure_creds()
        auth_token = self.get_token_from_client_credentials(oauth2_token_endpoint, client_id, client_secret)

        creds = SubscriptionCloudCredentials(subscription_id, auth_token)

        self.resource_client = ResourceManagementClient(creds)
        self.compute_client = ComputeManagementClient(creds)
        self.network_client = NetworkResourceProviderClient(creds)

        print(self.json_format_dict(self.build_inventory(), True))
        sys.exit(0)

    def build_inventory(self):
        groups = {}
        meta = {
            'hostvars': {}
        }

        if 'azure_vars' in self.config.sections():
            azure_vars = dict(self.config.items('azure_vars'))

        # get all resource groups
        result = self.resource_client.resource_groups.list(None)
        self.check_azure_result(result, 'list_groups')
        for group in result.resource_groups:
            group_name = group.name

            groups[group_name] = []

            # list vm
            result = self.compute_client.virtual_machines.list(group_name)
            self.check_azure_result(result, 'list_virtual_machines', 'group_name={}'.format(group_name))

            for vm in result.virtual_machines:
                vm_name = vm.name

                # add vm to the group of this resource group
                groups[group_name].append(vm_name)

                vm = self.compute_client.virtual_machines.get(group_name, vm_name).virtual_machine
                vm_dict = self.vm_to_dict(group_name, vm)
                meta["hostvars"][vm_name] = vm_dict

                if azure_vars:
                    for key in azure_vars:
                        meta['hostvars'][vm_name][key] = azure_vars[key]

                # create/update group for OS type
                self.append_to_group(groups, vm_dict['os_type'], vm_name)

                nics = vm_dict['network_interfaces']
                for nic in nics:
                    self.append_to_group(groups, nic, vm_name)

                if 'public_ip' in vm_dict:
                    self.append_to_group(groups, vm_dict['public_ip'], vm_name)

                if vm_dict['tags']:
                    for key in vm_dict['tags']:
                        value = vm_dict['tags'][key]
                        self.append_to_group(groups, 'tag_{}:{}'.format(key, value), vm_name)

        groups["_meta"] = meta
        return groups

    def append_to_group(self, groups, group_name, item):
        if group_name in groups:
            groups[group_name].append(item)
        else:
            groups[group_name] = [item]

    def vm_to_dict(self, resource_group, vm):
        if vm is None:
            return {}

        os_type = vm.storage_profile.os_disk.operating_system_type

        network_interfaces = vm.network_profile.network_interfaces
        nics = []
        private_ip_addr = None
        public_ip_addr = None
        if network_interfaces:
            for nic in network_interfaces:
                try:
                    nic_name = nic.reference_uri.split('/')[-1]
                    nics.append(nic_name)
                except IndexError, e:
                    pass

                # get nic
                if nic_name:
                    nic = self.network_client.network_interfaces.get(resource_group, nic_name).network_interface
                    # only proceed if nic is primary
                    if nic.primary:
                        try:
                            ip_config = nic.ip_configurations[0]
                            private_ip_addr = ip_config.private_ip_address
                            if hasattr(ip_config, 'public_ip_address'):
                                public_ip_name = ip_config.public_ip_address.id.split('/')[-1]
                                public_ip = self.network_client.public_ip_addresses.get(resource_group, public_ip_name)\
                                    .public_ip_address
                                public_ip_addr = public_ip.ip_address
                        except (IndexError, AttributeError), e:
                            pass

        return {
            'name': vm.name,
            'id': vm.id,
            'type': vm.type,
            'os_type': os_type,
            'network_interfaces': nics,
            'location': vm.location,
            'tags': vm.tags,
            'private_ip': private_ip_addr,
            'public_ip': public_ip_addr,
            'provisioning_state': vm.provisioning_state,
            'ansible_ssh_host': public_ip_addr if public_ip_addr else private_ip_addr
        }


    def read_settings(self):
        """ Reads the settings from the azure.ini file """

        config = ConfigParser.SafeConfigParser()

        azure_default_ini_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'azure.ini')
        azure_ini_path = os.environ.get('AZURE_INI_PATH', azure_default_ini_path)
        config.read(azure_ini_path)

        if 'azure' not in config.sections():
            config.add_section('azure')

        config.read(azure_ini_path)

        self.config = config
        return config


    def check_azure_result(self, result, operation=None, info=None):
        if result.status_code != 200 and result.status_code != 201:
            self.exit_fail('Got Azure error code, status code = {}, operation = {}, {}'
                           .format(result.status_code, operation, info))

    def exit_fail(self, msg):
        sys.stderr.write(msg)
        sys.exit(1)

    def get_azure_creds(self):
        subscription_id = self.config.get('azure', 'subscription_id')
        if not subscription_id:
            subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
        if not subscription_id:
            self.exit_fail("No subscription_id provided. "
                           "Please set 'AZURE_SUBSCRIPTION_ID' or use the 'subscription_id' parameter")

        oauth2_token_endpoint = self.config.get('azure', 'oauth2_token_endpoint')
        if not oauth2_token_endpoint:
            oauth2_token_endpoint = os.environ.get('AZURE_OAUTH2_TOKEN_ENDPOINT', None)
        if not oauth2_token_endpoint:
            self.exit_fail("No OAuth2 token endpoint provided. Please set 'AZURE_OAUTH2_TOKEN_ENDPOINT' or "
                           "use the 'oauth2_token_endpoint' parameter")

        client_id = self.config.get('azure', 'client_id')
        if not client_id:
            client_id = os.environ.get('AZURE_CLIENT_ID', None)
        if not client_id:
            self.exit_fail("No client_id provided. Please set 'AZURE_CLIENT_ID' or use the 'client_id' parameter")

        client_secret = self.config.get('azure', 'client_secret')
        if not client_secret:
            client_secret = os.environ.get('AZURE_CLIENT_SECRET', None)
        if not client_secret:
            self.exit_fail("No client_secret provided. Please set 'AZURE_CLIENT_SECRET' environment variable or "
                           "use the 'client_secret' parameter")

        return subscription_id, oauth2_token_endpoint, client_id, client_secret

    def get_token_from_client_credentials(self, endpoint, client_id, client_secret):
        payload = {
            'grant_type': 'client_credentials',
            'client_id': client_id,
            'client_secret': client_secret,
            'resource': 'https://management.core.windows.net/',
        }
        response = requests.post(endpoint, data=payload).json()
        return response['access_token']

    def json_format_dict(self, data, pretty=False):
        ''' Converts a dict to a JSON object and dumps it as a formatted
        string '''

        if pretty:
            return json.dumps(data, sort_keys=True, indent=2)
        else:
            return json.dumps(data)

if __name__ == '__main__':
    import warnings
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.packages.urllib3.exceptions import InsecurePlatformWarning

    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    warnings.filterwarnings("ignore", category=InsecurePlatformWarning)

    AzureInventory()