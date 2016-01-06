#!/usr/bin/python

import base64
from distutils.version import LooseVersion

try:
    import azure as windows_azure

    if hasattr(windows_azure, '__version__') and LooseVersion(windows_azure.__version__) <= "0.11.1":
      from azure import WindowsAzureError as AzureException
      from azure import WindowsAzureMissingResourceError as AzureMissingException
    else:
      from azure.common import AzureException as AzureException
      from azure.common import AzureMissingResourceHttpError as AzureMissingException

    from azure.servicemanagement import (ServiceManagementService, OSVirtualHardDisk, SSH, PublicKeys,
                                         PublicKey, LinuxConfigurationSet, ConfigurationSetInputEndpoints,
                                         ConfigurationSetInputEndpoint, Listener, WindowsConfigurationSet, VMImage,
                                        CaptureRoleAsVMImage)

    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False

from types import MethodType


def _wait_for_completion(azure, promise, wait_timeout, msg):
    if not promise: return
    wait_timeout = time.time() + wait_timeout
    while wait_timeout > time.time():
        operation_result = azure.get_operation_status(promise.request_id)
        time.sleep(5)
        if operation_result.status == "Succeeded":
            return

    raise AzureException('Timed out waiting for async operation ' + msg + ' "' + str(promise.request_id) + '" to complete.')


def get_ssh_certificate_tokens(module, ssh_cert_path):
    """
    Returns the sha1 fingerprint and a base64-encoded PKCS12 version of the certificate.
    """
    # This returns a string such as SHA1 Fingerprint=88:60:0B:13:A9:14:47:DA:4E:19:10:7D:34:92:2B:DF:A1:7D:CA:FF
    rc, stdout, stderr = module.run_command(['openssl', 'x509', '-in', ssh_cert_path, '-fingerprint', '-noout'])
    if rc != 0:
        module.fail_json(msg="failed to generate the key fingerprint, error was: %s" % stderr)
    fingerprint = stdout.strip()[17:].replace(':', '')

    rc, stdout, stderr = module.run_command(['openssl', 'pkcs12', '-export', '-in', ssh_cert_path, '-nokeys', '-password', 'pass:'])
    if rc != 0:
        module.fail_json(msg="failed to generate the pkcs12 signature from the certificate, error was: %s" % stderr)
    pkcs12_base64 = base64.b64encode(stdout.strip())

    return (fingerprint, pkcs12_base64)


def get_azure_creds(module):
    # Check module args for credentials, then check environment vars
    subscription_id = module.params.get('subscription_id')
    if not subscription_id:
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
    if not subscription_id:
        module.fail_json(msg="No subscription_id provided. Please set 'AZURE_SUBSCRIPTION_ID' or use the 'subscription_id' parameter")

    management_cert_path = module.params.get('management_cert_path')
    if not management_cert_path:
        management_cert_path = os.environ.get('AZURE_CERT_PATH', None)
    if not management_cert_path:
        module.fail_json(msg="No management_cert_path provided. Please set 'AZURE_CERT_PATH' or use the 'management_cert_path' parameter")

    return subscription_id, management_cert_path


def create_vm_image(module, azure):
    wait_timeout = int(module.params.get('wait_timeout'))
    changed = False
    try:
        result = azure.add_os_image(module.params.get('label'),
                                    module.params.get('media_link'),
                                    module.params.get('name'), module.params.get('os'))
        _wait_for_completion(azure, result, wait_timeout, "create_os_image")
        changed = True
    except AzureException, e:
        module.fail_json(msg="failed to create the new OS Image, error was: %s" % str(e))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(required=True),
            label=dict(required=True),
            description=dict(),
            os=dict(default='Linux', choices=['Windows', 'Linux']),
            media_link=dict(required=True),
            subscription_id=dict(no_log=True),
            management_cert_path=dict(),
            state=dict(default='present', choices=['present', 'absent']),
            wait=dict(type='bool', default=False),
            wait_timeout=dict(default=600),
            wait_timeout_redirects=dict(default=300),
        )
    )
    if not HAS_AZURE:
        module.fail_json(msg='azure python module required for this module')
    # create azure ServiceManagementService object
    subscription_id, management_cert_path = get_azure_creds(module)

    wait_timeout_redirects = int(module.params.get('wait_timeout_redirects'))

    if hasattr(windows_azure, '__version__') and LooseVersion(windows_azure.__version__) <= "0.8.0":
        # wrapper for handling redirects which the sdk <= 0.8.0 is not following
        azure = Wrapper(ServiceManagementService(subscription_id, management_cert_path), wait_timeout_redirects)
    else:
        azure = ServiceManagementService(subscription_id, management_cert_path)

    if module.params.get('state') == 'absent':
        module.fail_json(msg="Unsupported state")
    
    elif module.params.get('state') == 'present':
        create_vm_image(module, azure)
        module.exit_json(changed=True)


class Wrapper(object):
    def __init__(self, obj, wait_timeout):
        self.other = obj
        self.wait_timeout = wait_timeout

    def __getattr__(self, name):
        if hasattr(self.other, name):
            func = getattr(self.other, name)
            return lambda *args, **kwargs: self._wrap(func, args, kwargs)
        raise AttributeError(name)

    def _wrap(self, func, args, kwargs):
        if type(func) == MethodType:
            result = self._handle_temporary_redirects(lambda: func(*args, **kwargs))
        else:
            result = self._handle_temporary_redirects(lambda: func(self.other, *args, **kwargs))
        return result

    def _handle_temporary_redirects(self, f):
        wait_timeout = time.time() + self.wait_timeout
        while wait_timeout > time.time():
            try:
                return f()
            except AzureException, e:
                if not str(e).lower().find("temporary redirect") == -1:
                    time.sleep(5)
                    pass
                else:
                    raise e


# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()