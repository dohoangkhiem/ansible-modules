#!/usr/bin/python

__author__ = 'khiem'

import re

try:
    from libcloud.compute.types import Provider
    from libcloud.compute.providers import get_driver
    from libcloud.common.google import GoogleBaseError, QuotaExceededError, \
        ResourceExistsError, ResourceNotFoundError, InvalidRequestError
    from libcloud.compute.drivers.gce import GCENodeDriver

    _ = Provider.GCE
    HAS_LIBCLOUD = True
except ImportError:
    HAS_LIBCLOUD = False


class GCEBetaDriver(GCENodeDriver):

    def __init__(self, *args, **kwargs):
        super(GCEBetaDriver, self).__init__(*args, **kwargs)
        self.base_path = '/compute/beta/projects/%s' % self.project
        self.connection.request_path = '/compute/beta/projects/%s' % self.project

    def ex_set_node_labels(self, node, labels):
        """
        Set the labels on a Node instance.

        Note that this updates the node object directly.

        :param  node: Node object
        :type   node: :class:`Node`

        :param  labels: Dict of labels to apply to the object
        :type   labels: ``dict`` of ``str``

        :return:  True if successful
        :rtype:   ``bool``
        """
        request = '/zones/%s/instances/%s/setLabels' % (node.extra['zone'].name,
                                                        node.name)

        labels_data = {
            'labels': labels,
            'labelFingerprint': node.extra['label_fingerprint']
        }

        self.connection.async_request(request, method='POST',
                                      data=labels_data)
        new_node = self.ex_get_node(node.name, node.extra['zone'])
        node.extra['labels'] = new_node.extra['labels']
        node.extra['label_fingerprint'] = new_node.extra['label_fingerprint']
        return True

    def _to_node(self, response):
        node_obj = super(GCEBetaDriver, self)._to_node(response)
        # set labels and label_fingerprint on node.extra
        node_obj.extra['labels'] = response.get('labels', {})
        node_obj.extra['label_fingerprint'] = response.get('labelFingerprint')
        return node_obj


def gce_beta_connect(module):
    """Return a Google Cloud Engine connection."""
    service_account_email = module.params.get('service_account_email', None)
    pem_file = module.params.get('pem_file', None)
    project_id = module.params.get('project_id', None)

    # If any of the values are not given as parameters, check the appropriate
    # environment variables.
    if not service_account_email:
        service_account_email = os.environ.get('GCE_EMAIL', None)
    if not project_id:
        project_id = os.environ.get('GCE_PROJECT', None)
    if not pem_file:
        pem_file = os.environ.get('GCE_PEM_FILE_PATH', None)

    # If we still don't have one or more of our credentials, attempt to
    # get the remaining values from the libcloud secrets file.
    if service_account_email is None or pem_file is None:
        try:
            import secrets
        except ImportError:
            secrets = None

        if hasattr(secrets, 'GCE_PARAMS'):
            if not service_account_email:
                service_account_email = secrets.GCE_PARAMS[0]
            if not pem_file:
                pem_file = secrets.GCE_PARAMS[1]
        keyword_params = getattr(secrets, 'GCE_KEYWORD_PARAMS', {})
        if not project_id:
            project_id = keyword_params.get('project', None)

    # If we *still* don't have the credentials we need, then it's time to
    # just fail out.
    if service_account_email is None or pem_file is None or project_id is None:
        module.fail_json(msg='Missing GCE connection parameters in libcloud '
                             'secrets file.')
        return None

    try:
        gce = GCEBetaDriver(service_account_email, pem_file,
                datacenter=module.params.get('zone', None),
                project=project_id)
        gce.connection.user_agent_append("%s/%s" % (
            USER_AGENT_PRODUCT, USER_AGENT_VERSION))
    except (RuntimeError, ValueError), e:
        module.fail_json(msg=str(e), changed=False)
    except Exception, e:
        module.fail_json(msg=unexpected_error_msg(e), changed=False)

    return gce


def gce_convert_str(str):
    return re.sub(r'[_|?|\\|\/|*|+|\||\.]', '-', str).lower()


def add_labels(gce, module, instance_name, labels):
    """Add labels to instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not labels:
        module.fail_json(msg='Must supply labels', changed=False)

    modified_labels = {}
    for key in labels:
        modified_labels[gce_convert_str(key)] = gce_convert_str(labels[key])

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_labels = node.extra['labels']
    changed = False
    labels_changed = []

    for l in modified_labels:
        if l not in node_labels or node_labels[l] != modified_labels[l]:
            changed = True
            node_labels[l] = modified_labels[l]
            labels_changed.append(l)

    if not changed:
        return False, None

    try:
        gce.ex_set_node_labels(node, node_labels)
        return True, labels_changed
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def remove_labels(gce, module, instance_name, labels):
    """Remove labels from instance."""
    zone = module.params.get('zone')

    if not instance_name:
        module.fail_json(msg='Must supply instance_name', changed=False)

    if not labels:
        module.fail_json(msg='Must supply labels', changed=False)

    modified_labels = {}
    for key in labels:
        modified_labels[gce_convert_str(key)] = gce_convert_str(labels[key])

    try:
        node = gce.ex_get_node(instance_name, zone=zone)
    except ResourceNotFoundError:
        module.fail_json(msg='Instance %s not found in zone %s' % (instance_name, zone), changed=False)
    except GoogleBaseError, e:
        module.fail_json(msg=str(e), changed=False)

    node_labels = node.extra['labels']
    changed = False
    labels_changed = []

    for l in modified_labels:
        if l in node_labels:
            node_labels.pop(l, None)
            changed = True
            labels_changed.append(l)

    if not changed:
        return False, None

    try:
        gce.ex_set_node_labels(node, node_labels)
        return True, labels_changed
    except (GoogleBaseError, InvalidRequestError) as e:
        module.fail_json(msg=str(e), changed=False)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            instance_name=dict(required=True),
            labels=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            zone=dict(default='us-central1-a'),
            service_account_email=dict(),
            pem_file=dict(),
            project_id=dict(),
        )
    )

    if not HAS_LIBCLOUD:
        module.fail_json(msg='libcloud with GCE support is required.')

    instance_name = module.params.get('instance_name')
    state = module.params.get('state')
    labels = module.params.get('labels')
    zone = module.params.get('zone')
    changed = False

    if not zone:
        module.fail_json(msg='Must specify a "zone"', changed=False)

    # connect to GCE Beta
    gce = gce_beta_connect(module)

    # add labels to instance.
    if state == 'present':
        changed, labels_changed = add_labels(gce, module, instance_name, labels)

    # remove labels from instance
    if state == 'absent':
        changed, labels_changed = remove_labels(gce, module, instance_name, labels)

    module.exit_json(changed=changed, instance_name=instance_name, labels=labels_changed, zone=zone)
    sys.exit(0)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.gce import *

if __name__ == '__main__':
    main()