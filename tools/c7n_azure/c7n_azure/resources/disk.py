# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import datetime
import dateutil
import distutils
from c7n.filters import Filter
from c7n.utils import type_schema
from c7n_azure.resources.arm import ArmResourceManager
from c7n_azure.provider import resources


@resources.register('disk')
class Disk(ArmResourceManager):
    """Disk Resource

    :example:

    This policy will find all data disks that are not being managed by a VM.

    .. code-block:: yaml

        policies:
          - name: orphaned-disk
            resource: azure.disk
            filters:
              - type: value
                key: managedBy
                value: null

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Storage']

        service = 'azure.mgmt.compute'
        client = 'ComputeManagementClient'
        enum_spec = ('disks', 'list', None)
        default_report_fields = (
            'name',
            'location',
            'resourceGroup',
            'properties.diskState',
            'sku.name'
        )
        resource_type = 'Microsoft.Compute/disks'


@Disk.filter_registry.register('snapshots')
class DiskSnapshotsFilter(Filter):

    schema = type_schema(
        'snapshots',
        **{'exist': {'anyOf': [{'type': 'boolean'}, {'type': 'string'}]},
           'max-age': {'type': 'integer', 'minimum': 1},
           'required': ['exist', 'max-age']}
    )

    def process(self, resources, event=None):
        client = self.manager.get_client('azure.mgmt.compute.ComputeManagementClient')

        expecting_exist = self.data['exist']
        expecting_max_age = self.data['max-age']
        now = datetime.datetime.now(tz=dateutil.tz.tzutc())
        filtered_resources = []
        snapshots = [snapshot for snapshot in client.snapshots.list()]
        for resource in resources:
            add_to_filtered = False
            for snapshot in snapshots:
                if (resource['id'].lower() == snapshot.creation_data.source_resource_id.lower()
                        and (now - snapshot.time_created).days < expecting_max_age):
                    add_to_filtered = True
                    break

            if (isinstance(expecting_exist, bool) and add_to_filtered == expecting_exist) or \
                    (isinstance(expecting_exist, str) and
                     add_to_filtered == distutils.util.strtobool(expecting_exist)):
                filtered_resources.append(resource)

        return filtered_resources
