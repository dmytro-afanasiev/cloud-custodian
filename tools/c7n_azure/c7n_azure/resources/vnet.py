# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

from c7n_azure.provider import resources
from c7n_azure.resources.arm import ArmResourceManager
from c7n.filters import ValueFilter
from c7n.utils import type_schema


@resources.register('vnet')
class Vnet(ArmResourceManager):
    """Virtual Networks Resource

    :example:

    This set of policies will find all Virtual Networks that do not have DDOS protection enabled.

    .. code-block:: yaml

        policies:
          - name: find-vnets-ddos-protection-disabled
            resource: azure.vnet
            filters:
              - type: value
                key: properties.enableDdosProtection
                op: equal
                value: False

    """

    class resource_type(ArmResourceManager.resource_type):
        doc_groups = ['Networking']

        service = 'azure.mgmt.network'
        client = 'NetworkManagementClient'
        enum_spec = ('virtual_networks', 'list_all', None)
        resource_type = 'Microsoft.Network/virtualNetworks'


@Vnet.filter_registry.register('subnet-application-gateway')
class SubnetApplicationGatewayVnetFilter(ValueFilter):

    schema = type_schema('subnet-application-gateway')

    def process(self, resources, event=None):
        client = self.manager.get_client()
        self.application_gateways = client.application_gateways.list_all()
        filtered_resources = []
        for vnet in resources:
            for subnet_id in vnet['properties']['subnets']:
                if self._mapping_resources(subnet_id['id']):
                    filtered_resources.append(vnet)
                    break
        return filtered_resources

    def _mapping_resources(self, subnet_id):
        for application_gateway in self.application_gateways:
            for subnet in application_gateway.gateway_ip_configurations:
                if subnet.subnet.id == subnet_id:
                    return True
        return False
