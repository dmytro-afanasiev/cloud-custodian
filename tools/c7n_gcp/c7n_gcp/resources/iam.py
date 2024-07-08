# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import re

from c7n.utils import type_schema
from c7n_gcp.filters.iampolicy import IamPolicyFilter
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo, ChildResourceManager, ChildTypeInfo
from c7n_gcp.actions import MethodAction
from c7n.filters import Filter
from c7n.filters.core import op
from c7n.utils import local_session


@resources.register('project-role')
class ProjectRole(QueryResourceManager):
    """GCP Project Role
    https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#Role
    """
    class resource_type(TypeInfo):
        service = 'iam'
        version = 'v1'
        component = 'projects.roles'
        enum_spec = ('list', 'roles[]', None)
        scope = 'project'
        scope_key = 'parent'
        scope_template = 'projects/{}'
        name = id = "name"
        default_report_fields = ['name', 'title', 'description', 'stage', 'deleted']
        asset_type = "iam.googleapis.com/Role"
        urn_component = "project-role"
        urn_id_segments = (-1,)  # Just use the last segment of the id in the URN

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', verb_arguments={
                    'name': 'projects/{}/roles/{}'.format(
                        resource_info['project_id'],
                        resource_info['role_name'].rsplit('/', 1)[-1])})


@resources.register('service-account')
class ServiceAccount(QueryResourceManager):

    class resource_type(TypeInfo):
        service = 'iam'
        version = 'v1'
        component = 'projects.serviceAccounts'
        enum_spec = ('list', 'accounts[]', [])
        scope = 'project'
        scope_key = 'name'
        scope_template = 'projects/{}'
        id = "name"
        name = 'email'
        default_report_fields = ['name', 'displayName', 'email', 'description', 'disabled']
        asset_type = "iam.googleapis.com/ServiceAccount"
        metric_key = 'resource.labels.unique_id'
        urn_component = 'service-account'
        urn_id_path = 'email'

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', verb_arguments={
                    'name': 'projects/{}/serviceAccounts/{}'.format(
                        resource_info['project_id'],
                        resource_info['email_id'])})

        @staticmethod
        def get_metric_resource_name(resource):
            return resource["uniqueId"]


@resources.register('service-account-bindings')
class ServiceAccountBindings(ChildResourceManager):
    class resource_type(ChildTypeInfo):
        service = 'iam'
        version = 'v1'
        component = 'projects.serviceAccounts'
        enum_spec = ('getIamPolicy', 'bindings[]', None)
        scope = 'resource'
        scope_key = 'resource'
        id = name = 'name'
        default_report_fields = [name, 'description']
        parent_spec = {
            'resource': 'service-account',
            'child_enum_params': {
                ('name', 'resource')},
        }


@ServiceAccountBindings.filter_registry.register('new-roles-iam-filter')
class NewRolesIAMFilter(Filter):
    schema = type_schema('new-roles-iam-filter',
                         op={'$ref': '#/definitions/filters_common/value'},
                         value={'$ref': '#/definitions/filters_common/value'},
                         by={'$ref': '#/definitions/filters_common/value'})
    permissions = ('resourcemanager.projects.list',)

    def process(self, resources, event=None):
        filtered = []
        session = local_session(self.manager.session_factory)
        client_simple = session.client(service_name='iam', version='v1', component='roles')
        client_custom = session.client(service_name='iam', version='v1', component='projects.roles')
        by_who = self.data.get('by')

        for resource in resources:
            for member in resource['members']:
                if by_who == 'user' and member.startswith(by_who):
                    if resource['role'].startswith('project'):
                        permissions = client_custom.execute_command('get', {
                            "name": resource['role']})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
                    else:
                        permissions = client_simple.execute_command('get', {
                            "name": resource['role']})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break

                elif by_who == 'serviceAccount' and member.startswith(by_who):
                    if resource['role'].startswith('project'):
                        permissions = client_custom.execute_command('get', {
                            "name": resource['role']})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
                    else:
                        permissions = client_simple.execute_command('get', {
                            "name": resource['role']})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
                else:
                    continue
        return filtered


@ServiceAccount.action_registry.register('delete')
class DeleteServiceAccount(MethodAction):
    schema = type_schema('delete')
    method_spec = {'op': 'delete'}
    permissions = ("iam.serviceAccounts.delete",)

    def get_resource_params(self, m, r):
        return {'name': r['name']}


@ServiceAccount.action_registry.register('enable')
class EnableServiceAccount(MethodAction):
    schema = type_schema('enable')
    method_spec = {'op': 'enable'}
    permissions = ("iam.serviceAccounts.enable",)

    def get_resource_params(self, m, r):
        return {'name': r['name']}


@ServiceAccount.action_registry.register('disable')
class DisableServiceAccount(MethodAction):
    schema = type_schema('disable')
    method_spec = {'op': 'disable'}
    permissions = ("iam.serviceAccounts.disable",)

    def get_resource_params(self, m, r):
        return {'name': r['name']}


@ServiceAccount.filter_registry.register('iam-policy')
class ServiceAccountIamPolicyFilter(IamPolicyFilter):
    """
    Overrides the base implementation to process service account resources correctly.
    """
    permissions = ('resourcemanager.projects.getIamPolicy',)


@resources.register('service-account-key')
class ServiceAccountKey(ChildResourceManager):
    """GCP Resource
    https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys
    """
    def _get_parent_resource_info(self, child_instance):
        project_id, sa = re.match(
            'projects/(.*?)/serviceAccounts/(.*?)/keys/.*',
            child_instance['name']).groups()
        return {'project_id': project_id,
                'email_id': sa}

    def get_resource_query(self):
        """Does nothing as self does not need query values unlike its parent
        which receives them with the use_child_query flag."""
        pass

    class resource_type(ChildTypeInfo):
        service = 'iam'
        version = 'v1'
        component = 'projects.serviceAccounts.keys'
        enum_spec = ('list', 'keys[]', [])
        scope = None
        scope_key = 'name'
        name = id = 'name'
        default_report_fields = ['name', 'privateKeyType', 'keyAlgorithm',
          'validAfterTime', 'validBeforeTime', 'keyOrigin', 'keyType']
        parent_spec = {
            'resource': 'service-account',
            'child_enum_params': [
                ('name', 'name')
            ],
            'use_child_query': True
        }
        asset_type = "iam.googleapis.com/ServiceAccountKey"
        scc_type = "google.iam.ServiceAccountKey"
        permissions = ("iam.serviceAccounts.list",)
        metric_key = 'metric.labels.key_id'
        urn_component = "service-account-key"
        urn_id_segments = (3, 5)

        @staticmethod
        def get(client, resource_info):
            project, sa, key = re.match(
                '.*?/projects/(.*?)/serviceAccounts/(.*?)/keys/(.*)',
                resource_info['resourceName']).groups()
            return client.execute_query(
                'get', {
                    'name': 'projects/{}/serviceAccounts/{}/keys/{}'.format(
                        project, sa, key)})

        @staticmethod
        def get_metric_resource_name(resource):
            return resource["name"].split('/')[-1]


@ServiceAccountKey.action_registry.register('delete')
class DeleteServiceAccountKey(MethodAction):

    schema = type_schema('delete')
    method_spec = {'op': 'delete'}
    permissions = ("iam.serviceAccountKeys.delete",)

    def get_resource_params(self, m, r):
        return {'name': r['name']}


@resources.register('iam-role')
class Role(QueryResourceManager):
    """GCP Organization Role
    https://cloud.google.com/iam/docs/reference/rest/v1/organizations.roles#Role
    """
    class resource_type(TypeInfo):
        service = 'iam'
        version = 'v1'
        component = 'roles'
        enum_spec = ('list', 'roles[]', None)
        scope = "global"
        name = id = "name"
        default_report_fields = ['name', 'title', 'description', 'stage', 'deleted']
        asset_type = "iam.googleapis.com/Role"
        urn_component = "role"
        # Don't show the project ID in the URN.
        urn_has_project = False
        urn_id_segments = (-1,)  # Just use the last segment of the id in the URN

        @staticmethod
        def get(client, resource_info):
            return client.execute_command(
                'get', {
                    'name': 'roles/{}'.format(
                        resource_info['name'])})


@resources.register('api-key')
class ApiKey(QueryResourceManager):
    """GCP API Key
    https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys#Key
    """
    class resource_type(TypeInfo):
        service = 'apikeys'
        version = 'v2'
        component = 'projects.locations.keys'
        enum_spec = ('list', 'keys[]', None)
        scope = 'project'
        scope_key = 'parent'
        scope_template = 'projects/{}/locations/global'
        name = id = "name"
        default_report_fields = ['name', 'displayName', 'createTime', 'updateTime']
        asset_type = "apikeys.googleapis.com/projects.locations.keys"
