# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import itertools
from concurrent.futures import as_completed
import re

import jmespath
from c7n_gcp.filters.iampolicy import IamPolicyFilter

from c7n_gcp.actions import SetIamPolicy, MethodAction
from c7n_gcp.provider import resources
from c7n_gcp.query import QueryResourceManager, TypeInfo

from c7n.resolver import ValuesFrom
from c7n.utils import type_schema, local_session
from c7n.filters.core import ValueFilter, ListItemFilter, op, Filter
from c7n.filters.missing import Missing

from googleapiclient.errors import HttpError


@resources.register('organization')
class Organization(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/rest/v1/organizations
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'organizations'
        scope = 'global'
        enum_spec = ('search', 'organizations[]', {'body': {}})
        id = 'name'
        name = 'displayName'
        default_report_fields = [
            "name", "displayName", "creationTime", "lifecycleState"]
        asset_type = "cloudresourcemanager.googleapis.com/Organization"
        scc_type = "google.cloud.resourcemanager.Organization"
        perm_service = 'resourcemanager'
        permissions = ('resourcemanager.organizations.get',)
        urn_component = "organization"
        urn_id_segments = (-1,)  # Just use the last segment of the id in the URN
        urn_has_project = False

        @staticmethod
        def get(client, resource_info):
            org = resource_info['resourceName'].rsplit('/', 1)[-1]
            return client.execute_query(
                'get', {'name': "organizations/" + org})


@Organization.action_registry.register('set-iam-policy')
class OrganizationSetIamPolicy(SetIamPolicy):
    """
    Overrides the base implementation to process Organization resources correctly.
    """
    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@resources.register('folder')
class Folder(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/rest/v1/folders
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v2'
        component = 'folders'
        scope = 'global'
        enum_spec = ('list', 'folders', None)
        name = id = 'name'
        default_report_fields = [
            "name", "displayName", "lifecycleState", "createTime", "parent"]
        asset_type = "cloudresourcemanager.googleapis.com/Folder"
        perm_service = 'resourcemanager'
        urn_component = "folder"
        urn_id_segments = (-1,)  # Just use the last segment of the id in the URN
        urn_has_project = False

    def get_resources(self, resource_ids):
        client = self.get_client()
        results = []
        for rid in resource_ids:
            if not rid.startswith('folders/'):
                rid = 'folders/%s' % rid
            results.append(client.execute_query('get', {'name': rid}))
        return results

    def get_resource_query(self):
        if 'query' in self.data:
            for child in self.data.get('query'):
                if 'parent' in child:
                    return {'parent': child['parent']}


@resources.register('project')
class Project(QueryResourceManager):
    """GCP resource: https://cloud.google.com/compute/docs/reference/rest/v1/projects
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'projects'
        scope = 'global'
        enum_spec = ('list', 'projects', None)
        name = id = 'projectId'
        default_report_fields = [
            "name", "lifecycleState", "createTime", "parent.id"]
        asset_type = "cloudresourcemanager.googleapis.com/Project"
        scc_type = "google.cloud.resourcemanager.Project"
        perm_service = 'resourcemanager'
        labels = True
        labels_op = 'update'
        urn_component = "project"
        urn_has_project = False

        @staticmethod
        def get_label_params(resource, labels):
            return {'projectId': resource['projectId'],
                    'body': {
                        'name': resource['name'],
                        'parent': resource['parent'],
                        'labels': labels}}

        @staticmethod
        def get(client, resource_info):
            return client.execute_query(
                'get', {'projectId': resource_info['resourceName'].rsplit('/', 1)[-1]})

    def get_resource_query(self):
        # https://cloud.google.com/resource-manager/reference/rest/v1/projects/list
        if 'query' in self.data:
            for child in self.data.get('query'):
                if 'filter' in child:
                    return {'filter': child['filter']}


Project.filter_registry.register('missing', Missing)


@Project.filter_registry.register('precondition-check-filter')
class PreconditionCheckFilter(Filter):
    schema = type_schema('precondition-check-filter', rinherit=ValueFilter.schema)
    permissions = ('accessapproval.settings.get',)

    def process(self, resources, event=None):
        filtered_resources = []
        session = local_session(self.manager.session_factory)
        client = session.client(service_name='accessapproval',
                                version='v1', component='projects')
        for resource in resources:
            try:
                get_access = client.execute_command(
                    'getAccessApprovalSettings', {
                        'name': 'projects/' + resource[
                            'projectId'] + '/accessApprovalSettings'})
                if get_access:
                    continue

            except Exception as e:
                if 'Precondition check failed' in str(e):
                    return resources
                else:
                    continue

        return filtered_resources


@Project.filter_registry.register('log-project-sink-filter')
class LogProjectsSinkFilter(Filter):
    """
    This filter allows sinks in projects, if exist
    Check fields in sink resources.
    """

    schema = type_schema('log-project-sink-filter')
    permissions = ('logging.sinks.list',)

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)
        client = session.client(
            service_name='logging', version='v2', component='projects.sinks')
        accepted = []

        with self.executor_factory(max_workers=3) as w:
            futures = {}
            for resource in resources:
                futures[w.submit(client.execute_command, 'list',
                                 {'parent': 'projects/{}'.format(resource['projectId'])})] = resource
                for future in as_completed(futures):
                    try:
                        sinks = future.result()
                    except Exception:
                        continue
                    if all(['filter' in sink for sink in sinks['sinks']]):
                        accepted.append(resource)

        return accepted


@Project.filter_registry.register('logging-metrics-filter')
class LoggingMetricsFilter(ValueFilter):
    """
    This filter allows check metrics in projects, if exists.
    Check fields in metrics.
    """

    schema = type_schema('logging-metrics-filter', rinherit=ValueFilter.schema)
    permissions = ('logging.logMetrics.list',)

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)
        logging_client = session.client(
            service_name='logging', version='v2', component='projects.metrics')
        alert_client = session.client(
            service_name='monitoring', version='v3', component='projects.alertPolicies')
        accepted = []

        with self.executor_factory(max_workers=10) as w:
            futures_alerts = {}
            futures_metrics = {}
            for resource in resources:
                futures_alerts[w.submit(alert_client.execute_command, 'list', {
                    'name': 'projects/{}'.format(resource['projectId'])})] = resource
                futures_metrics[w.submit(logging_client.execute_command, 'list',
                                         {'parent': 'projects/{}'.format(resource['projectId'])})] = resource
                for future_alert in as_completed(futures_alerts):
                    try:
                        alerts = future_alert.result()
                    except Exception:
                        continue

                    valid_metrics = []
                    if alerts.get('alertPolicies'):
                        for alert in alerts['alertPolicies']:
                            gen_metrics = [
                                metric for metric in self._check_is_valid_alert(resource, alert)]
                            for gen in gen_metrics:
                                if gen not in valid_metrics:
                                    valid_metrics.append(gen.split('/')[-1])

                for future_metric in as_completed(futures_metrics):
                    metrics = future_metric.result()
                    if metrics.get('metrics'):
                        for metric in metrics['metrics']:
                            jmespath_key = jmespath.search(self.data.get('key'), metric)
                            if metric.get('name') and metric['name'] in valid_metrics and \
                                    op(self.data, jmespath_key, self.data.get('value')):
                                accepted.append(resource)
                                break

        return accepted

    def _check_is_valid_alert(self, resource, alert):
        result = []
        project_id = resource['projectId']

        if 'conditions' in alert and alert.get('enabled'):
            for metric in alert['conditions']:
                if 'conditionThreshold' in metric and 'filter' in metric['conditionThreshold'] and \
                        'user' in metric['conditionThreshold']['filter']:
                    filter = re.findall(r'(?<=user/)(.*?)(?=\")',
                                        metric['conditionThreshold']['filter'])[0]
                    metric['conditionThreshold']['filter'] = filter
                    result.append('projects/{}/metrics/{}'
                                  .format(project_id, metric['conditionThreshold']['filter']))
                else:
                    continue

        return result


@Project.filter_registry.register('iam-policy')
class ProjectIamPolicyFilter(IamPolicyFilter):
    """
    Overrides the base implementation to process Project resources correctly.
    """
    permissions = ('resourcemanager.projects.getIamPolicy',)

    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@Project.filter_registry.register('compute-meta')
class ProjectComputeMetaFilter(ValueFilter):
    """
    Allows filtering on project-level compute metadata including common instance metadata
    and quotas.

    :example:

    Find Projects that have not enabled OS Login for compute instances

    .. code-block:: yaml

        policies:
          - name: project-compute-os-login-not-enabled
            resource: gcp.project
            filters:
              - type: compute-meta
                key: "commonInstanceMetadata.items[?key==`enable-oslogin`].value | [0]"
                op: ne
                value_type: normalize
                value: true

    """

    key = 'c7n:projectComputeMeta'
    permissions = ('compute.projects.get',)
    schema = type_schema('compute-meta', rinherit=ValueFilter.schema)

    def __call__(self, resource):
        if self.key in resource:
            return resource[self.key]

        session = local_session(self.manager.session_factory)
        self.client = session.client('compute', 'v1', 'projects')

        resource[self.key] = self.client.execute_command('get', {"project": resource['projectId']})

        return super().__call__(resource[self.key])


@Project.action_registry.register('delete')
class ProjectDelete(MethodAction):
    """Delete a GCP Project

    Note this will also schedule deletion of assets contained within
    the project. The project will not be accessible, and assets
    contained within the project may continue to accrue costs within
    a 30 day period. For details see
    https://cloud.google.com/resource-manager/docs/creating-managing-projects#shutting_down_projects

    """
    method_spec = {'op': 'delete'}
    attr_filter = ('lifecycleState', ('ACTIVE',))
    schema = type_schema('delete')

    def get_resource_params(self, model, resource):
        return {'projectId': resource['projectId']}


@Project.action_registry.register('set-iam-policy')
class ProjectSetIamPolicy(SetIamPolicy):
    """
    Overrides the base implementation to process Project resources correctly.
    """
    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


class HierarchyAction(MethodAction):

    def load_hierarchy(self, resources):
        parents = {}
        session = local_session(self.manager.session_factory)

        for r in resources:
            client = self.get_client(session, self.manager.resource_type)
            ancestors = client.execute_command(
                'getAncestry', {'projectId': r['projectId']}).get('ancestor')
            parents[r['projectId']] = [
                a['resourceId']['id'] for a in ancestors
                if a['resourceId']['type'] == 'folder']
        self.parents = parents
        self.folder_ids = set(itertools.chain(*self.parents.values()))

    def load_folders(self):
        folder_manager = self.manager.get_resource_manager('gcp.folder')
        self.folders = {
            f['name'].split('/', 1)[-1]: f for f in
            folder_manager.get_resources(list(self.folder_ids))}

    def load_metadata(self):
        raise NotImplementedError()

    def diff(self, resources):
        raise NotImplementedError()

    def process(self, resources):
        if self.attr_filter:
            resources = self.filter_resources(resources)

        self.load_hierarchy(resources)
        self.load_metadata()
        op_set = self.diff(resources)
        client = self.manager.get_client()
        for op in op_set:
            self.invoke_api(client, *op)


@Project.action_registry.register('propagate-labels')
class ProjectPropagateLabels(HierarchyAction):
    """Propagate labels from the organization hierarchy to a project.

    folder-labels should resolve to a json data mapping of folder path
    to labels that should be applied to contained projects.

    as a worked example assume the following resource hierarchy

    ::

      - /dev
           /network
              /project-a
           /ml
              /project-b

    Given a folder-labels json with contents like

    .. code-block:: json

      {"dev": {"env": "dev", "owner": "dev"},
       "dev/network": {"owner": "network"},
       "dev/ml": {"owner": "ml"}

    Running the following policy

    .. code-block:: yaml

      policies:
       - name: tag-projects
         resource: gcp.project
         # use a server side filter to only look at projects
         # under the /dev folder the id for the dev folder needs
         # to be manually resolved outside of the policy.
         query:
           - filter: "parent.id:389734459211 parent.type:folder"
         filters:
           - "tag:owner": absent
         actions:
           - type: propagate-labels
             folder-labels:
                url: file://folder-labels.json

    Will result in project-a being tagged with owner: network and env: dev
    and project-b being tagged with owner: ml and env: dev

    """
    schema = type_schema(
        'propagate-labels',
        required=('folder-labels',),
        **{
            'folder-labels': {
                '$ref': '#/definitions/filters_common/value_from'}},
    )

    attr_filter = ('lifecycleState', ('ACTIVE',))
    permissions = ('resourcemanager.folders.get',
                   'resourcemanager.projects.update')
    method_spec = {'op': 'update'}

    def load_metadata(self):
        """Load hierarchy tags"""
        self.resolver = ValuesFrom(self.data['folder-labels'], self.manager)
        self.labels = self.resolver.get_values()
        self.load_folders()
        self.resolve_paths()

    def resolve_paths(self):
        self.folder_paths = {}

        def get_path_segments(fid):
            p = self.folders[fid]['parent']
            if p.startswith('folder'):
                for s in get_path_segments(p.split('/')[-1]):
                    yield s
            yield self.folders[fid]['displayName']

        for fid in self.folder_ids:
            self.folder_paths[fid] = '/'.join(get_path_segments(fid))

    def resolve_labels(self, project_id):
        hlabels = {}
        parents = self.parents[project_id]
        for p in reversed(parents):
            pkeys = [p, self.folder_paths[p], 'folders/%s' % p]
            for pk in pkeys:
                hlabels.update(self.labels.get(pk, {}))

        return hlabels

    def diff(self, resources):
        model = self.manager.resource_type

        for r in resources:
            hlabels = self.resolve_labels(r['projectId'])
            if not hlabels:
                continue

            delta = False
            rlabels = r.get('labels', {})
            for k, v in hlabels.items():
                if k not in rlabels or rlabels[k] != v:
                    delta = True
            if not delta:
                continue

            rlabels = dict(rlabels)
            rlabels.update(hlabels)

            if delta:
                yield ('update', model.get_label_params(r, rlabels))


@Organization.filter_registry.register('essential-contacts')
class OrgContactsFilter(ListItemFilter):
    """Filter Resources based on essential contacts configuration

    .. code-block:: yaml

      - name: org-essential-contacts
        resource: gcp.organization
        filters:
        - type: essential-contacts
          count: 2
          count_op: gte
          attrs:
            - validationState: VALID
            - type: value
              key: notificationCategorySubscriptions
              value: TECHNICAL
              op: contains
    """
    schema = type_schema(
        'essential-contacts',
        attrs={'$ref': '#/definitions/filters_common/list_item_attrs'},
        count={'type': 'number'},
        count_op={'$ref': '#/definitions/filters_common/comparison_operators'}
    )

    annotate_items = True
    permissions = ("essentialcontacts.contacts.list",)

    def get_item_values(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("essentialcontacts", "v1", "organizations.contacts")
        pages = client.execute_paged_query('list', {'parent': resource['name'], 'pageSize': 100})
        contacts = []
        for page in pages:
            contacts.extend(page.get('contacts', []))
        return contacts


@Organization.filter_registry.register('org-policy')
class OrgPoliciesFilter(ListItemFilter):
    """Filter Resources based on orgpolicy configuration

    .. code-block:: yaml

      - name: org-policy
        resource: gcp.organization
        filters:
        - type: org-policy
          attrs:
            - type: value
              key: constraint
              value: constraints/iam.allowedPolicyMemberDomains
              op: contains
    """
    schema = type_schema(
        'org-policy',
        attrs={'$ref': '#/definitions/filters_common/list_item_attrs'}
    )

    annotate_items = True
    permissions = ("orgpolicy.policy.get",)

    def get_item_values(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("cloudresourcemanager", "v1", "organizations")
        pages = client.execute_paged_query('listOrgPolicies', {'resource': resource['name']})
        policies = []
        for page in pages:
            policies.extend(page.get('policies', []))
        return policies


@Project.filter_registry.register('access-approval')
class AccessApprovalFilter(ValueFilter):
    """Filter Resources based on access approval configuration

    .. code-block:: yaml

      - name: project-access-approval
        resource: gcp.project
        filters:
        - type: access-approval
          key: enrolledServices.cloudProduct
          value: "all"
    """
    schema = type_schema('access-approval', rinherit=ValueFilter.schema)
    permissions = ('accessapproval.settings.get',)

    def process(self, resources, event=None):
        return [r for r in resources
                if self.match(self.get_access_approval(r))]

    def get_access_approval(self, resource):
        session = local_session(self.manager.session_factory)
        client = session.client("accessapproval", "v1", "projects")
        project = resource['projectId']

        try:
            access_approval = client.execute_command(
                'getAccessApprovalSettings',
                {'name': f"projects/{project}/accessApprovalSettings"},)
        except HttpError as ex:
            if (ex.status_code == 400
                and ex.reason == "Precondition check failed.") \
                    or (ex.status_code == 404):
                # For above exceptions, it implies that access approval is
                # not enabled, so we return an empty setting.
                access_approval = {}
            else:
                raise ex

        return access_approval


@resources.register('project-iam-policy-bindings')
class ProjectIamPolicyBindings(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/
                     rest/v1/projects/getIamPolicy
    """
    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'projects'
        scope = 'project'
        enum_spec = ('getIamPolicy', 'bindings[]', {'body': {}})
        scope_key = 'resource'
        scope_template = '{}'
        name = id = 'role'
        default_report_fields = [id, 'members']
        get_multiple_resources = True

        @staticmethod
        def get(client, resource_info):
            iam_policy = client.execute_command(
                'getIamPolicy', {'resource': resource_info['project_id']})
            return iam_policy['bindings'] if 'bindings' in iam_policy else []


@resources.register('project-iam-policy-bindings-by-members')
class ProjectIamPolicyBindingsByMembers(QueryResourceManager):
    """GCP resource: https://cloud.google.com/resource-manager/reference/
                     rest/v1/projects/getIamPolicy
    """

    class resource_type(TypeInfo):
        service = 'cloudresourcemanager'
        version = 'v1'
        component = 'projects'
        scope = 'project'
        enum_spec = ('getIamPolicy', 'bindings[]', {'body': {}})
        scope_key = 'resource'
        scope_template = '{}'
        name = id = 'member'
        default_report_fields = [id, 'roles']
        get_multiple_resources = True

    def _fetch_resources(self, query):
        fetched_resources = super()._fetch_resources(query)
        remapped_resources = []
        remapped_members = []
        for fetched_resource in fetched_resources:
            for member in fetched_resource['members']:
                if member in remapped_members:
                    for remapped_resource in remapped_resources:
                        if remapped_resource['member'] == member:
                            remapped_resource['roles'].append(fetched_resource['role'])
                else:
                    remapped_resources.append(
                        {'member': member, 'roles': [fetched_resource['role']]})
                    remapped_members.append(member)
        return remapped_resources


@ProjectIamPolicyBindingsByMembers.filter_registry.register('new-roles-filter')
class NewRolesFilter(Filter):
    schema = type_schema('new-roles-filter',
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
            if by_who == 'user' and resource['member'].startswith(by_who):
                for role in resource['roles']:
                    if role.startswith('project'):
                        permissions = client_custom.execute_command('get', {
                            "name": role})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
                    else:
                        permissions = client_simple.execute_command('get', {
                            "name": role})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break

            elif by_who == 'serviceAccount' and resource['member'].startswith(by_who):
                for role in resource['roles']:
                    if role.startswith('project'):
                        permissions = client_custom.execute_command('get', {
                            "name": role})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
                    else:
                        permissions = client_simple.execute_command('get', {
                            "name": role})['includedPermissions']
                        if op(self.data, permissions, self.data.get('value')):
                            filtered.append(resource)
                            break
            else:
                continue
        return filtered


@Organization.filter_registry.register('iam-policy')
class OrganizationIamPolicyFilter(IamPolicyFilter):
    """
    Overrides the base implementation to process Organization resources correctly.
    """
    permissions = ('resourcemanager.organizations.getIamPolicy',)

    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@Folder.filter_registry.register('iam-policy')
class FolderIamPolicyFilter(IamPolicyFilter):
    """
    Overrides the base implementation to process Folder resources correctly.
    """
    permissions = ('resourcemanager.folders.getIamPolicy',)

    def _verb_arguments(self, resource):
        verb_arguments = SetIamPolicy._verb_arguments(self, resource)
        verb_arguments['body'] = {}
        return verb_arguments


@Project.filter_registry.register('service-vuln-scanning-filter')
class ServiceVulnScanningFilter(ValueFilter):
    schema = type_schema('service-vuln-scanning-filter', rinherit=ValueFilter.schema)
    permissions = ('serviceusage.services.list',)

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)
        project = session.get_default_project()

        client = session.client(service_name='serviceusage', version='v1', component='services')
        services = client.execute_command('list', {'parent': 'projects/' + project,
                                                   'filter': 'state:ENABLED',
                                                   'pageSize': 200})['services']
        accepted_resources = []
        for resource in services:
            jmespath_key = jmespath.search(self.data.get('key'), resource)
            if jmespath_key is not None and op(self.data, jmespath_key, self.data.get('value')):
                accepted_resources.append(resource)

        if len(accepted_resources) == 0:
            for resource in resources:
                if resource['name'] == project:
                    return [resource]

        return []


@Project.filter_registry.register('audit-config-project-filter')
class AuditConfigProjectFilter(Filter):
    """
    This filter allows check audit configs in projects, if exist
    Check fields in audit config resources.
    """

    schema = type_schema('audit-config-project-filter')
    permissions = ('resourcemanager.projects.getIamPolicy',)

    def process(self, resources, event=None):
        session = local_session(self.manager.session_factory)
        client = session.client(
            service_name='cloudresourcemanager', version='v1', component='projects')
        accepted = []

        with self.executor_factory(max_workers=3) as w:
            futures = {}
            for resource in resources:
                futures[w.submit(client.execute_command, 'getIamPolicy',
                                 {'resource': '{}'.format(resource['projectId'])})] = resource
                for future in as_completed(futures):
                    configs = future.result()
                    as_a_result = []
                    if configs.get('auditConfigs'):
                        for config in configs['auditConfigs']:
                            if config.get('service') and \
                                    config['service'] == 'allServices' and \
                                    config.get('auditLogConfigs') and len(
                                config['auditLogConfigs']) == 2 and config[
                                'auditLogConfigs'][0]['logType'] in \
                                    ['DATA_WRITE', 'DATA_READ'] and config[
                                'auditLogConfigs'][1]['logType'] in \
                                    ['DATA_WRITE', 'DATA_READ'] and \
                                    'exemptedMembers' not in config['auditLogConfigs'][1] and \
                                    'exemptedMembers' not in config['auditLogConfigs'][0]:
                                as_a_result.append(True)
                            else:
                                as_a_result.append(False)

                        if True in as_a_result:
                            accepted.append(resource)

        return accepted
