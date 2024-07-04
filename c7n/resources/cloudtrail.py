# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
import re
import logging
import jmespath

from botocore.exceptions import ClientError
from c7n.actions import Action, BaseAction
from c7n.exceptions import PolicyValidationError
from c7n.filters import ValueFilter, Filter
from c7n.filters.core import OPERATORS
from c7n.manager import resources
from c7n.tags import universal_augment
from c7n.query import ConfigSource, DescribeSource, QueryResourceManager, TypeInfo
from c7n.utils import local_session, type_schema

from .aws import shape_validate, Arn

log = logging.getLogger('c7n.resources.cloudtrail')


class DescribeTrail(DescribeSource):

    def augment(self, resources):
        return universal_augment(self.manager, resources)


def get_trail_groups(session_factory, trails):
    # returns a dictionary -> key: region value: (client, trails)
    grouped = {}
    for t in trails:
        region = Arn.parse(t['TrailARN']).region
        client, trails = grouped.setdefault(region, (None, []))
        trails.append(t)
        if client is None:
            client = local_session(session_factory).client(
                'cloudtrail', region_name=region)
        grouped[region] = client, trails
    return grouped


@resources.register('cloudtrail')
class CloudTrail(QueryResourceManager):
    class resource_type(TypeInfo):
        service = 'cloudtrail'
        enum_spec = ('describe_trails', 'trailList', None)
        filter_name = 'trailNameList'
        filter_type = 'list'
        arn_type = 'trail'
        arn = id = 'TrailARN'
        name = 'Name'
        cfn_type = config_type = "AWS::CloudTrail::Trail"
        universal_taggable = object()

    source_mapping = {
        'describe': DescribeTrail,
        'config': ConfigSource
    }


@CloudTrail.filter_registry.register('cloudtrail-s3-logging')
class CloudTrailS3LoggingFilter(Filter):
    schema = type_schema('cloudtrail-s3-logging', enabled={'type': 'boolean'})
    permissions = ('cloudtrail:DescribeTrails',)

    def __call__(self, resource):
        return resource

    def process(self, resources, event=None):
        s3_client = local_session(self.manager.session_factory).client('s3')
        result = []

        if self.data.get('enabled', True):
            for cloudtrail_bucket in resources:
                try:
                    s3_bucket = s3_client.get_bucket_logging(
                        Bucket=cloudtrail_bucket['S3BucketName'])
                    if 'LoggingEnabled' in s3_bucket:
                        result.append(cloudtrail_bucket)

                except ClientError:
                    continue
        else:
            for cloudtrail_bucket in resources:
                try:
                    s3_bucket = s3_client.get_bucket_logging(
                        Bucket=cloudtrail_bucket['S3BucketName'])
                    if 'LoggingEnabled' not in s3_bucket:
                        result.append(cloudtrail_bucket)

                except ClientError:
                    continue

        return result


@CloudTrail.filter_registry.register('is-shadow')
class IsShadow(Filter):
    """Identify shadow trails (secondary copies), shadow trails
    can't be modified directly, the origin trail needs to be modified.

    Shadow trails are created for multi-region trails as well for
    organizational trails.
    """
    schema = type_schema('is-shadow', state={'type': 'boolean'})
    permissions = ('cloudtrail:DescribeTrails',)
    embedded = False

    def process(self, resources, event=None):
        rcount = len(resources)
        trails = [t for t in resources if (self.is_shadow(t) == self.data.get('state', True))]
        if len(trails) != rcount and self.embedded:
            self.log.info("implicitly filtering shadow trails %d -> %d",
                          rcount, len(trails))
        return trails

    def is_shadow(self, t):
        if t.get('IsOrganizationTrail') and self.manager.config.account_id not in t['TrailARN']:
            return True
        if t.get('IsMultiRegionTrail') and t['HomeRegion'] != self.manager.config.region:
            return True
        return False


@CloudTrail.filter_registry.register('status')
class Status(ValueFilter):
    """Filter a cloudtrail by its status.

    :Example:

    .. code-block:: yaml

        policies:
          - name: cloudtrail-check-status
            resource: aws.cloudtrail
            filters:
            - type: status
              key: IsLogging
              value: False
    """

    schema = type_schema('status', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('cloudtrail:GetTrailStatus',)
    annotation_key = 'c7n:TrailStatus'

    def process(self, resources, event=None):
        grouped_trails = get_trail_groups(self.manager.session_factory, resources)
        for region, (client, trails) in grouped_trails.items():
            for t in trails:
                if self.annotation_key in t:
                    continue
                status = client.get_trail_status(Name=t['TrailARN'])
                status.pop('ResponseMetadata')
                t[self.annotation_key] = status
        return super(Status, self).process(resources)

    def __call__(self, r):
        return self.match(r[self.annotation_key])


@CloudTrail.filter_registry.register('event-selectors')
class EventSelectors(ValueFilter):
    """Filter a cloudtrail by its related Event Selectors.

    :example:

    .. code-block:: yaml

      policies:
        - name: cloudtrail-event-selectors
          resource: aws.cloudtrail
          filters:
          - type: event-selectors
            key: EventSelectors[].IncludeManagementEvents
            op: contains
            value: True
    """

    schema = type_schema('event-selectors', rinherit=ValueFilter.schema)
    schema_alias = False
    permissions = ('cloudtrail:GetEventSelectors',)
    annotation_key = 'c7n:TrailEventSelectors'

    def process(self, resources, event=None):
        grouped_trails = get_trail_groups(self.manager.session_factory, resources)
        for region, (client, trails) in grouped_trails.items():
            for t in trails:
                if self.annotation_key in t:
                    continue
                selectors = client.get_event_selectors(TrailName=t['TrailARN'])
                selectors.pop('ResponseMetadata')
                t[self.annotation_key] = selectors
        return super(EventSelectors, self).process(resources)

    def __call__(self, r):
        return self.match(r[self.annotation_key])


@CloudTrail.filter_registry.register('cloudtrail-s3-filter')
class CloudTrailS3LoggingPublicFilter(Filter):
    schema = type_schema('cloudtrail-s3-filter',
                         key={'type': 'string'},
                         op={'type': 'string'},
                         state={'type': 'string'},
                         # If we want to check existing of key
                         # in resource, we can use state field
                         value={'$ref': '#/definitions/filters_common/value'})
    permissions = ('cloudtrail:DescribeTrails',)

    def __call__(self, resource):
        return resource

    def process(self, resources, event=None):
        s3_client = local_session(self.manager.session_factory).client('s3')
        s3_api_fields = {'LoggingEnabled': s3_client.get_bucket_logging,
                         'PublicAccessBlockConfiguration': s3_client.get_public_access_block}
        result = []
        k = self.data.get('key').split('.')[0]

        for r in resources:
            if k in s3_api_fields:
                try:
                    entity = s3_api_fields[k](
                        Bucket='{}'.format(r['S3BucketName']))
                    if self.is_valid_state(k, entity):
                        result.append(r)
                    else:
                        key = jmespath.search(self.data.get('key'), entity)
                        op = OPERATORS[self.data.get('op')]
                        if op(key, self.data.get('value')):
                            result.append(r)
                except ClientError:
                    continue
            else:
                raise KeyError

        return result

    def is_valid_state(self, key, entity):
        if self.data.get('state') == 'present':
            if key in entity:
                return True
        elif self.data.get('state') == 'absent':
            if key not in entity:
                return True
        return False


@CloudTrail.filter_registry.register('configuration-changes-alarm-exists')
class CloudTrailChangesAlarmExistsFilter(Filter):
    """
    Filter cloudtrails by a complex rule.

    :Example:

        policies:
          - name: cloudtrail_configuration_changes_alarm_exists
            resource: aws.cloudtrail
            filters:
              - type: configuration-changes-alarm-exists
                filter-pattern: "{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) \
                                || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) \
                                || ($.eventName=StopLogging)}"
                subscriptions-confirmed: null
    """
    schema = type_schema('configuration-changes-alarm-exists',
                         required=['filter-pattern',
                                   'subscriptions-confirmed'],
                         **{'filter-pattern': {'type': 'string'},
                            'subscriptions-confirmed': {},
                            'subscriptions-confirmed-op': {'type': 'string'}
                            })
    permissions = ('cloudtrail:DescribeTrails',)

    def __call__(self, resource):
        return resource

    def process(self, resources, event=None):
        cloud_watch_client = local_session(
            self.manager.session_factory).client('cloudwatch')
        cloud_watch_logs_client = local_session(
            self.manager.session_factory).client('logs')
        sns_client = local_session(self.manager.session_factory).client('sns')

        log_groups = cloud_watch_logs_client.describe_log_groups()['logGroups']
        metric_filters = cloud_watch_logs_client.describe_metric_filters()[
            'metricFilters']
        alarms = cloud_watch_client.describe_alarms()['MetricAlarms']
        sns_topics = sns_client.list_topics()['Topics']

        filter_pattern = self.data['filter-pattern']
        subscriptions_confirmed = self.data['subscriptions-confirmed']
        subscriptions_confirmed_op = OPERATORS[
            self.data.get('subscriptions-confirmed-op', 'eq')]
        log_groups_map = {lg['arn']: lg for lg in log_groups}
        metric_filter_map = {mf['logGroupName']: mf for mf in metric_filters
                             if re.search(filter_pattern, mf['filterPattern'])}
        alarm_map = {(a['MetricName'], a['Namespace']): a for a in alarms if
                     'MetricName' in a
                     and 'Namespace' in a}
        sns_topic_attributes_map = {}
        for sns_topic in sns_topics:
            topic_arn = sns_topic['TopicArn']
            attributes = sns_client.get_topic_attributes(
                TopicArn=topic_arn).get('Attributes')
            if attributes.get(
                    'SubscriptionsConfirmed') is not None and subscriptions_confirmed_op(
                int(attributes.get('SubscriptionsConfirmed')), int(subscriptions_confirmed)):
                sns_topic_attributes_map[topic_arn] = attributes

        filtered_resources = []
        for resource in resources:
            log_group = log_groups_map.get(
                resource.get('CloudWatchLogsLogGroupArn'))
            if log_group:
                metric_filter = metric_filter_map.get(
                    log_group.get('logGroupName'))
                if metric_filter:
                    for metric_transformation in metric_filter['metricTransformations']:
                        metric_transformation_name = metric_transformation.get(
                            'metricName')
                        metric_namespace = metric_transformation[
                            'metricNamespace']
                        alarm = alarm_map.get(
                            (metric_transformation_name, metric_namespace))
                        if metric_transformation_name and alarm:
                            for sns_topic in sns_topics:
                                if sns_topic.get('TopicArn') in alarm['AlarmActions']:
                                    sns_topic_attribute = sns_topic_attributes_map.get(
                                        sns_topic['TopicArn'])
                                    if sns_topic_attribute:
                                        filtered_resources.append(resource)

        return super(CloudTrailChangesAlarmExistsFilter, self).process(
            filtered_resources)


@CloudTrail.action_registry.register('update-trail')
class UpdateTrail(Action):
    """Update trail attributes.

    :Example:

    .. code-block:: yaml

       policies:
         - name: cloudtrail-set-log
           resource: aws.cloudtrail
           filters:
            - or:
              - KmsKeyId: empty
              - LogFileValidationEnabled: false
           actions:
            - type: update-trail
              attributes:
                KmsKeyId: arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef
                EnableLogFileValidation: true
    """
    schema = type_schema(
        'update-trail',
        attributes={'type': 'object'},
        required=('attributes',))
    shape = 'UpdateTrailRequest'
    permissions = ('cloudtrail:UpdateTrail',)

    def validate(self):
        attrs = dict(self.data['attributes'])
        if 'Name' in attrs:
            raise PolicyValidationError(
                "Can't include Name in update-trail action")
        attrs['Name'] = 'PolicyValidation'
        return shape_validate(
            attrs,
            self.shape,
            self.manager.resource_type.service)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)

        for r in resources:
            client.update_trail(
                Name=r['Name'],
                **self.data['attributes'])


@CloudTrail.action_registry.register('set-logging')
class SetLogging(Action):
    """Set the logging state of a trail

    :Example:

    .. code-block:: yaml

      policies:
        - name: cloudtrail-set-active
          resource: aws.cloudtrail
          filters:
           - type: status
             key: IsLogging
             value: False
          actions:
           - type: set-logging
             enabled: True
    """
    schema = type_schema(
        'set-logging', enabled={'type': 'boolean'})

    def get_permissions(self):
        enable = self.data.get('enabled', True)
        if enable is True:
            return ('cloudtrail:StartLogging',)
        else:
            return ('cloudtrail:StopLogging',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        enable = self.data.get('enabled', True)

        for r in resources:
            if enable:
                client.start_logging(Name=r['Name'])
            else:
                client.stop_logging(Name=r['Name'])


@CloudTrail.action_registry.register('delete')
class DeleteTrail(BaseAction):
    """ Delete a cloud trail

    :example:

    .. code-block:: yaml

      policies:
        - name: delete-cloudtrail
          resource: aws.cloudtrail
          filters:
           - type: value
             key: Name
             value: delete-me
             op: eq
          actions:
           - type: delete
    """

    schema = type_schema('delete')
    permissions = ('cloudtrail:DeleteTrail',)

    def process(self, resources):
        client = local_session(self.manager.session_factory).client('cloudtrail')
        shadow_check = IsShadow({'state': False}, self.manager)
        shadow_check.embedded = True
        resources = shadow_check.process(resources)
        for r in resources:
            try:
                client.delete_trail(Name=r['Name'])
            except client.exceptions.TrailNotFoundException:
                continue
