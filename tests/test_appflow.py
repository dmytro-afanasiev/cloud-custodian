# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest


class AppFlowTests(BaseTest):

    def test_appflow_tag(self):
        session_factory = self.replay_flight_data('test_appflow_tag')
        new_tag = {'lob': 'overhead'}
        p = self.load_policy(
            {
                'name': 'app-flow',
                'resource': 'app-flow',
                'filters': [{
                    'tag:lob': 'absent'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': new_tag
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        flow_name = resources[0].get('flowName')
        appflow = session_factory().client('appflow')
        call = appflow.describe_flow(flowName=flow_name)
        self.assertEqual(new_tag, call.get('tags'))

    def test_appflow_untag(self):
        session_factory = self.replay_flight_data('test_appflow_untag')
        p = self.load_policy(
            {
                'name': 'app-flow',
                'resource': 'app-flow',
                'filters': [{
                    'tag:lob': 'overhead'
                }],
                'actions': [{
                    'type': 'remove-tag',
                    'tags': ['lob']
                }],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        flow_name = resources[0].get('flowName')
        appflow = session_factory().client('appflow')
        call = appflow.describe_flow(flowName=flow_name)
        self.assertEqual({}, call.get('tags'))

    def test_appflow_delete(self):
        session_factory = self.replay_flight_data('test_appflow_delete')
        p = self.load_policy(
            {
                'name': 'app-flow',
                'resource': 'app-flow',
                'actions': [{
                    'type': 'delete',
                    'force': True
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))

        appflow = session_factory().client('appflow')
        call = appflow.list_flows(maxResults=1)
        self.assertEqual([], call.get('flows'))


class TestAppFlowKmsKeyFilter(BaseTest):
    def test_appflow_kmskey_filter(self):
        session_factory = self.replay_flight_data('test_appflow_kms_key_filter')
        p = self.load_policy(
            {
                'name': 'app-flow',
                'resource': 'app-flow',
                'filters': [{
                    'type': 'appflow-kms-key-filter',
                    'key': 'KeyManager',
                    'op': 'eq',
                    'value': 'AWS'
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()

        self.assertEqual(1, len(resources))
        self.assertEqual('399-appflow-red', resources[0]['flowName'])
