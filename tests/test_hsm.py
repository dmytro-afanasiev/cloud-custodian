# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0
from .common import BaseTest, event_data
import time


class CloudHSMClusterTest(BaseTest):

    def test_clouhsm_deprecated(self):
        factory = self.replay_flight_data("test_hsm_deprecated")
        p = self.load_policy(
            {
                "name": "cloudhsm",
                "resource": "hsm"
            },
            session_factory=factory,
        )
        resources = p.run()
        assert len(resources) == 0

    def test_cloudhsm(self):
        factory = self.replay_flight_data("test_cloudhsm")
        client = factory().client("cloudhsmv2")
        p = self.load_policy(
            {
                "name": "cloudhsm",
                "resource": "cloudhsm-cluster",
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        id = resources[0]["ClusterId"]
        tags = client.list_tags(ResourceId=id)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertTrue("foo" in tag_map)

    def test_cloudhsm_subnet_delete(self):
        factory = self.replay_flight_data("test_cloudhsm_subnet_delete")
        client = factory().client("cloudhsmv2")
        p = self.load_policy(
            {
                "name": "cloudhsm",
                "resource": "cloudhsm-cluster",
                "filters": [
                    {"type": "subnet", "key": "SubnetId", "value": "subnet-914763e7"},
                ],
                "actions": [{"type": "delete"}]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].get('ClusterId'), 'cluster-mrq6aozbe5s')
        self.assertEqual(resources[0].get('SubnetMapping'), {"us-east-1a": "subnet-914763e7"})
        if self.recording:
            time.sleep(25)
        self.assertEqual(
            client.describe_clusters(Filters={'clusterIds': ['cluster-mrq6aozbe5s']}).get(
                'Clusters')[0].get('State'), 'DELETED')

    def test_cloudhsm_tag(self):
        factory = self.replay_flight_data("test_cloudhsm_tag")
        client = factory().client("cloudhsmv2")
        p = self.load_policy(
            {
                "name": "cloudhsm",
                "resource": "cloudhsm-cluster",
                "filters": [{"tag:c7n": "absent"}],
                "actions": [{"type": "tag", "key": "c7n", "value": "test"}]
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        id = resources[0]["ClusterId"]
        tags = client.list_tags(ResourceId=id)
        tag_map = {t["Key"]: t["Value"] for t in tags["TagList"]}
        self.assertTrue("c7n" in tag_map)

    def test_cloudhsm_cluster_tag_event(self):
        factory = self.replay_flight_data("test_cloudhsm_cluster_tag_event")
        policy = self.load_policy(
            {
                "name": "cloudhsm-cluster-tag-event",
                "resource": "aws.cloudhsm-cluster",
                "mode": {"type": "cloudtrail", "events": [{
                    "source": "cloudhsm.amazonaws.com",
                    "ids": "responseElements.cluster.clusterId",
                    "event": "CreateCluster"
                }]},
                "filters": [{"type": "value", "key": "tag:Owner", "value": "test"}]
            },
            session_factory=factory,
        )
        event = {
            "detail": event_data("event-cloud-trail-hsm-create-cluster.json"),
            "debug": True,
        }
        resources = policy.push(event)
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].get('Tags'), [{"Key": "Owner", "Value": "test"}])

    def test_cloudhsm_backup_has_statement(self):
        session_factory = self.replay_flight_data(
            "test_cloudhsm_backup_statement"
        )
        p = self.load_policy(
            {
                "name": "test_cloudhsm_backup_statement",
                "resource": "cloudhsm-backup",
                "filters": [
                    {
                        "type": "has-statement"
                    }
                ],
            },
            session_factory=session_factory,
            config={'region': 'us-east-1'}
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cloudhsm_has_allow_statement(self):
        factory = self.replay_flight_data("test_cloudhsm_has_allow_statement")
        p = self.load_policy(
            {
                "name": "cloudhsm-has-statement-allow",
                "resource": "cloudhsm-backup",
                "filters": [
                    {
                        "type": "has-statement",
                        "statements": [
                            {
                                "Effect": "Allow",
                                "Action": "cloudhsm:DescribeBackups",
                                "Resource": "{backup_arn}"
                            }
                        ]
                    }
                ],
            },
            session_factory=factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

    def test_cloudhsm_backup_tag_untag(self):
        session_factory = self.replay_flight_data('test_cloudhsm_backup_tag_untag')
        tag = {'env': 'dev'}
        p = self.load_policy(
            {
                'name': 'cloudhsm-backup-tag-untag',
                'resource': 'cloudhsm-backup',
                'filters': [{
                    'tag:owner': 'policy'
                }],
                'actions': [{
                    'type': 'tag',
                    'tags': tag
                },
                {
                    'type': 'remove-tag',
                    'tags': ['owner']
                }]
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(1, len(resources))
        client = session_factory().client("cloudhsmv2")
        tags = client.list_tags(ResourceId=resources[0]["BackupId"])["TagList"]
        self.assertEqual(1, len(tags))
        new_tag = {}
        new_tag[tags[0]['Key']] = tags[0]['Value']
        self.assertEqual(tag, new_tag)

    def test_cloudhsm_backup_mark_for_op(self):
        session_factory = self.replay_flight_data("test_cloudhsm_backup_mark_for_op")
        p = self.load_policy(
            {
                "name": "cloudhsm-backup-mark",
                "resource": "cloudhsm-backup",
                "filters": [
                    {'tag:owner': 'policy'},
                ],
                "actions": [
                    {
                        "type": "mark-for-op",
                        "tag": "custodian_cleanup",
                        "op": "notify",
                        "days": 1,
                    }
                ],
            },
            session_factory=session_factory
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)

        p = self.load_policy(
            {
                "name": "cloudhsm-backup-marked",
                "resource": "cloudhsm-backup",
                "filters": [
                    {
                        "type": "marked-for-op",
                        "tag": "custodian_cleanup",
                        "op": "notify",
                        "skew": 3,
                    }
                ],
            },
            session_factory=session_factory,
        )
        resources = p.run()
        self.assertEqual(len(resources), 1)
        assert resources[0]['BackupId'] == 'backup-6qjbcmkhcxm'
