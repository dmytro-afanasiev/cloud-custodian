from ..azure_common import BaseTest


class SqlManagedInstanceTest(BaseTest):

    def test_sql_managed_instance_schema_validate(self):
        p = self.load_policy({
            'name': 'test-policy-assignment',
            'resource': 'azure.sql-managed-instance'
        }, validate=True)
        self.assertTrue(p)

        # test alias for back-compatibility
        p = self.load_policy({
            'name': 'test-policy-assignment',
            'resource': 'azure.sqlmanagedinstance'
        }, validate=True)
        self.assertTrue(p)

    def test_sql_managed_instance(self):
        p = self.load_policy({
            'name': 'test-azure-sql-managed-instance-all',
            'resource': 'azure.sql-managed-instance',
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('vvtestmisql', resources[0]['name'])

    def test_sql_managed_instance_security_alert_policies(self):
        p = self.load_policy({
            'name': 'test-azure-sql-managed-instance-filter-security-alert-policy',
            'resource': 'azure.sql-managed-instance',
            'filters': [{
                'type': 'value',
                'key': 'properties.state',
                'value': 'Ready'
            }]
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('vvtestmisql', resources[0]['name'])
        self.assertEqual('Ready', resources[0]['properties']['state'])

    def test_sql_managed_server_security_alert_policies(self):
        p = self.load_policy({
            'name': 'test-azure-sql-managed-server-filter-security-alert-policy',
            'resource': 'azure.sql-managed-instance',
            'filters': [{
                'type': 'managed-server-security-alert-policies',
                'key': 'state',
                'value': 'Disabled'
            }]
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('vvsqlmi1', resources[0]['name'])

    def test_filter_recurring_scans(self):
        p = self.load_policy({
            'name': 'test-azure-sql-managed-instance-recurring-scan-disabled',
            'resource': 'azure.sql-managed-instance',
            'filters': [
                {'type': 'vulnerability-assessments',
                 'key': 'recurring_scans.is_enabled',
                 'value': 'True'
                 }],
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('testsqlmi71', resources[0]['name'])

    def test_filter_encryption_protector(self):
        p = self.load_policy({
            'name': 'test-azure-sql-managed-instance-service-managed',
            'resource': 'azure.sql-managed-instance',
            'filters': [
                {'type': 'encryption-protector',
                 'key': 'kind',
                 'value': 'servicemanaged'
                 }],
        })
        resources = p.run()
        self.assertEqual(1, len(resources))
        self.assertEqual('testsqlmi71', resources[0]['name'])
