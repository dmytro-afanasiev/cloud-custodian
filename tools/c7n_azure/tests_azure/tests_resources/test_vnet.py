from ..azure_common import BaseTest


class SubnetApplicationGatewayTest(BaseTest):

    def test_subnet_application_gateway_filter(self):
        p = self.load_policy(
            {
                "name": "test-subnet-application-gateway",
                "resource": "azure.vnet",
                "filters": [
                    {
                        "type": "subnet-application-gateway"},
                    {
                        "type": "value",
                        "key": "properties.ddosProtectionPlan.id",
                        "value": r"\/.+\/ddosProtectionPlans\/.+",
                        "op": "regex",
                    },
                    {
                        "type": "value",
                        "key": "properties.enableDdosProtection",
                        "value": True,
                    }
                ],
            }
        )
        resources = p.run()

        self.assertEqual(len(resources), 1)
