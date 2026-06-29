import yaml
from django.test import SimpleTestCase

from .services import epl_to_sigma


class EplToSigmaTests(SimpleTestCase):
    def test_converts_event_function_conditions(self):
        epl = """
        module CUXXX_PS_control_Psafeadminsw;

        @Name('[TEST]CUXXX_PS_control_Psafeadminsw_al_grupo_TI-SI_IS_APLICATIVOS')
        @Description('')
        @RSAAlert(oneInSeconds=0)
        SELECT * FROM Event(
            isOneOfIgnoreCase(device_type,{ 'pbps' })

            AND `user` IS NOT NULL
            AND `user`.firstOf().toString().toLowerCase() LIKE '%psafeadminsw%'

            AND
            (
                isOneOfIgnoreCase(pbps_details,{ 'type=rdp' })
                OR
                isOneOfIgnoreCase(obj_name,{ 'password' })
            )

            AND isOneOfIgnoreCase(action,{ 'add','retrieve','retrive' })
        );
        """

        rule = yaml.safe_load(epl_to_sigma(epl))

        self.assertEqual(rule["title"], "[TEST]CUXXX_PS_control_Psafeadminsw_al_grupo_TI-SI_IS_APLICATIVOS")
        self.assertEqual(rule["logsource"]["product"], "event")
        detection = rule["detection"]
        self.assertEqual(detection["selection"]["device_type"], ["pbps"])
        self.assertTrue(detection["selection"]["user|exists"])
        self.assertEqual(detection["selection"]["user|contains"], "psafeadminsw")
        self.assertEqual(detection["selection"]["action"], ["add", "retrieve", "retrive"])
        self.assertEqual(detection["selection_or_1_1"]["pbps_details"], ["type=rdp"])
        self.assertEqual(detection["selection_or_1_2"]["obj_name"], ["password"])
        self.assertEqual(detection["condition"], "selection and (selection_or_1_1 or selection_or_1_2)")
