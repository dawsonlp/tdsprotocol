import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import campaign


class ProbeConfiguration(unittest.TestCase):
    def test_nested_guest_diagnostics_are_redacted(self):
        raw={'stdout':{'value':'a test-secret b'},'stderr':['test-secret',1]}
        self.assertEqual(campaign.redact(raw,['test-secret']),{'stdout':{'value':'a [redacted] b'},'stderr':['[redacted]',1]})

    def test_native_process_receives_no_application_credential(self):
        credentials={'user_password':'test-user','admin_password':'test-admin','sql_password':'test-sql'}
        inventory={'inventory':{'sql':{'external_ip':'192.0.2.1'}}}
        with patch.object(campaign.configure,'credentials',return_value=credentials),patch.object(campaign.lab,'read',return_value=inventory):
            for method in ['ntlm','kerberos','negotiate']:
                native=campaign.config('windows',method)
                self.assertEqual(native['provider'],'native')
                self.assertNotIn('password',native)
                self.assertNotIn('username',native)
            explicit=campaign.config('linux','kerberos')
            self.assertEqual(explicit['username'],'tdsuser@TDS.TEST')
            self.assertEqual(explicit['password'],'test-user')
            self.assertEqual(explicit['provider'],'portable')


if __name__=='__main__':unittest.main()
