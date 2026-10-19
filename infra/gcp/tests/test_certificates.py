from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import configure


class Certificates(unittest.TestCase):
    def test_strict_chain_has_key_identifiers_and_required_usages(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
        with tempfile.TemporaryDirectory() as temporary,patch.object(configure,'SECRET',Path(temporary)):
            configure.certificates()
            ca=x509.load_pem_x509_certificate((Path(temporary)/'ca.pem').read_bytes())
            _,leaf,_=load_key_and_certificates((Path(temporary)/'sql.pfx').read_bytes(),configure.credentials()['pfx_password'].encode())
            self.assertEqual(leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier,ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest)
            self.assertTrue(ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
            usage=leaf.extensions.get_extension_for_class(x509.KeyUsage).value
            self.assertTrue(usage.digital_signature and usage.key_encipherment)
            self.assertFalse(usage.key_cert_sign)


if __name__=='__main__':unittest.main()
