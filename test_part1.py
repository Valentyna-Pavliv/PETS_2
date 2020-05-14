import unittest
import credential
import your_code


class MyTestCase(unittest.TestCase):
    def test_serialize(self):
        iss = credential.Issuer
        iss.setup("resto club cafet")
        self.assertEqual(iss.sk, credential.deserialize(iss.get_serialized_secret_key()[0]))

    

if __name__ == '__main__':
    unittest.main()
