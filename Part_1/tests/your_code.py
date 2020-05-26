"""
Classes that you need to complete.
"""

# Optional import
import base64

from serialization import jsonpickle, G1EMHandler, G2EMHandler
from petrelic.multiplicative.pairing import G1, G2, GT
import json
import random as rd
from credential import AnonCredential, Signature, Issuer, serialize, deserialize

class Server:
    """Server"""

    @staticmethod
    def generate_ca(valid_attributes):
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and chooses a secret key
        for the server.

        Args:
            valid_attributes (string): a list of all valid attributes. Users cannot
            get a credential with an attribute which is not included here.

            Note: You can use JSON to encode valid_attributes in the string.

        Returns:
            (tuple): tuple containing:
                byte[] : server's public information
                byte[] : server's secret key
            You are free to design this as you see fit, but all communications
            needs to be encoded as byte arrays.
        """

        #As we setup the server, we need setup inside an entity who will be the issuer
        issuer = Issuer()

        #Now the issuer will setup everything and the server's public/private keys == issuer sk+pk
        issuer.setup(valid_attributes)

        return (issuer.get_serialized_public_key(), issuer.get_serialized_secret_key())

    def register(self, server_sk, issuance_request, username, attributes):
        """ Registers a new account on the server.

        Args:
            server_sk (byte []): the server's secret key (serialized)
            issuance_request (bytes[]): The issuance request (serialized)
            username (string): username
            attributes (string): attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            response (bytes[]): the client should be able to build a credential
            with this response.
        """
        
        C, zkp = deserialize(issuance_request[0]), deserialize(issuance_request[1])

        #the issuer deals with the issue credentials
        return Issuer().issue(server_sk, C, zkp, attributes, username)

    def check_request_signature(self, server_pk, message, revealed_attributes, signature):
        """

        Args:
            server_pk (byte[]): the server's public key (serialized)
            message (byte[]): The message to sign
            revealed_attributes (string): revealed attributes
            signature (bytes[]): user's autorization (serialized)

            Note: You can use JSON to encode revealed_attributes in the string.

        Returns:
            valid (boolean): is signature valid
        """
        # We test a signature to see if it is valid.
        test_sig = Signature().deserialize(signature)
        
        return test_sig.verify(server_pk, revealed_attributes, message)



class Client:
    """Client"""

    def prepare_registration(self, server_pk, username, attributes):
        """Prepare a request to register a new account on the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            username (string): username
            attributes (string): user's attributes

            Note: You can use JSON to encode attributes in the string.

        Return:
            tuple:
                byte[]: an issuance request
                (private_state): You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """
        pk, valid_attr = deserialize(server_pk)

        m_list = [1 if att in attributes else 0 for att in valid_attr]
        
        request, private_state = AnonCredential().create_issue_request(m_list, server_pk, username, attributes)
        return (request, private_state)



    def proceed_registration_response(self, server_pk, server_response, private_state):
        
        #Create an anonymous credential from response

        """Process the response from the server.

        Args:
            server_pk (byte[]): a server's public key (serialized)
            server_response (byte[]): the response from the server (serialized)
            private_state (private_state): state from the prepare_registration
            request corresponding to this response

        Return:
            credential (byte []): create an attribute-based credential for the user
        """

        #Returns an Anoncredential (serialized)
        return AnonCredential().receive_issue_response(server_response, private_state)

    def sign_request(self, server_pk, credential, message, revealed_info):
        """Signs the request with the clients credential.

        Arg:
            server_pk (byte[]): a server's public key (serialized)
            credential (byte[]): client's credential (serialized)
            message (byte[]): message to sign
            revealed_info (string): attributes which need to be authorized

            Note: You can use JSON to encode revealed_info.

        Returns:
            byte []: message's signature (serialized)
        """
        # credential passed as argument is an Anoncredential object.

        pk, valid_attr = deserialize(server_pk)
        revealed = [1 if att in revealed_info else 0 for att in valid_attr]
        
        return AnonCredential().sign(serialize(pk), credential, message, revealed)


