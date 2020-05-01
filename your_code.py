"""
Classes that you need to complete.
"""

# Optional import
import base64

from credential import Signature
from serialization import jsonpickle, G1EMHandler, G2EMHandler
from petrelic.multiplicative.pairing import G1, G2, GT
import json
import random as rd

class Server:
    """Server"""

    @staticmethod
    def generate_ca(self, valid_attributes):
        attribute_list = jsonpickle.decode(valid_attributes)
        self.valid_attributes = attribute_list
        
        self.r = len(attribute_list) #To Update HOW DO WE USE ATTRIBUTES ?
        self.p = G2.order()
        
        g_tilde = G2.generator() ** G2.order().random()
        
        sk = []
        pk = [g_tilde]
        for i in range(self.r+1):
            sk.append(rd.randint(1, self.p))
            pk.append(g_tilde ** sk[-1])
         des trucs
        self.sk = sk
        self.pk = pk
        
        pk_byte_array = serialize_G2(pk)
        sk_byte_array = serialize_int(sk)
        
        
        return(pk_byte_array, sk_byte_array)
        
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

    def register(self, server_sk, issuance_request, username, attributes):
        
        # Response should contain (server_pk, server_response, private_state ????)
        
        request = jsonpickle.decode(issuance_request)
        if request["username"] != username or request["attribute"] != attributes or (attributes not in self.attribute_list):
            return(b"failed")
        
        
        
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
        raise NotImplementedError

    def check_request_signature(self, server_pk, message, revealed_attributes, signature):
        # We test a signature to see if it is valid.
        my_sig = Signature()
        test_sig = my_sig.deserialize(signature)
        my_bool = test_sig.verify(server_pk, revealed_attributes, message)
        
        return(my_bool)
    
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


class Client:
    """Client"""

    def prepare_registration(self, server_pk, username, attributes):
        
        # What should we do with the server_pk ?
        
        issuance_request = {}
        issuance_request["username"] = username
        issuance_request["attribute"] = attributes
        
        issuance_request_serialized = jsonpickle.encode(issuance_request)
        
        return(issuance_request_serialized)
        
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
        
        raise NotImplementedError

    def sign_request(self, server_pk, credential, message, revealed_info):
        
        # We sign something == create a signature.
        # credential passed as argument is an Anoncredential object.
        deserialized_pk = deserialize(server_pk)
        
        # We have to programm the object Anoncredential
        
        my_credential = Anoncredential(credential) #Create a new Anoncredential object and ask him to sign the message.
        my_signature = my_credential.sign(message, revealed_info)
        
        return(my_signature.serialize())
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

def serialize_int(my_list):
    
    byte_array = b""
    
    for element in my_list:
        byte_array += base64.b64encode(element.to_bytes(element.bit_length()//8+1, byteorder = "big")) + b'___'
    
    return(byte_array)

def deserialize_int(byte_array):
    
    my_list = []
    
    byte_list = byte_array.split(b"___")
    
    for element in byte_list:
        my_list.append(int.from_bytes(base64.b64decode(element), byteorder = 'big'))
    
    return(my_list[:-1])
    

def serialize_G1(my_list):
    my_handler = G1EMHandler(jsonpickle.handlers.BaseHandler)
    
    byte_array = b""
    
    for element in my_list:
        byte_array += bytes(my_handler.flatten(element, {})['b64repr']+"___", "utf-8")
    
    return(byte_array)

def deserialize_G1(byte_array):
    my_handler = G1EMHandler(jsonpickle.handlers.BaseHandler)
    
    my_list = []
    decoded_byte = byte_array.decode().split("___")
    
    for element in decoded_byte:
        my_list.append(my_handler.restore({"b64repr":element}))
    
    return(my_list[:-1])



def serialize_G2(my_list):
    my_handler = G2EMHandler(jsonpickle.handlers.BaseHandler)
    
    byte_array = b""
    
    for element in my_list:
        byte_array += bytes(my_handler.flatten(element, {})['b64repr']+"___", "utf-8")
    
    return(byte_array)

def deserialize_G2(byte_array):
    my_handler = G2EMHandler(jsonpickle.handlers.BaseHandler)
    
    my_list = []
    decoded_byte = byte_array.decode().split("___")
    
    for element in decoded_byte:
        my_list.append(my_handler.restore({"b64repr":element}))
    
    return(my_list[:-1])
    
