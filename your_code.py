"""
Classes that you need to complete.
"""

# Optional import
import base64

from credential import Signature, Issuer
from serialization import jsonpickle, G1EMHandler, G2EMHandler
from petrelic.multiplicative.pairing import G1, G2, GT
import json
import random as rd
from credential import AnonCredential

class Server:
    """Server"""

    @staticmethod
    def generate_ca(self, valid_attributes):
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
        attribute_list = jsonpickle.decode(valid_attributes)

        #As we setup the server, we need setuo inside an entity who will be the issuer
        issuer = Issuer()

        #Now the issuer will setup everything and the server's public/private keys == issuer sk+pk
        issuer.setup(attribute_list)

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
        # Response should contain (server_pk, server_response, private_state ????)
        # La response contient pas private state, c'est juste le client qui est au courant de ça

        C, zkp = deserialize(issuance_request)

        #je sais pas trop ce que tu fais ici :(
        '''
        request = jsonpickle.decode(issuance_request)
        if request["username"] != username or request["attribute"] != attributes or (
                #je suis vraiment pas sure de ça
                attributes not in self.attribute_list):
            return (b"failed")
        '''



        #the issuer deals with the issue credentials
        return serialize(Issuer.issue(C, zkp))

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
        my_sig = Signature()
        test_sig = my_sig.deserialize(signature)
        
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

        #TODO What should we do with the server_pk ?
        # On récupère les infos sur le serveur, ie les valid attributes etc...
        valid_attr, pp = deserialize(server_pk)


        #je sais pas ce que tu veux faire avec ça :(
        '''
        issuance_request = {}
        issuance_request["username"] = username
        issuance_request["attribute"] = attributes
        '''

        #m_list transformation en liste binaire:
        #m_list sera de la meme longueur que valid_attributes, si attribute dans ceux du user = 1, else 0
        m_list = [1 if att in valid_attr else 0 for att in attributes.split()]

        #AnonCredential s'occupe de create issue request, alors ça sera son problème
        request, private_state = AnonCredential.create_issue_request(m_list, pp)
        return (serialize(request), private_state)



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
        
        # We sign something == create a signature.
        # credential passed as argument is an Anoncredential object.
        deserialized_pk = Signature.deserialize(server_pk)
        
        # We have to programm the object Anoncredential
        
        my_credential = AnonCredential(credential) #Create a new Anoncredential object and ask him to sign the message.
        my_signature = my_credential.sign(message, revealed_info)
        
        return(my_signature.serialize())


def serialize(complex_object):
    """
    Transform an object into byte array

    Transform an object into a json and then to a byte array

    Arg: a python object

    Return : the object encoded to byte[]
    """
    return jsonpickle.encode(complex_object).encode('utf-8')

def deserialize(byte_array):
    """
    given a byte array of a json pickle of an object, return the python object

    Arg: byte array of a python object encoded to a json

    Return: the python object
    """
    return jsonpickle.decode(byte_array.decode('utf-8'))


#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def serialize_int(my_list):
    
    byte_array = b""
    
    for element in my_list:
        byte_array += base64.b64encode(element.to_bytes(element.bit_length()//8+1, byteorder = "big")) + b'___'
    
    return(byte_array)

#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def deserialize_int(byte_array):
    
    my_list = []
    
    byte_list = byte_array.split(b"___")
    
    for element in byte_list:
        my_list.append(int.from_bytes(base64.b64decode(element), byteorder = 'big'))
    
    return(my_list[:-1])


#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def serialize_G1(my_list):
    my_handler = G1EMHandler(jsonpickle.handlers.BaseHandler)
    
    byte_array = b""
    
    for element in my_list:
        byte_array += bytes(my_handler.flatten(element, {})['b64repr']+"___", "utf-8")
    
    return(byte_array)


#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def deserialize_G1(byte_array):
    my_handler = G1EMHandler(jsonpickle.handlers.BaseHandler)
    
    my_list = []
    decoded_byte = byte_array.decode().split("___")
    
    for element in decoded_byte:
        my_list.append(my_handler.restore({"b64repr":element}))
    
    return(my_list[:-1])


#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def serialize_G2(my_list):
    my_handler = G2EMHandler(jsonpickle.handlers.BaseHandler)
    
    byte_array = b""
    
    for element in my_list:
        byte_array += bytes(my_handler.flatten(element, {})['b64repr']+"___", "utf-8")
    
    return(byte_array)

#TODO pas sure que c'es la méthode la plus simple à utiliser => à remplacer avec deserialize/serialize?
def deserialize_G2(byte_array):
    my_handler = G2EMHandler(jsonpickle.handlers.BaseHandler)
    
    my_list = []
    decoded_byte = byte_array.decode().split("___")
    
    for element in decoded_byte:
        my_list.append(my_handler.restore({"b64repr":element}))
    
    return(my_list[:-1])
    
