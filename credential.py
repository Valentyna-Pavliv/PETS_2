# The goal of this skeleton is helping you start with the credential.
# Following this API is not mandatory and you can change it as you see fit.
# This skeleton only provides major classes/functionality that you need. You 
# should define more classes and functions.

# Hint: for a clean code, you should create classes for messages that you want
# to pass between user and issuer. The serialization helps you with (de)serializing them
# (network API expects byte[] as input).

from serialization import jsonpickle
from petrelic.multiplicative.pairing import G1, G2, GT
import random as rd
import base64

class PSSignature(object):
    """PS's Multi-message signature from section 4.2
    
    **Important** This class has no direct use in the project.

    Implementing this class allows you to get familiar with coding crypto schemes
    and its simplicity in comparison with the ABC scheme allows you to realize
    misunderstandings/problems early on.
    """
    def __init__(self, r, p): # This __init__ is not mandatory, and serves test purposes. We could have chosen self.p = G2.order and self.r = len(messages).
        self.r = r
        self.p = p

    def generate_key(self):
        g_tilde = G2.generator() ** G2.order().random()
        
        sk = []
        pk = [g_tilde]
        for i in range(r+1):
            sk.append(rd.randint(1, p))
            pk.append(g_tilde ** sk[-1])
        
        self.sk = sk
        self.pk = pk
        return(pk)

    def sign(self, sk, messages):
        
        h = G1.generator() ** G1.order().random()
        
        my_sum = sk[0]
        for i in range(len(messages)):
            my_sum += sk[i+1] * messages[i]

        return(h, h**my_sum)

    def verify(self, pk, messages, signature):
        sigma1 = signature[0]
        sigma2 = signature[1]
        if sigma1 == G1.neutral_element():
            return("Cataschtroumpf")
        
        my_prod = pk[1]
        for i in range(2,len(pk)):
            my_prod *= pk[i] ** messages[i-2]
        
        return(sigma1.pair(my_prod) == sigma2.pair(pk[0]))


class Issuer(object):
    """Allows the server to issue credentials"""

    def setup(self, valid_attributes): #Issuer knows which valid_attributes it can call.
        self.p = G2.order()
        
        """Decides the public parameters of the scheme and generates a key for
        the issuer.

        Args:
            valid_attributes (string): all valid attributes. The issuer
            will never be called with a value outside this list
        """
        pass

    def get_serialized_public_key(self):
        """Returns the public parameters and the public key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's public params and key
        """
        pass

    def get_serialized_secret_key(self):
        """Returns the secret key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's secret params and key
        """
        pass

    def issue():
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """
        pass


class AnonCredential(object):
    """An AnonCredential"""

    def create_issue_request():
        """Gets all known attributes (subscription) of a user and creates an issuance request.
        You are allowed to add extra attributes to the issuance.

        You should design the issue_request as you see fit.
        """
        pass

    def receive_issue_response():
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """
        pass

    def sign(self, message, revealed_attr):
        """Signs the message.

        Args:
            message (byte []): message
            revealed_attr (string []): a list of revealed attributes

        Return:
            Signature: signature
        """
        pass


class Signature(object):
    """A Signature"""

    def verify(self, issuer_public_info, public_attrs, message):
        my_list = list(message)
        
        """Verifies a signature.

        Args:
            issuer_public_info (): output of issuer's 'get_serialized_public_key' method
            public_attrs (dict): public attributes
            message (byte []): list of messages

        returns:
            valid (boolean): is signature valid
        """
        pass

    def serialize(self):
        json_obj = jsonpickle.encode(self)
        
        return(base64.b64encode(json_obj))
        """Serialize the object to a byte array.

        Returns: 
            byte[]: a byte array 
        """
        
    @staticmethod
    def deserialize(data):
        json_byte = base64.b64decode(data)
        my_obj = jsonpickle.decode(json_byte)
        return(my_obj)
        """Deserializes the object from a byte array.

        Args: 
            data (byte[]): a byte array 

        Returns:
            Signature
        """
