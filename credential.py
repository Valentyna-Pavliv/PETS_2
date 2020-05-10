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
import hashlib

''' Unused in the project
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
        for i in range(self.r+1):
            sk.append(rd.randint(1, self.p))
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
'''
def hash(stuff):
    """
    Hash function used for fiat shamir zkp, hashes everything
    return:
        string that is the digest of the hash
    """
    return int.from_bytes(hashlib.sha512(serialize(stuff)).digest(), byteorder = 'big')

class Issuer(object):
    """Allows the server to issue credentials"""

    def setup(self, attribute_string): #Issuer knows which valid_attributes it can call.
        """Decides the public parameters of the scheme and generates a key for
        the issuer.

        Args:
            valid_attributes (string): all valid attributes. The issuer
            will never be called with a value outside this list
        """

        # We consider that each attribute is composed of a word, so that we can then split them.
        self.valid_attributes = attribute_string.split()

        #Public parameters
        self.p = G1.order()

        #Key Generation
        self.r = len(self.valid_attributes)
        self.g = G1.generator()
        self.g_tilde = G2.generator()


        #Secret key
        x = self.p.random()
        self.sk = self.g**x


        #Public key
        X_tilde = self.g_tilde**x
        #r+1 because we need to take the username in account
        y_list = [self.p.random() for i in range(self.r+1)]
        self.Y_list = [self.g**y_i for y_i in y_list]
        Y_tilde_list = [self.g_tilde**y_i for y_i in y_list]

        self.pk = (self.g, self.Y_list, self.g_tilde, X_tilde,Y_tilde_list)


    def get_serialized_public_key(self):
        """Returns the public parameters and the public key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's public params and key
        """
        return serialize((self.pk, self.valid_attributes))

    def get_serialized_secret_key(self):
        """Returns the secret key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's secret params and key
        """
        # The secret key needs to contain the first element of the pk, so that we can compute the complete pk from the secret key.
        return serialize((self.sk, self.Y_list))

    def issue(self, sk, C, zkp, message, attributes):
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """

        #first: the issuer verifies zkp
        
        #c is the hash and R the list
        c, R = zkp
        sk, Y_list = deserialize(sk)
        
        R_prime = G1.generator()**R[0] * (C**c).inverse() * G1.prod([Y_list[i]**R[i+1] for i in range(len(Y_list))])
        
        #Compute the hash and check if the same
        if hash((R_prime, Y_list, message, attributes)) != c:
            raise ValueError('Incorrect ! Abort mission, extraction needed !')

        #if zkp is correct, issuer issues signature
        u = G1.order().random()
        return serialize((G1.generator()**u, (C*sk)**u))


class AnonCredential(object):
    """An AnonCredential"""

    @staticmethod
    def create_issue_request(m_list, pk, username, attributes):
        
        #Client proves that he knows (t, m) with m the secret value and t is a random scalar.
        
        """Gets all known attributes (subscription) of a user and creates an issuance request.
        You are allowed to add extra attributes to the issuance.


        You should design the issue_request as you see fit.
        """

        #Compute C
        g, Y_list, g_tilde, X_tilde, Y_tilde_list = deserialize(pk)[0]
        t = G1.order().random()
        C = g ** t * G1.prod([y_i ** m_i for (y_i, m_i) in zip(Y_list, m_list)])
        p = G1.order()

        #Use Fiat shamir heuristic for zkp
        #we need to pick a "challenge" ourselves and hash it
        #m_list has to be smaller than the size of valid_attributes
        m_len = len(m_list)
        exponents = [G1.order().random() for i in range(m_len + 1)]
        challenge = [G1.generator() ** exponents[i] for i in range(m_len + 1)]
        V = g ** exponents[0] * G1.prod([Y_list[i] ** exponents[i+1] for i in range(m_len)])

        #Now hash V and public params
        c = hash((V, Y_list, m_list, attributes))
        R = [exponents[0] + c * t % p].extend([exponents[i+1] + c * m_list[i] % p for i in range(m_len)])

        zkp= (c, R)

        return (serialize((C, zkp)), (t, m_list))


    def receive_issue_response(self, sigma_prime_serialized, private_state):
        
        # Find sigma out of sigma_prime.
        
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """
        
        sigma_prime = deserialize(sigma_prime_serialized)
        
        return serialize((sigma_prime[0], sigma_prime[1]/sigma_prime[0]**private_state[1], private_state))


    def sign(self, pk, credential, message, revealed_attr):
        """Signs the message.

        Args:
            message (byte []): message
            revealed_attr (string []): a list of revealed attributes

        Return:
            Signature: signature
        """
        g, Y_list, g_tilde, X_tilde, Y_tilde_list = deserialize(pk)
        sigma, private_state = deserialize(credential)
        Y_len = len(Y_list)

        r = G1.order().random()

        new_sigma = (sigma[0]**r, (sigma[0] ** private_state[1] * sigma[1]) ** r)

        #Again we need to build fiat heuristic proof
        challenges = [GT.order().random() for i in range(Y_len + 2)]

        V = new_sigma[0].pair(g_tilde ** challenges[0]) \
            * new_sigma[0].pair(X_tilde ** challenges[1]) \
            * GT.prod((new_sigma[0].pair(Y_tilde_list[i] ** challenges[i+2]) for i in range(Y_len)))

        c = hash(V, Y_tilde_list, message)
        q = GT.order()
        R = [challenges[0] + c * private_state[0]]\
            .extend([challenges[i+1] + c * (private_state[1])[i] for i in range(Y_len)])

        zkp = (c, R)

        my_signature = Signature()
        my_signature.custom_signature(new_sigma, message, zkp, revealed_attr)
        return my_signature


class Signature(object):
    """A Signature"""
    
    # We first thought of using a constructor, but realized that we could use empty signatures to deserialize other signatures.
    def custom_signature(self, sigma, message, zkp, attr):
        self.sigma = sigma
        self.message = message
        self.zkp = zkp
        self.attr = revealed_attr

    def verify(self, issuer_public_info, public_attrs, message):        
        """Verifies a signature.

        Args:
            issuer_public_info (): output of issuer's 'get_serialized_public_key' method
            public_attrs (dict): public attributes
            message (byte []): list of messages

        returns:
            valid (boolean): is signature valid
        """
        
        # Some verifications to check if the signature is not a forgery.
        if message != self.message:
            return False
        if self.sigma[0] == G1.neutral_element():
            return False
        
        #Extract useful test parameters
        c, R = self.zkp
        pk, attr = deserialize(issuer_public_info)
        g, Y_list, g_tilde, X_tilde, Y_tilde_list = pk
        y_len = len(Y_tilde_list)
        
        # Check that we have a correct signature
        my_prod = self.sigma[0].pair(g_tilde) ** c \
            * self.sigma[0].pair(X_tilde) ** R[0] \
            * GT.prod([self.sigma[0].pair(Y_tilde_list[i]) ** R[i+1] for i in range(y_len)]) \
            * (self.sigma[1].pair(g_tilde) ** c).inverse()
        c_prime = hash(my_prod, Y_tilde_list, message)
        
        return c_prime == c
        

    def serialize(self):
        """Serialize the object to a byte array.

        Returns:
            byte[]: a byte array
        """        
        return(serialize((self.sigma, self.message, self.zkp, self.revealed_attr)))

    @staticmethod
    def deserialize(data):
        """Deserializes the object from a byte array.

        Args:
            data (byte[]): a byte array

        Returns:
            Signature
        """
        sigma, message, zkp, attr = deserialize(data)
        My_sig = Signature()
        My_sig.custom_signature(sigma, message, zkp, attr)
        return(My_sig)

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
