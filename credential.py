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

from your_code import serialize_G2, serialize_int, serialize_G1, serialize, deserialize

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
    return int.to_bytes(hashlib.sha512(serialize(stuff)).hexdigest(), byteorder='big')

class Issuer(object):
    """Allows the server to issue credentials"""

    def setup(self, attribute_string): #Issuer knows which valid_attributes it can call.
        """Decides the public parameters of the scheme and generates a key for
        the issuer.

        Args:
            valid_attributes (string): all valid attributes. The issuer
            will never be called with a value outside this list
        """

        self.valid_attributes = attribute_string.split()

        #Public parameters
        self.p = G2.order()

        #Key Generation
        self.r = len(self.valid_attributes)
        self.g = G1.generator()
        self.g_tilde = G2.generator()


        #Secret key
        x = self.p.random()
        self.sk = self.g**x
        self.sk_serialized = serialize(self.sk)


        #Public key
        X_tilde = self.g_tilde**x
        #r+1 because we need to take the username in account
        y_list = [self.p.random() for i in range(self.r+1)]
        self.Y_list = [self.g**y_i for y_i in y_list]
        Y_tilde_list = [self.g_tilde**y_i for y_i in y_list]

        self.pk = (self.p, self.g, self.Y_list, self.g_tilde, X_tilde,Y_tilde_list)
        self.pk_serialized = serialize((self.valid_attributes, self.pk))


    def get_serialized_public_key(self):
        """Returns the public parameters and the public key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's public params and key
        """
        return self.pk_serialized

    def get_serialized_secret_key(self):
        """Returns the secret key of the issuer.

        Args:
            No input

        Returns:
            byte[]: issuer's secret params and key
        """
        return self.sk_serialized

    def issue(self, C, zkp):
        """Issues a credential for a new user. 

        This function should receive a issuance request from the user
        (AnonCredential.create_issue_request), and a list of known attributes of the
        user (e.g. the server received bank notes for subscriptions x, y, and z).

        You should design the issue_request as you see fit.
        """

        #first: the issuer verifies zkp
        #c is the hash and R the list
        c, R = zkp
        R_prime = self.g**R[0] * (C**c).inverse() * G1.prod([self.Y_list[i]**R[i+1] for i in range(self.r)])
        #Compute the hash and check if the same
        if hash((R_prime, self.pk)) != c:
            return ()

        #if zkp is correct, issuer issues signature
        u = G1.order().random()
        return (self.g**u, (C*self.sk)**u)


class AnonCredential(object):
    """An AnonCredential"""

    def create_issue_request(self, m_list, pp):
        
        #Client proves that he knows (t, m) with m the secret value and t is a random scalar.
        
        """Gets all known attributes (subscription) of a user and creates an issuance request.
        You are allowed to add extra attributes to the issuance.


        You should design the issue_request as you see fit.
        """

        #Compute C
        p, g, Y_list, g_tilde, X_tilde, Y_tilde_list = pp
        t = p.random()
        C = g**t * G1.prod([y_i**m_i for (y_i, m_i) in Y_list.zip(m_list)])

        #Use Fiat shamir heuristic for zkp
        #we need to pick a "challenge" ourselves and hash it
        m_len = len(m_list)
        challenge = [p.random() for i in m_len+1]
        V=g**challenge[0] * G1.prod([Y_list[i]**challenge[i+1] for i in range(m_len)])

        #Now hash V and public params
        c = hash((V, pp))
        R = [challenge[0]+c*t%p].extend([challenge[i+1]+c*m_list[i]%p for i in range(m_len)])

        zkp= (c, R)

        return ((C, zkp), (m_list, t))


    def receive_issue_response(self, sigma_prime, private_state):
        
        # Find sigma out of sigma_prime.
        
        """This function finishes the credential based on the response of issue.

        Hint: you need both secret values from the create_issue_request and response
        from issue to build the credential.

        You should design the issue_request as you see fit.
        """

        return (sigma_prime[0], sigma_prime[1]/sigma_prime[0]**private_state[1], private_state)


    def sign(self, pp, credential, message, revealed_attr):
        """Signs the message.

        Args:
            message (byte []): message
            revealed_attr (string []): a list of revealed attributes

        Return:
            Signature: signature
        """
        p, g, Y_list, g_tilde, X_tilde, Y_tilde_list = pp
        sigma, private_state = credential

        r= p.random()

        new_sigma = (sigma[0]**r, (sigma[0]**private_state[1] * sigma[1])**r)


        #Again we need to build fiat heuristic proof
        challenges = [GT.order().random() for i in range(Y_list+2)]

        V = (new_sigma[0], g_tilde)**challenges[0] \
            * (new_sigma[0], X_tilde)**challenges[1] \
            * GT.prod((new_sigma[0], Y_tilde_list[i])**challenges[i+2] for i in range(len(Y_tilde_list)))

        c = hash(pp, V, sigma[1])
        q = GT.order()
        R = [challenges[0]+c*private_state[1]%q, challenges[1]+c%q]\
            .extend([challenges[i+2]+c*(private_state[0])[i] for i in range(len(Y_tilde_list))])

        zkp = (c, R)


        #TODO create the signature
        return Signature()


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
        """Serialize the object to a byte array.

        Returns:
            byte[]: a byte array
        """

        json_obj = jsonpickle.encode(self)
        
        return(base64.b64encode(json_obj))

    @staticmethod
    def deserialize(data):
        """Deserializes the object from a byte array.

        Args:
            data (byte[]): a byte array

        Returns:
            Signature
        """
        json_byte = base64.b64decode(data)
        my_obj = jsonpickle.decode(json_byte)
        return(my_obj)

