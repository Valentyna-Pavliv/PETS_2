import pytest
import credential
import your_code
from petrelic.multiplicative.pairing import G1, G2, GT

def test_serialize():
    #Xe check that our serialization / deserialization function works.
    pk, _ = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    assert(pk == credential.serialize(credential.deserialize(pk)))

def test_attributes():
    #We check that we compute correct messages.
    pk, _ = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    pk, attributes = credential.deserialize(pk)
    verif = True
    for element in attributes:
        if element not in "Moon Pluto Uranus Sun Paris":
            verif = False
    assert (len(attributes) == 5) and verif

def test_sk():
    #We check that we get the right values for our public keys and our secret key.
    pk_ser, sk_ser = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    pk, _ = credential.deserialize(pk_ser)   
    sk = credential.deserialize(sk_ser)
    assert((sk[1] == pk[1]) and (len(pk[1]) == 6))

def test_credential():
    #We check that we have the correct value for our credentials.
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    response = my_server.register(sk_ser, request, "stain", "Moon Paris")
    cred = my_client.proceed_registration_response(pk_ser, response, state)

    #We want to check that e(sigma_prime_0, X_tilde * product(Y[i]**m[i])) = e(sigma_prime_1, g_tilde)

    message = [1 if att in "Moon Paris" else 0 for att in "Moon Pluto Uranus Sun Paris".split()]
    message = [credential.hash("stain")] + message
    
    pk, _ = credential.deserialize(pk_ser) 
    g, Y_list, g_tilde, X_tilde, Y_tilde_list = pk
    sigma_0, sigma_1, private_state = credential.deserialize(cred)
    
    pair_1 = sigma_0.pair(X_tilde) * sigma_0.pair(G2.prod((Y_tilde_list[i] ** message[i] for i in range(len(Y_tilde_list)))))
    pair_2 = sigma_1.pair(g_tilde)
    
    assert pair_1 == pair_2 and sigma_0 != G1.neutral_element()

def test_signature():
    #We check that an honest client gets a valid signature at the end of the protocol.
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    response = my_server.register(sk_ser, request, "stain", "Moon Paris")
    cred = my_client.proceed_registration_response(pk_ser, response, state)
    my_mess = "I love PETS"
    my_attr = "Moon Paris"
    my_sig = my_client.sign_request(pk_ser, cred, my_mess, my_attr)
    my_verif = my_server.check_request_signature(pk_ser, my_mess, my_attr, my_sig)
    assert my_verif

#We now test some failure cases.

def test_false_username():
    #We check that someone whos steals a registration request from a client cannot get a signature for his values.
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    with pytest.raises(ValueError):
        assert my_server.register(sk_ser, request, "Jean Baptiste le forain", "Sun Pluto")

def test_neutral_element():
    #We check that the Adversary can't just send sigma = (1, 1) and get entry.
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    response = my_server.register(sk_ser, request, "stain", "Moon Paris")
    cred = my_client.proceed_registration_response(pk_ser, response, state)
    _, _, private_state = credential.deserialize(cred)
    my_mess = "I love PETS"
    my_attr = "Moon Paris"
    new_cred = credential.serialize((G1.neutral_element(), G1.neutral_element(), private_state))
    my_sig = my_client.sign_request(pk_ser, new_cred, my_mess, my_attr)
    my_verif = my_server.check_request_signature(pk_ser, my_mess, my_attr, my_sig)
    assert not my_verif

def test_false_attributes():
    #We check that a credential can't give access to additional attributes.
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    response = my_server.register(sk_ser, request, "stain", "Moon Paris")
    cred = my_client.proceed_registration_response(pk_ser, response, state)
    my_mess = "I love PETS"
    my_attr = "Sun"
    my_sig = my_client.sign_request(pk_ser, cred, my_mess, my_attr)
    my_verif = my_server.check_request_signature(pk_ser, my_mess, my_attr, my_sig)
    assert not my_verif
