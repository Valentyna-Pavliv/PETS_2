import pytest
import credential
import your_code

def test_serialize():
    pk, _ = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    assert(pk == credential.serialize(credential.deserialize(pk)))

def test_attributes():
    pk, _ = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    pk, attributes = credential.deserialize(pk)
    verif = True
    for element in attributes:
        if element not in "Moon Pluto Uranus Sun Paris":
            verif = False
    assert (len(attributes) == 5) and verif

def test_sk():
    pk_ser, sk_ser = your_code.Server().generate_ca("Moon Pluto Uranus Sun Paris")
    pk, _ = credential.deserialize(pk_ser)   
    sk = credential.deserialize(sk_ser)
    assert((sk[1] == pk[1]) and (len(pk[1]) == 6))

def test_signature():
    my_server = your_code.Server()
    my_client = your_code.Client()
    pk_ser, sk_ser = my_server.generate_ca("Moon Pluto Uranus Sun Paris")
    request, state = my_client.prepare_registration(pk_ser, "stain", "Moon Paris")
    response = my_server.register(sk_ser, request, "stain", "Moon Paris")
    credential = my_client.proceed_registration_response(pk_ser, response, state)
    my_mess = "I love PETS"
    my_attr = "Moon"
    my_sig = my_client.sign_request(pk_ser, credential, my_mess, my_attr)
    my_verif = my_server.check_request_signature(pk_ser, my_mes, my_attr, my_sig)
    assert my_verif
