# CS523-Project 2 part 1

########### Description ##########

This is part 1 of project 2 of Advanced topics on PETS.
We implement a method so that a Client can register using Attribute-Based Credentials.

########### Description of the files ##########

The project contains five files and one "tests" folder.

Files left unchanged :
client.py
serialization.py
server.py

Files modified :
credential.py
your_code.py

In these files, we implemented the various methods that were given as a skeleton. We also added in credential.py a method to hash, serialize and deserialize.

The "tests" folder contains the exact same files plus a test_part1.py files containing the different tests we used to see if our functions worked.

########### Running the program ##########

In order to run the program, we can use the commands given :

Initialization:
```
Open a shell
$ cd PETS_2
$ docker-compose build
$ docker-compose up -d
```

Server side:
```
Open a shell
$ cd PETS_2
$ docker exec -it cs523-server /bin/bash
(server) $ cd /server
(server) $ python3 server.py gen-ca -a 'attributes' -s key.sec -p key.pub
(server) $ python3 server.py run -s key.sec -p key.pub
```

Client side:
```
Open a shell
$ cd PETS_2
$ docker exec -it cs523-client /bin/bash
(client) $ cd /client
(client) $ python3 client.py get-pk -o key-client.pub
(client) $ python3 client.py register -a 'attributes' -p key-client.pub -u "name" -o attr.cred
(client) $ python3 client.py loc -p key-client.pub -c attr.cred -r 'revealed attrs' 46.52345 6.57890

```

To run the tests, go in the "tests" folder and type 
$ pytest

########### Have a great day :) ##########

LION Clement & PAVLIV Valentyna
