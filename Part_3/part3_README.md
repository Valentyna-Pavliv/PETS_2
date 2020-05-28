# CS523-Project 2 part 3

########### Description ##########

This is part 3 of project 2 of Advanced topics on PETS.
We did a jupyter notebook file to extract and clean data, in order to build a classifier that predict the location zone of users, given their network communication.

########### Description of the files ##########

The third part contains 1001 files, located in 'Part_3/Training_data' file:

- 1000 Data files: they all have the same format zoneNumber_sample_userNumber.csv 
           => there is 100 different zones and 10 different users per zone
           => the same user number in different zones doesn't mean that the user is the same
           => a csv file is a network capture of packets during the exchange between the user and the server 
- jupyter notebook file: clean and extract data form these csv files, and build a classifier

Our jupyter book has functions to analyze and clean the data files, as well as build a model to find out user's location given the network communication.


########### Running the program ##########

Make sure you have every file cited above in the same file. Open the jupyter notebook and run all cells one after another. Be aware that the model fitting is time-consumming. You'll get the accuracy in the final cell.

########### Have a great day :) ##########

LION Clement & PAVLIV Valentyna