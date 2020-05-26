import csv
import pandas as pd

nb = 0
sample = 1
index = 1
fieldnames = ["No.","Time","Source","Destination","Protocol","Length","Info"]
begin = 0

with open('my_csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter = ",")
    lines = 0
    current_list = [fieldnames]
    for row in csv_reader:
        if lines == 0:
            print("Heaven or Hell ? Let's Rock !")
            lines +=1
        else:
            if (row[2] == "192.168.1.1" or row[3] == "192.168.1.1"):
                if len(current_list) > 10:
                    name = str(index) + "_sample_" + str(sample) + ".csv"
                    my_write = open(name, 'w')
                    writer = csv.writer(my_write)
                    writer.writerows(current_list)
                    sample += 1
                    current_list = [fieldnames]
                    if sample == 11:
                        sample = 1
                        index += 1
                begin = row[1]
                lines = 1
            else:
                row[0] = str(lines)
                row[1] = str(float(row[1]) - float(begin))
                current_list.append(row)
