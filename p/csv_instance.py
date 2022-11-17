# -*- coding: UTF-8 -*-
import csv
name_list=[]
age_list=[]
info_list=[]
headers = ["姓名", "年龄"]
with open('test.csv', 'w', encoding="utf8" ,newline="")as file:
    writer = csv.writer(file)
    writer.writerow(headers)
    for i in range(100000):
        # name_list.append("test"+str(i))
        # age_list.append(i)
        name="test"+str(i)
        info_list.append([name, i+100000])
        writer.writerow([name, i+100000])
