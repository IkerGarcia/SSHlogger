#!usr/bin/env python
#-*-coding:utf-8-*-
#This program analyzes auth.log files (both unzipped and zipped) and counts failed and accepted login attempts, subtracting our own attempts.
#Created by Iker García.

import os
import os.path
import glob
import gzip
import time
user=os.getenv("USER")

a = 0 #Variable to store accepted log number from previous runs.
b = 0 #Variable to count accepted log number.
c = 0 #Variable to store failed log number from previous runs.
d = 0 #Variable to count failed log nuber.

if os.path.isfile(".Acceptedlogdb"): #Searches for accepted login database (hidden), if exists updates the value of a.
  db = open(".Acceptedlogdb", "r")
  for dbline in db:
    a = dbline 

if os.path.isfile(".Failedlogdb"): #Searches for failed login database (hidden), if exists updates the value of c.
  db2 = open(".Failedlogdb", "r")
  for dbline2 in db2:
    c = dbline2

os.chdir("/var/log") #Changes directory to /var/log.
filenames = glob.glob("auth.log*") #Reads unzipped auth.log files.
for file in filenames:
  f=open(file, "r") 
  for line in f:
    if "Accepted password" in line: #Counts accepted login attempts.
      b = b+1
    elif "Accepted password for 192.*" in line: #Subtracts accepted login attempts from our own IP.
      b = b-1
    elif "Accepted password for *.*.*.*" in line: #Subtracts accepted login attempts from another own IP.
      b = b-1
    if "Failed password" in line: #Counts failed login attempts.
      d =  d+1
    elif "Failed password for 192.*" in line: #Subtracts failed login attempts from our own IP.
      d = d-1
    elif "Failed password for *.*.*.*" in line: 
      d = d-1

zipfile = glob.glob("auth.log.*.gz") #Reads zipped auth.log files.
for zip in zipfile:
  with gzip.open(zip, "r") as zf:
    for zline in zf:
      if "Accepted password" in zline: #Same behaviour as previous if statements.
        b = b+1
      elif "Accepted password for 192.*" in zline:
        b = b-1
      elif "Accepted password for *.*.*.*" in zline:
        b = b-1
      if "Failed password" in zline: 
        d = d+1
      elif "Failed password for 192.*" in zline:
        d = d-1
      elif "Failed password for *.*.*.*" in zline:
        d = d-1

a = int(a) #a variable must be int type.
c = int (c) #c vairable must be int type.
sa = b - a  #Successful login attempts (Successful attacks).
ra = d - c #Rejected login attempts (Rejected attacks).

os.chdir("/home/"+user) #Changes directory to the one where a log is going to be stored.

log = open("SSHlog.txt","a") #Creates a log text.
log.write(time.strftime("%b %d %Y "))
log.write("\t")
log.write("New successful attacks: ")
log.write("%s" % sa)
log.write("\t")
log.write("New rejected attacks: ")
log.write("%s" % ra)
log.write("\n")  

a = b #Updates the values of a and c variables stored in the databases. 
c = d

db = open(".Acceptedlogdb", "w") #Updates accepted login database.
db.write("%s" % a)
db.close()
db2 = open(".Failedlogdb", "w") #Updated failed login database.
db2.write("%s" % c)
db2.close()
