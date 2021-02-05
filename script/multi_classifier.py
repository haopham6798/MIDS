import os
import subprocess
import logging
import csv
import pandas as pd
import numpy as np
import joblib
from sklearn import preprocessing
from Netflow import Netflow


#print type of attack
def alert_prediction(pre, nflow):
	print("{0}:{1} ---> {2}:{3} Flags: {4} | Alert: Possible {5}".format(nflow["saddr"],nflow["sport"], nflow["daddr"], nflow["dport"], nflow["state"] , pre))

# render list of models and get input
def model_selection():
	s = ''
	filepath = ""
	while s == '':
		print("Select your model")
		print("1. Naive Bayes Classifier")
		print("2. Random Forest Classifier")
		print("3. Decision Tree Classifier (default)")
		print()
		user_input = input("Enter number of your model: ")
		s = str(user_input)
		if s == '1':
			print("Loading Naive Bayes...")
			filepath = "../model/20_nb_ids_191220.sav"
		elif s == '2':
			print("Loading Random Forest...")
			filepath = "../model/20_rf_ids_151220.sav"
		else:
			print("Loading Decision Tree...")
			filepath = "../model/20_dec_ids_191220.sav"
	return filepath

def main():
	print("+========================================================+")
	print("|                  IoT Dectection System                 |")
	print("+========================================================+")
	print("\n")
	argus_fields = [ "saddr","sport", "daddr", "dport", "dur", "proto", "state", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss", "dloss",  "tcprtt", "synack", "ackdat", "smeansz", "dmeansz"]
	model_dir = model_selection()
    #load model from user's selection
	clf =joblib.load(model_dir)
    
	print("Enter IP target")
	ip_target = input("IP > ")
	statement = "ra -S {}:561 -L -1 -u -nn -c , -s saddr, sport, daddr,dport, dur, proto, state, spkts, dpkts, sbytes, dbytes, sttl, dttl, sload, dload, sloss, dloss,  tcprtt, synack, ackdat, smeansz, dmeansz".format(ip_target)
	cmd = statement.split(" ")
	print("Your IP input: {}:561".format(ip_target))
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout = []
	while True:
	    line = p.stdout.readline()
	    if not isinstance(line, (str)):
	        line = line.decode('utf-8')
	        temp_list = line.split(",")
	        temp_sr = pd.Series(temp_list)
	        temp_sr.index = argus_fields
	        argus_flow = temp_sr.drop(labels=["saddr","daddr"])
	        nf =Netflow(argus_flow)
	        nf.encode_state()
	        nf.to_num()
	        nf.reshape()
	        predictions = clf.predict(nf.flow)
	        alert_prediction(predictions[0],temp_sr)
	    if (line == '' and p.poll() != None):
	    	break

if __name__ == "__main__":
    main()
