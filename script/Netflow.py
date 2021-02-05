import os
import subprocess
import logging
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import confusion_matrix
import joblib
from sklearn import preprocessing
from sklearn.impute import SimpleImputer
import csv


class Netflow:
    #flow = pd.Series()
    def __init__(self, flow):

        self.flow = flow
      
    def clear_hex_value(self):
        try:
            sport = self.flow["sport"]
            dport = self.flow["dport"]
            s = int(str(sport),0)
            d = int(str(dport),0)
            self.flow = self.flow.replace(to_replace=sport, value=s)
            self.flow = self.flow.replace(to_replace=dport, value=d)
        except:
            pass

    def to_num(self):
        self.flow = pd.to_numeric(self.flow, errors='coerce').fillna(0, downcast='infer')

    def encode_state(self):
        le = preprocessing.LabelEncoder()
        state_list = ['ECO', 'ECR', 'CON', 'INT', 'TST', 'MAS', 'no', 'PAR', 'RST', 'ACC', 'URN', 'FIN', 'URH', 'REQ', 'CLO', 'TXD',]
        try:
            lenc = le.fit(state_list)
            self.flow["state"] = lenc.transform([self.flow["state"]])[0]
        except ValueError as e:
            state_list.append(str(self.flow["state"]))
            lenc = le.fit(state_list)
            self.flow["state"] = lenc.transform([self.flow["state"]])[0]

    def reshape(self):
        self.flow = self.flow.values.reshape(1,-1)
# def convert_to_series(str):
#     temp_list = temp.split(",")

# if __name__ == "__main__":
#     argus_fields= [ "sport", "dport","dur", "proto", "state", "spkts", "dpkts", "sbytes", "dbytes", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "swin", "dwin", "stcpb", "dtcpb", "tcprtt", "synack", "ackdat", "smeansz", "dmeansz",'stime', 'ltime']
#     temp = '0xcc09,22,1.387502,6,FIN,2,5,216,466,64,64,622.701843,2150.627686,0,0,64128,64256,3744473807,307063853,0.001315,0.000049,0.001266,108.000000,93.199997,1603635912.632219,1603635914.019721'
#     temp_list = temp.split(",")
#     temp_sr = pd.Series(temp_list)
#     #index_ = argus_fields
#     temp_sr.index = argus_fields
#     nf =Netflow(temp_sr)
#     nf.encode_state()
#     nf.clear_hex_value()
#     nf.to_num()
#     nf.reshape()
#     #proto_num = get_number_proto()
#     print(nf.flow)
#     clf = joblib.load("../Model/model_rf_ids.sav")
#     predictions = clf.predict(nf.flow)
#     print(predictions)
