#!/usr/bin/env python
#Prediction module based in the LWR method


import numpy as np 
import math
import pylab as pl
from scipy import stats
import time
import pandas as df
from collections import OrderedDict


class Prediction():
    

    def __init__(self, timeThreshold=0, sizeThreshold=0):
        self.base = df.read_csv("database.csv", sep=",") #Flow Database.
        
        #Thresholdes
        self.timeThreshold = timeThreshold;
        self.sizeThreshold = sizeThreshold;


    def setFlow(self, tupla, timeStamp, time, size, flagEF=False):
        if tupla not in self.base:
            if len(tupla) == 5:
                data = list(tupla) + [timeStamp,time,size,flagEF] 
                aux = df.DataFrame([data], columns = self.base.columns)
                self.base = self.base.append(aux, ignore_index=True)
               
    #Get historical databases.
    #tupla = (ip_scr, ip_dst, ip_proto, port_src, port_dst)
    def getData(self, tupla, local_database=None):
        scr = tupla[0]
        dst = tupla[1]

        data = []
        grup  = ["ipsrc","ipdst","proto","srcPort","dstPort"]
        if local_database:
            grup.append(local_database)

        for i in self.base.groupby(grup):
            if i[0][0] == scr and i[0][1] == dst:
                ts = np.array(i[1]['timeStamp'])
                t  = np.array(i[1]['time'])
                s  = np.array(i[1]['size'])

                data =  np.c_[ts.transpose(), t.transpose(), s.transpose()]

        return data



    # Function to perform the process of inference data.
    #tuple = (ip_scr, ip_dst, ip_proto, port_src, port_dst)
    #timeTol = tolerance for TIME prediction range
    #sizeTol = tolerance for SIZE prediction range
    #cTime = current execution time
    #k = Gaussian function adjustment parameter.
    #k defines the window of weights for the samples in the inference process.
    #Returns:
    # True -> If the flow is predicted as an Elephant Flow
    # False - > If thresholds are not exceeded.
# Or the pressure range is not acceptable.  
    def inferData(self, tupla, timeTol, sizeTol, cTime, k=1, database=None):

        if tupla:
            dados = self.getData(tupla, database)
            if len(dados) > 10:
                
                #Inference: Flow's duration
                timeInfer, timePI = self.lwr(np.c_[dados[:,0],dados[:,1]], cTime, k)
                resulTime = abs(timeInfer) *  (timeTol/100.0)  #Inferred absolute value plus acceptance tolerance
                
                #Inference: Flow's size
                sizeInfer, sizePI = self.lwr(np.c_[dados[:,0],dados[:,2]], cTime, k)
                resulSize = abs(sizeInfer) *  (sizeTol/100.0)  #Inferred absolute value plus acceptance tolerance
                
                print ("\nTIME: %f Pred. Interv: %f\tTol(%.2f%%): %f"%(timeInfer, timePI, timeTol, resulTime))          
                print ("SIZE: %f Pred. Interv: %f\tTol(%.2f%%): %f"%(sizeInfer, sizePI, sizeTol, resulSize)) 
                
                #Check inferences
                if( timePI <= resulTime and sizePI <= resulSize):
                    print ("\t\033[%imAcceptable Inference!\033[%im"%(32, 37))

                    if((timeInfer+timePI) > self.timeThreshold and (sizeInfer+sizePI) > self.sizeThreshold):
                        print ("\t\033[%imElephant Flow Identified - INFERENCE!\033[%im"%(32, 37))
                        return True
        return False



    #################################################
    #       LOCALLY WEIGHTED REGRESSION METHOD      #
    #################################################
    def gaussianKernel(self, x, x0, k):
        d2 = (x-x0)**2 
        resul = math.exp(-d2 / (2.0 * (k**2))) 
        return resul


    def getWeights(self, D, x, k):
        n = len(D)            
        weights = np.eye(n)   
        for i in range(n):
            x0 = D[i][0]
            weights[i,i] = self.gaussianKernel(x, x0, k)

        return weights


    def lwr(self, D, coordX, k):
    
        beta = []
        try:
            W = self.getWeights(D, coordX, k)  
            m = len(D)
            X = D[:,:-1]                  
            X = np.c_[np.ones(m),X]       
            y = D[:,1]                    
                
            Xt = np.transpose(X)
            Xt_W = np.dot(Xt,W)
            M5 = np.dot(W, X)
            Xt_W_X = np.dot(Xt_W,M5)
            Xt_W_X_INV = np.linalg.inv(Xt_W_X)
            M6  = np.dot(W, y)
            Xt_W_y = np.dot(Xt_W,M6)
            beta = np.dot(Xt_W_X_INV,Xt_W_y)
            
            Xi  = np.array([1,coordX])
            Xit = np.transpose(Xi)
            resul = np.dot(Xit,beta)
            
            
            #T-value
            sw = 0                      #sw: squared weights
            for i in range(m):          #
                sw += W[i][i]**2        #SUM
            #print W
            pl = (sw/m)*2.0             #p' = (n'/n)*p. p': beta coefficients

            t = stats.t.ppf(0.95, sw-pl )  #T-value
            
            #Variance and prediction interval:
            Xb_y = np.dot(X,beta) - y
            Xb_y_t_W = np.dot(np.transpose(Xb_y), W)
            W_Xb_y   = np.dot(W, Xb_y)
            M1       = np.dot(Xb_y_t_W, W_Xb_y) 
            s = math.sqrt(M1/(sw-pl))
            
            M2 = np.dot(np.transpose(Xi), Xt_W_X_INV)
            M2 = np.dot(M2, Xi)
            I = t * s * math.sqrt(1.0 + M2 )
            
            
            return resul, I  
        except Exception as erro:
            print "\nError LWR\n",erro
            
            return None, None
