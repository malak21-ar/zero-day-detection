# Zero-Day Attack Detection Using a Hybrid AI Architecture

#Project Overview
This is a personal project that combines Artificial Intelligence and Cybersecurity to explore the detection of Zero-Day attacks in network traffic.
The project implements a hybrid detection architecture combining an Autoencoder and a Random Forest Classifier. A public network traffic dataset, NSL-KDD, is used for training and evaluation.
As NSL-KDD contains known attacks, the DoS attack family is intentionally excluded from the training data and simulated as a Zero-Day attack family. This allows the system to be tested on an attack family that was not seen during training.

#Objectives
The main objectives of this project are to:

Explore the use of Artificial Intelligence for cybersecurity.
Detect abnormal network traffic using an Autoencoder.
Classify known network attacks using Random Forest.
Simulate Zero-Day attack detection using an unseen attack family.
Experiment with a hybrid AI-based architecture for network intrusion detection.


#Hybrid Architecture
The proposed architecture follows two main stages:

                 Network Traffic
                        │
                        ▼
                  Autoencoder
                        │
             Reconstruction Error
                        │
              ┌─────────┴─────────┐
              │                   │
        Low Error             High Error
        = Normal              = Anomaly
              │                   │
              ▼                   ▼
       Random Forest           Zero-Day
              │
              ▼
     Known Attack Classification
     
1. Autoencoder
The Autoencoder is trained using normal network traffic.
It learns to reconstruct normal traffic. The reconstruction error is then used to determine whether a new traffic sample is similar to normal behavior or appears anomalous.
A threshold is used to distinguish between:
Low reconstruction error → normal-like traffic
High reconstruction error → anomaly / simulated Zero-Day
The Autoencoder is implemented using MLPRegressor from Scikit-learn.

2. Random Forest
When the traffic is considered normal-like by the Autoencoder, it is passed to a Random Forest Classifier.
The Random Forest is trained to classify known traffic into attack families such as:
Normal
Probe
R2L
U2R
The DoS family is excluded from training so that it can be used as the simulated Zero-Day family during evaluation.


#Dataset
The project uses the NSL-KDD public dataset, which contains network traffic records with multiple features describing network connections.
The dataset is used to train and evaluate the Machine Learning models.
The original dataset files are not included in this repository. They can be obtained separately from the public NSL-KDD dataset source.

#Technologies Used
-Python
-Scikit-learn
  - MLPRegressor
  - RandomForestClassifier
  - StandardScaler
  - LabelEncoder
-Pandas
-NumPy
-Joblib
