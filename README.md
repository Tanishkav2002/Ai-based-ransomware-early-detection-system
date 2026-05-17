# Ransomware Detection System (Machine Learning Based)

## Overview

This project is a machine learning-based ransomware detection system that identifies malicious activities using behavioral analysis. Instead of relying on traditional signature-based methods, the system analyzes system behavior to detect both known and unknown ransomware attacks.

It uses Sysmon logs to monitor system activities such as process creation, file changes, and registry updates. These logs are then processed and used to predict whether the activity is normal or ransomware.

## Features

* Behavior-based ransomware detection
* Can detect zero-day (unknown) attacks
* Uses multiple machine learning models: Random Forest, SVM, and XGBoost
* Feature extraction from Sysmon logs
* Simple web interface using Flask
* Improved accuracy using ensemble learning

## How It Works

1. Sysmon collects system activity logs
2. Logs are cleaned and converted into useful data
3. Important features are extracted
4. Machine learning models analyze the data
5. Final prediction is made using combined model results
6. Output is shown as Normal or Ransomware

## Tech Stack

* Python
* Scikit-learn, XGBoost
* Flask
* Pandas, NumPy
* Sysmon

## Project Structure

* app.py – main application
* modeltrain.ipynb – model training
* sysmon_integration.ipynb – log processing
* templates/ – HTML files
* uploads/ – input files
* images/ – project images
* model files (.pkl)

## Dataset

The model is trained using the CIC-MalMem-2022 dataset, which contains both normal and ransomware behavior data.

## Output

The system predicts whether the input activity is normal or ransomware.

## Future Scope

* Real-time log monitoring
* Cloud deployment
* Better accuracy with advanced models

## Author

Final Year CSE Student, VIT Vellore

## Note

This project focuses on behavior-based detection, which makes it more effective than traditional antivirus systems.
