# IoTDataset

The repository contains the code files used to get the dataset used in our paper, When Apps Outlive Vendors: Security Implications of IoT Abandonware

We start by first getting the csv file of all apks available from Androzoo [here](https://androzoo.uni.lu/api_doc), under the "Obtaining SHA256 Hashes" section.

We then clean this csv, as it contains duplicates of the same application but of different versions. We remove all duplicates but  keep only the latest version.

Then, we use [Androzoo's API](https://androzoo.uni.lu/api_doc) to get the descrptions of all of these applications. 

Now that we have the description of all of these applications, we classify them using [IoTSpotter's](https://github.com/xinjin95/IoTSpotter/tree/main?tab=readme-ov-file#6-mobile-iot-app-classifiers) BERT classification model.


After classifying the apps as either IoT or non-IoT, we keep the IoT ones and check if they have been abandoned. An app is considered abandoned if it is there in the playstore but has not received an update in over 2 years, or if it no longer exists in the playstore.This makes up our final dataset.


In the `abandoned_apps.csv` file, it contains 61,500 apps' IDs that we collected. 
is_obsolete indicates whether the apps is abandoned (no updates for 2 years and no longer in the Google Play Store)
