import csv
import json
import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor

# Function to get the description of a package from the API
def get_package_description(package_name, api_key, retries=3, delay=5):
    url = f"https://androzoo.uni.lu/api/get_gp_metadata/{package_name}"
    
    for attempt in range(retries):
        try:
            response = requests.get(url, params={'apikey': api_key}, timeout=10)  # Add timeout
            response.raise_for_status()  # Raise an exception for bad status codes
            data = response.json()
            if data:
                return data[0].get('descriptionHtml', ''), package_name  # Return both description and package name
            return '', package_name  # Return empty if no description found
        except (requests.exceptions.RequestException, requests.exceptions.ConnectionError) as e:
            print(f"Error fetching {package_name}: {e}")
            if attempt < retries - 1:
                print(f"Retrying... ({attempt + 1}/{retries})")
                time.sleep(delay)  # Wait before retrying
            else:
                print(f"Failed to fetch {package_name} after {retries} attempts.")
                return '', package_name

# Read SHA256 and package names from CSV file
def get_packages_from_csv(csv_file):
    packages = []
    with open(csv_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            packages.append((row['sha256'], row['pkg_name']))  # Extract both SHA256 and package name
    return packages

# Get the last processed package from progress file
def get_last_processed_package(progress_file="progress.txt"):
    if os.path.exists(progress_file):
        with open(progress_file, 'r', encoding='utf-8') as file:
            return file.readline().strip()
    return None

# Save progress to the progress file
def save_progress(package_name, progress_file="progress.txt"):
    with open(progress_file, 'w', encoding='utf-8') as file:
        file.write(package_name)

# Function to save the results to a CSV file
def save_descriptions_to_csv(packages, api_key, file_name="descriptions.csv"):
    last_processed_package = get_last_processed_package()  # Get last processed package

    start_index = 0
    if last_processed_package:
        package_names = [pkg[1] for pkg in packages]
        if last_processed_package in package_names:
            start_index = package_names.index(last_processed_package) + 1  # Start after last processed package
        else:
            print(f"Package {last_processed_package} not found in the list. Starting from the beginning.")

    # Open the CSV file in append mode and write the header if it's empty
    with open(file_name, 'a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        file_empty = os.stat(file_name).st_size == 0  # Check if file is empty to write header
        if file_empty:
            writer.writerow(['sha256', 'pkg_name', 'description'])  # Write header
        
        # Use ThreadPoolExecutor for multithreading
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda pkg: get_package_description(pkg[1], api_key), packages[start_index:])
            
            for (sha256, package_name), (description, _) in zip(packages[start_index:], results):
                if description:
                    writer.writerow([sha256, package_name, description])  # Use SHA256 from CSV
                    print(f"Description for {package_name}: {description[:100]}...")  # Preview first 100 characters
                    save_progress(package_name)  # Save progress after processing each package
                else:
                    print(f"No description found for {package_name}")

# Define your API key
API_KEY = "Insert androzoo api key here"

# Get package names and their SHA256 hashes from CSV
packages = get_packages_from_csv('androzoo_cleaned.csv') # androzoo csv file after removing duplicates of the same application and only leaving the latest version

# Save descriptions to descriptions.csv
save_descriptions_to_csv(packages, API_KEY)

print("Descriptions saved to descriptions.csv. Now, you can run the iotspotter-classifier.py model to classify the descriptions.")
