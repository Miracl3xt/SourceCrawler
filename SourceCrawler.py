import os
import re
import requests
import csv
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# Define the directory path where your files are located
directory_path = '/Users/path'

# Define the target host for URL validation
target_host = 'www.example.com'  # Change to the host you want to validate against

# Define your custom regex pattern
url_pattern = r'(?<=[^a-zA-Z0-9_/])((?:/[\w.-]+)+)(?=[^a-zA-Z0-9_/])'

# Initialize lists to store valid and invalid URLs
valid_urls = []
invalid_urls = []

# Function to extract URLs from a given file
def extract_urls_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        urls = re.findall(url_pattern, content)
        return urls

# Function to validate URLs against the target host with a proxy
def validate_urls(urls,session, proxy=None):
    for url in urls:
        #full_url = f'https://{target_host}{url}' if not url.startswith('/') else f'https://{target_host}{url}'
        full_url = f'https://{target_host}/{url.lstrip("/")}' if not url.startswith('/') else f'https://{target_host}{url}'# Add a slash if missing
        try:
            response = requests.head(full_url, proxies=proxy)
            status_code = response.status_code
            if status_code == 200:
                valid_urls.append((f"{full_url}", status_code))  # Green
                print(f"\033[32mValid URL: {full_url} (Status Code: {status_code})\033[0m")  # Green
            elif status_code in [301, 302, 400, 403, 500]:
                valid_urls.append((f"{full_url}", status_code))  # Yellow
                print(f"\033[33mValid URL: {full_url} (Status Code: {status_code})\033[0m")  # Yellow
            else:
                invalid_urls.append((f"{full_url}", status_code))  # Red
                print(f"\033[31mInvalid URL: {full_url} (Status Code: {status_code})\033[0m")  # Red
        except requests.exceptions.RequestException:
            invalid_urls.append((f"{full_url}", "Failed to fetch"))  # Red
            print(f"\033[31mInvalid URL: {full_url} (Failed to fetch)\033[0m")  # Red

# Define your proxy settings here, if needed
# Example: proxy = {'http': 'http://your_proxy_address', 'https': 'http://your_proxy_address'}
proxy = None  # Set to None if no proxy is required

# # Recursively walk through the directory and extract URLs from each supported file
# for root, _, files in os.walk(directory_path):
#     for file_name in files:
#         if file_name.endswith(('.js', '.php', '.ts', '.py')):
#             file_path = os.path.join(root, file_name)
#             urls_in_file = extract_urls_from_file(file_path)
#             unique_urls = set(urls_in_file)
#             rel_path = os.path.relpath(file_path, directory_path)  # Get the relative path
#             unique_urls.add(rel_path)  # Add the relative path to the URLs

#             # Validate the extracted URLs against the target host with the specified proxy
#             validate_urls(unique_urls, proxy)

with ThreadPoolExecutor(max_workers=10) as executor, requests.Session() as session:
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith(('.js', '.php', '.ts', '.py')):
                file_path = os.path.join(root, file_name)
                urls_in_file = extract_urls_from_file(file_path)
                unique_urls = set(urls_in_file)
                rel_path = os.path.relpath(file_path, directory_path)  # Get the relative path
                unique_urls.add(rel_path)  # Add the relative path to the URLs

                # Validate the extracted URLs against the target host with the specified proxy
                futures = [executor.submit(validate_urls, unique_urls, session, proxy)]



# Sort the valid and invalid URLs by status code
valid_urls.sort(key=lambda x: (isinstance(x[1], int), x[1]))
invalid_urls.sort(key=lambda x: (isinstance(x[1], int), x[1]))

# Export valid URLs to a CSV file
with open('valid.csv', 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['URL', 'Status Code'])
    csv_writer.writerows(valid_urls)

# Export invalid URLs to a CSV file
with open('invalid.csv', 'w', newline='') as csvfile:
    csv_writer = csv.writer(csvfile)
    csv_writer.writerow(['URL', 'Status Code'])
    csv_writer.writerows(invalid_urls)

