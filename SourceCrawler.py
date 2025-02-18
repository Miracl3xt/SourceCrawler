import os
import re
import requests
import csv
import posixpath
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the directory path where your files are located
directory_path = r'C:\directory'

# Define the target host for URL validation
target_host = 'some.domain.com'  # Change to the host you want to validate against

# Define your custom regex pattern
url_pattern = r'(?<=[^a-zA-Z0-9_/])((?:/[\w.-]+)+)(?=[^a-zA-Z0-9_/])'

# --- Functions ---

def extract_urls_from_file(file_path, regex_pattern):
    """Extracts a set of unique URLs (or paths) from a given file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # Find all matches with regex
    urls = re.findall(regex_pattern, content)
    return set(urls)

def normalize_url_path(path_str):
    """
    1. Convert all backslashes to forward slashes.
    2. Normalize the path to remove any './' or '../' segments using posixpath.normpath.
    3. Ensure the result starts with a leading slash.
    """
    # Replace backslashes with forward slashes
    path_str = path_str.replace('\\', '/')
    # Normalize to remove ./ and ../ segments
    normalized = posixpath.normpath(path_str)
    
    # posixpath.normpath can return '.' if the path was empty or something like './'
    if normalized == '.' or not normalized:
        normalized = '/'
    
    # Ensure a leading slash
    if not normalized.startswith('/'):
        normalized = '/' + normalized.lstrip('/')
    
    return normalized

def validate_single_url(path_or_url, session, proxy=None):
    """
    Validates a single path or URL by sending a HEAD request.
    If the HEAD request returns a non-200 status code but a valid 
    Content-Length header is present, it makes a GET request to further validate.
    Returns a tuple (full_url, status_code_or_reason, content_length).
    """
    # Normalize the path
    path_or_url = normalize_url_path(path_or_url)
    # Build the final URL
    full_url = f'https://{target_host}{path_or_url}'

    try:
        response = session.head(full_url, proxies=proxy, timeout=10)
        status_code = response.status_code
        # Retrieve content length from headers if available; otherwise, mark as "N/A"
        content_length = response.headers.get('Content-Length', 'N/A')

        # If HEAD returns a non-200 status but a valid Content-Length is present,
        # attempt a GET request to further validate the URL.
        if status_code != 200 and content_length != 'N/A':
            try:
                get_response = session.get(full_url, proxies=proxy, timeout=10)
                status_code = get_response.status_code
                content_length = get_response.headers.get('Content-Length', 'N/A')
            except requests.exceptions.RequestException as e:
                # If GET fails, return the error message along with the URL.
                return (full_url, f"GET Failed ({e})", "N/A")

        return (full_url, status_code, content_length)
    except requests.exceptions.RequestException as e:
        # In case of an error during the HEAD request, return an error message.
        return (full_url, f"Failed to fetch ({e})", "N/A")

def categorize_result(result):
    """
    Helper function to categorize the result into valid/invalid based on status code or reason.
    Returns a tuple (category, url, status_code, content_length).
    """
    url, code, content_length = result
    if isinstance(code, int):
        if code == 200:
            return 'green', url, code, content_length
        elif code in [301, 302, 400, 403, 500]:
            return 'yellow', url, code, content_length
        else:
            return 'red', url, code, content_length
    else:
        # Non-integer code => likely an error message
        return 'red', url, code, content_length

# --- Main Execution ---

def main():
    proxy = None  # Replace with your proxy dict if needed, e.g., {'http': 'http://...', 'https': 'http://...'}

    # These lists will store all results
    valid_results = []
    invalid_results = []
    
    # This set will store all extracted paths
    all_paths = set()

    # Collect all URLs to validate (and remember from which file they came if needed)
    with requests.Session() as session, ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {}

        for root, _, files in os.walk(directory_path):
            for file_name in files:
                if file_name.endswith(('.js', '.php', '.ts', '.py', '.cs', '.html', '.yaml')):
                    file_path = os.path.join(root, file_name)
                    urls_in_file = extract_urls_from_file(file_path, url_pattern)
                    
                    # (Optional) Also treat the relative path as a "URL" if you want
                    rel_path = os.path.relpath(file_path, directory_path)
                    urls_in_file.add(rel_path)
                    
                    # Add the paths to the global set
                    all_paths.update(urls_in_file)

                    # For each URL in the file, create a future for validation
                    for url_candidate in urls_in_file:
                        future = executor.submit(validate_single_url, url_candidate, session, proxy)
                        future_to_url[future] = url_candidate

        # Process results as they complete
        for future in as_completed(future_to_url):
            url_candidate = future_to_url[future]
            try:
                result = future.result()  # (full_url, status_code_or_reason, content_length)
                category, full_url, code, content_length = categorize_result(result)

                if category in ['green', 'yellow']:  # considered valid
                    valid_results.append((full_url, code, content_length))
                    color = "\033[32m" if category == 'green' else "\033[33m"
                    print(f"{color}Valid URL: {full_url} (Status Code: {code}, Content-Length: {content_length})\033[0m")
                else:
                    invalid_results.append((full_url, code, content_length))
                    print(f"\033[31mInvalid URL: {full_url} (Status Code: {code}, Content-Length: {content_length})\033[0m")

            except Exception as exc:
                # Handles exceptions in the thread that weren't caught by requests
                full_url = f"https://{target_host}/{url_candidate.lstrip('/')}"
                invalid_results.append((full_url, f"Thread error: {exc}", "N/A"))
                print(f"\033[31mInvalid URL: {full_url} (Exception in thread: {exc})\033[0m")

    # Write all extracted paths to path.txt (creates the file if it doesn't exist)
    with open('path.txt', 'w', encoding='utf-8') as path_file:
        for path in sorted(all_paths):
            path_file.write(path + '\n')

    # --- Sorting Results ---
    def sort_key(item):
        # item is (url, code, content_length)
        _, code, _ = item
        return (isinstance(code, int), code if isinstance(code, int) else 999999)

    valid_results.sort(key=sort_key)
    invalid_results.sort(key=sort_key)

    # --- Write to CSV ---
    with open('valid.csv', 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['URL', 'Status Code', 'Content Length'])
        csv_writer.writerows(valid_results)

    with open('invalid.csv', 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['URL', 'Status Code', 'Content Length'])
        csv_writer.writerows(invalid_results)

    print("Validation complete.")
    print(f"Total valid URLs: {len(valid_results)}")
    print(f"Total invalid URLs: {len(invalid_results)}")
    print(f"Total unique paths extracted: {len(all_paths)}")

if __name__ == "__main__":
    main()
