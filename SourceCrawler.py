import os
import re
import json
import requests
import csv
import posixpath
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed

# Define the directory path where your files are located
directory_path = r'C:\folder'

# Define the target host for URL validation
target_host = 'some.host.com'  # Change to the host you want to validate against

# Define your custom regex pattern
url_pattern = r'(?<=[^a-zA-Z0-9_/])((?:/[\w.-]+)+)(?=[^a-zA-Z0-9_/])'

# --- Security Header Checks ---

def check_hsts(headers):
    """
    Checks the Strict-Transport-Security header.
    Returns a tuple (is_valid, value) where:
      - is_valid is a boolean (True if HSTS is implemented properly, False otherwise).
      - value is either the header value or "N/A" if not present.
    """
    hsts = headers.get('Strict-Transport-Security')
    if not hsts:
        return False, "N/A"
    if 'max-age' not in hsts:
        return False, hsts  # Header present but missing required directive
    return True, hsts

def check_csp(headers):
    """
    Checks the Content-Security-Policy header for common misconfigurations.
    Returns a tuple (is_valid, value) where:
      - is_valid is a boolean indicating whether the CSP is configured securely.
      - value is either a message with details or "N/A" if not present.
    """
    csp = headers.get('Content-Security-Policy')
    if not csp:
        return False, "N/A"
    
    messages = []
    valid = True

    # Check for overly permissive default-src usage (e.g., default-src *)
    if "default-src" in csp:
        if re.search(r"default-src\s+[^;]*\*", csp):
            messages.append("default-src is too permissive with wildcard (*)")
            valid = False

    # Check for inline script allowances in script-src
    if "script-src" in csp:
        if "unsafe-inline" in csp:
            messages.append("script-src allows unsafe-inline")
            valid = False
        if "unsafe-eval" in csp:
            messages.append("script-src allows unsafe-eval")
            valid = False

    # Check for inline style allowances in style-src
    if "style-src" in csp:
        if "unsafe-inline" in csp:
            messages.append("style-src allows unsafe-inline")
            valid = False

    # Check for risky URI schemes (data:, blob:, filesystem:) being allowed
    if re.search(r"(data:|blob:|filesystem:)", csp):
        messages.append("CSP allows risky URI schemes (data:, blob:, or filesystem:)")
        valid = False

    # Check if a reporting directive is missing (report-uri or report-to)
    if not ("report-uri" in csp or "report-to" in csp):
        messages.append("CSP does not include a reporting directive (report-uri or report-to)")
        # This can be treated as a warning if desired.

    if messages:
        return valid, "; ".join(messages)
    else:
        return True, csp

# --- Helper Functions ---

def extract_urls_from_file(file_path, regex_pattern):
    """Extracts a set of unique URLs (or paths) from a given file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # Find all matches with regex
    urls = re.findall(regex_pattern, content)
    return set(urls)

def extract_urls_from_text(text, regex_pattern):
    """Extracts URL-like paths from a given text."""
    return set(re.findall(regex_pattern, text))

def normalize_url_path(path_str):
    """
    1. Convert all backslashes to forward slashes.
    2. Normalize the path to remove any './' or '../' segments using posixpath.normpath.
    3. Ensure the result starts with a leading slash.
    """
    path_str = path_str.replace('\\', '/')
    normalized = posixpath.normpath(path_str)
    
    if normalized == '.' or not normalized:
        normalized = '/'
    
    if not normalized.startswith('/'):
        normalized = '/' + normalized.lstrip('/')
    
    return normalized

def validate_single_url(path_or_url, session, proxy=None):
    """
    Validates a single path or URL by sending a HEAD request and checking for
    security headers such as HSTS and CSP.
    
    Fallbacks:
      - If status_code != 200 and content_length is provided, perform a GET.
      - If status_code == 401, perform a GET.
      - If status_code != 200 and the URL ends with ".json", perform a GET and attempt
        to extract additional URL-like paths from the JSON response.
        
    Returns a tuple:
      (full_url, status_code_or_reason, content_length, security_info, extracted_urls)
    where extracted_urls is a set of new URL paths discovered from JSON content.
    """
    path_or_url = normalize_url_path(path_or_url)
    full_url = f'https://{target_host}{path_or_url}'
    extracted_urls = set()
    
    try:
        response = session.head(full_url, proxies=proxy, timeout=10)
        status_code = response.status_code
        content_length = response.headers.get('Content-Length', 'N/A')
        
        # Check security headers
        hsts_valid, hsts_info = check_hsts(response.headers)
        csp_valid, csp_info = check_csp(response.headers)
        security_info = {'HSTS': hsts_info, 'CSP': csp_info}
        
        # Fallback: if non-200 and content-length is provided, try GET
        if status_code != 200 and content_length != 'N/A':
            try:
                get_response = session.get(full_url, proxies=proxy, timeout=10)
                status_code = get_response.status_code
                content_length = get_response.headers.get('Content-Length', 'N/A')
                hsts_valid, hsts_info = check_hsts(get_response.headers)
                csp_valid, csp_info = check_csp(get_response.headers)
                security_info = {'HSTS': hsts_info, 'CSP': csp_info}
            except requests.exceptions.RequestException as e:
                return (full_url, f"GET Failed ({e})", "N/A", security_info, extracted_urls)
        
        # Handle 401 specifically by retrying with GET
        if status_code == 401 :
            try:
                get_response = session.get(full_url, proxies=proxy, timeout=10)
                status_code = get_response.status_code
                content_length = get_response.headers.get('Content-Length', 'N/A')
                hsts_valid, hsts_info = check_hsts(get_response.headers)
                csp_valid, csp_info = check_csp(get_response.headers)
                security_info = {'HSTS': hsts_info, 'CSP': csp_info}
            except requests.exceptions.RequestException as e:
                return (full_url, f"GET Failed ({e})", "N/A", security_info, extracted_urls)
        
        # Handle 503 specifically by retrying with GET
        if status_code == 503 :
            try:
                get_response = session.get(full_url, proxies=proxy, timeout=10)
                status_code = get_response.status_code
                content_length = get_response.headers.get('Content-Length', 'N/A')
                hsts_valid, hsts_info = check_hsts(get_response.headers)
                csp_valid, csp_info = check_csp(get_response.headers)
                security_info = {'HSTS': hsts_info, 'CSP': csp_info}
            except requests.exceptions.RequestException as e:
                return (full_url, f"GET Failed ({e})", "N/A", security_info, extracted_urls)
        
        # For URLs ending with .json, if still non-200, perform GET and extract new URLs
        if status_code != 200 and full_url.lower().endswith('.json'):
            try:
                get_response = session.get(full_url, proxies=proxy, timeout=10)
                status_code = get_response.status_code
                content_length = get_response.headers.get('Content-Length', 'N/A')
                hsts_valid, hsts_info = check_hsts(get_response.headers)
                csp_valid, csp_info = check_csp(get_response.headers)
                security_info = {'HSTS': hsts_info, 'CSP': csp_info}
                try:
                    json_data = get_response.json()
                    json_str = json.dumps(json_data)
                    extracted_urls = extract_urls_from_text(json_str, url_pattern)
                except Exception:
                    extracted_urls = set()
            except requests.exceptions.RequestException as e:
                return (full_url, f"GET Failed ({e})", "N/A", security_info, extracted_urls)
        
        return (full_url, status_code, content_length, security_info, extracted_urls)
    except requests.exceptions.RequestException as e:
        return (full_url, f"Failed to fetch ({e})", "N/A", {'HSTS': "N/A", 'CSP': "N/A"}, extracted_urls)

def categorize_result(result):
    """
    Helper function to categorize the result into valid/invalid based on status code or reason.
    Returns a tuple (category, url, status_code, content_length, security_info, extracted_urls).
    """
    url, code, content_length, security_info, extracted_urls = result
    if isinstance(code, int):
        if code == 200:
            return 'green', url, code, content_length, security_info, extracted_urls
        elif code in [301, 302, 400, 403, 500]:
            return 'yellow', url, code, content_length, security_info, extracted_urls
        else:
            return 'red', url, code, content_length, security_info, extracted_urls
    else:
        return 'red', url, code, content_length, security_info, extracted_urls

# --- Main Execution ---

def main():
    proxy = None  # Replace with your proxy dict if needed, e.g., {'http': 'http://...', 'https': 'http://...'}
    valid_results = []
    invalid_results = []
    
    # We'll keep track of processed URLs to avoid duplicates
    processed_urls = set()
    # And a queue for URLs pending validation
    pending_urls = deque()
    
    # Initially, extract URLs from files and add them to the pending queue.
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.endswith(('.js', '.php', '.ts', '.py', '.cs', '.html', '.yaml', '.json')):
                file_path = os.path.join(root, file_name)
                urls_in_file = extract_urls_from_file(file_path, url_pattern)
                # Also treat the file's relative path as a URL candidate
                rel_path = os.path.relpath(file_path, directory_path)
                urls_in_file.add(rel_path)
                for url_candidate in urls_in_file:
                    normalized = normalize_url_path(url_candidate)
                    if normalized not in processed_urls:
                        pending_urls.append(normalized)
                        processed_urls.add(normalized)
    
    # Process URLs concurrently; as new URLs are discovered (from JSON responses),
    # add them to the pending queue.
    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=10) as executor:
            while pending_urls:
                futures = {}
                # Drain the current batch of pending URLs
                current_batch = []
                while pending_urls:
                    url_candidate = pending_urls.popleft()
                    future = executor.submit(validate_single_url, url_candidate, session, proxy)
                    futures[future] = url_candidate
                    current_batch.append(url_candidate)
                
                # Process completed futures
                for future in as_completed(futures):
                    url_candidate = futures[future]
                    try:
                        result = future.result()  # (full_url, status, content_length, sec_info, extracted_urls)
                        category, full_url, code, content_length, sec_info, new_urls = categorize_result(result)
                        
                        # Add any new URLs discovered from JSON responses
                        for new_url in new_urls:
                            normalized_new = normalize_url_path(new_url)
                            if normalized_new not in processed_urls:
                                pending_urls.append(normalized_new)
                                processed_urls.add(normalized_new)
                        
                        if category in ['green', 'yellow']:
                            valid_results.append((full_url, code, content_length, sec_info))
                            color = "\033[32m" if category == 'green' else "\033[33m"
                            print(f"{color}Valid URL: {full_url} (Status Code: {code}, Content-Length: {content_length})")
                            print(f"    HSTS: {sec_info.get('HSTS', 'N/A')} | CSP: {sec_info.get('CSP', 'N/A')}\033[0m")
                        else:
                            invalid_results.append((full_url, code, content_length, sec_info))
                            print(f"\033[31mInvalid URL: {full_url} (Status Code: {code}, Content-Length: {content_length})")
                            print(f"    HSTS: {sec_info.get('HSTS', 'N/A')} | CSP: {sec_info.get('CSP', 'N/A')}\033[0m")
                    except Exception as exc:
                        full_url = f"https://{target_host}/{url_candidate.lstrip('/')}"
                        invalid_results.append((full_url, f"Thread error: {exc}", "N/A", {'HSTS': "N/A", 'CSP': "N/A"}))
                        print(f"\033[31mInvalid URL: {full_url} (Exception in thread: {exc})\033[0m")
    
    # Write out all unique paths processed
    with open('path.txt', 'w', encoding='utf-8') as path_file:
        for path in sorted(processed_urls):
            path_file.write(path + '\n')
    
    # --- Sorting Results ---
    def sort_key(item):
        _, code, _, _ = item
        return (isinstance(code, int), code if isinstance(code, int) else 999999)
    
    valid_results.sort(key=sort_key)
    invalid_results.sort(key=sort_key)
    
    # --- Write to CSV ---
    with open(f'{target_host}_valid.csv', 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['URL', 'Status Code', 'Content Length', 'HSTS', 'CSP'])
        for url, code, content_length, sec in valid_results:
            csv_writer.writerow([url, code, content_length, sec.get('HSTS', 'N/A'), sec.get('CSP', 'N/A')])
    
    with open(f'{target_host}_invalid.csv', 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['URL', 'Status Code', 'Content Length', 'HSTS', 'CSP'])
        for url, code, content_length, sec in invalid_results:
            csv_writer.writerow([url, code, content_length, sec.get('HSTS', 'N/A'), sec.get('CSP', 'N/A')])
    
    print("Validation complete.")
    print(f"Total valid URLs: {len(valid_results)}")
    print(f"Total invalid URLs: {len(invalid_results)}")
    print(f"Total unique paths extracted: {len(processed_urls)}")

if __name__ == "__main__":
    main()
