import requests
import csv
import time
import os
import json

API_KEY = 'YourApiKeyToken'  # TODO: replace with your API key
BASE_URL = 'https://api.etherscan.io/api'
TARGET_DIR = 'sources'

# Load the contract addresses from the CSV file
addresses = []
with open('../Utils/address_to_skelcode.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header row
    for row in reader:
        addresses.append(row[2])  # assuming contract address is in 2nd column

# Create target directory if it doesn't exist
os.makedirs(TARGET_DIR, exist_ok=True)

for idx, address in enumerate(addresses):
    # Prepare the URL
    request_url = f"{BASE_URL}?module=contract&action=getsourcecode&address={address}&apikey={API_KEY}"

    while True:
        # Make the API request
        response = requests.get(request_url)

        # Handle the response
        if response.status_code == 200:
            data = response.json()

            # Check if the response contains result
            if 'result' in data and data['result']:
                contract = data['result'][0]

                # check if json
                if contract['SourceCode'].startswith('{'):
                    try:
                        source_code_json = json.loads(contract['SourceCode'])
                        # Check if 'sources' key exists
                        if 'sources' in source_code_json:
                            source_dict = source_code_json['sources']
                        else:
                            source_dict = source_code_json
                        # Concatenate all 'content' fields into one string
                        source_code = '\n'.join(
                            [sc['content'] for sc in source_dict.values() if 'content' in sc])
                        # Write the source code to the .sol file
                        with open(f'sources/{address}.sol', 'w') as f:
                            f.write(source_code)
                    except:
                        pass  # TODO: handle this

                # Check if 'SourceCode' exists in contract and it's not empty
                else:
                    # Save the source code to a file, named after the contract address
                    with open(os.path.join(TARGET_DIR, f"{address}.sol"), 'w') as f:
                        f.write(contract['SourceCode'])

            break
        else:
            print(
                f"Request failed with status code {response.status_code}, retrying...")

        # Wait for a second before the next request to respect the rate limit
        time.sleep(1)
