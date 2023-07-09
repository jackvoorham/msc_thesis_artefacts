import os
import csv
import re
import shutil

# Initialize dictionaries
skelcode_to_contract = {}
skelcode_to_rank = {}

# Load the skeleton code to contract mapping from the CSV file
with open('../Utils/address_to_skelcode.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header row
    for row in reader:
        skelcode_to_contract[row[2]] = row[3]
        skelcode_to_rank[row[2]] = row[0]

# Specify root directory and new directory
root_dir = "results" #TODO: Change to this Di Angelo's results dataset
new_root_dir = "top_results"

# Define a regex pattern for Ethereum addresses
eth_address_pattern = "^0x[a-fA-F0-9]{40}$"

# Go through all directories and subdirectories in root_dir
for dirpath, dirnames, _ in os.walk(root_dir):
    # If we are in a 'skelcodes', 'retry32', 'timeout', 'timeout32', 'timeout1400' directory
    if any(sub in os.path.basename(dirpath) for sub in ['500', '500bis', 'skelcodes', 'retry32', 'timeout', 'timeout32', 'timeout1400']):
        for dir in dirnames:
            # Check if the folder's name contains '-'
            if '-' in dir:
                # If the folder's skeleton address is in address_to_skelcode.csv
                # split the folder name by '-' and compare the second part
                skelcode = dir.split('-')[1]
                # Verify the skelcode with regex
                if re.match(eth_address_pattern, skelcode):
                    # Use the skelcode-to-contract mapping to get the correct contract name
                    contract_name = skelcode_to_contract.get(
                        skelcode, skelcode)
                    if skelcode in skelcode_to_rank:
                        rank = skelcode_to_rank[skelcode]
                        tool = os.path.basename(os.path.dirname(dirpath))
                        new_dir = os.path.join(new_root_dir, skelcode, tool)
                        os.makedirs(new_dir, exist_ok=True)

                        src_dir = os.path.join(dirpath, dir)

                        # Iterate over all files in the source directory and move them
                        for file_name in os.listdir(src_dir):
                            full_file_name = os.path.join(src_dir, file_name)
                            if os.path.isfile(full_file_name):
                                shutil.copy(full_file_name, new_dir)
                        print(f"Copied files from {src_dir} to {new_dir}")
