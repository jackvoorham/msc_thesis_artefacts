import os
import csv
import glob

# Initialize an empty dictionary
address_to_contract = {}

# Define the number of contracts to process
num_contracts_to_process = 1000

# Read the contracts.csv file and get all contract addresses of interest
with open('contracts.csv', 'r') as file:
    reader = csv.reader(file)
    next(reader)  # Skip header row
    # Create a dictionary of contract addresses, all transformed to lower case,
    # with the contract number as the key
    contracts_of_interest = {int(row[0]): row[1].lower(
    ) for row in reader if int(row[0]) <= num_contracts_to_process}

# Navigate to the csv/skelcodes directory
os.chdir('csv/skelcodes')

# Loop through all CSV files in the directory
for filename in glob.glob('contract2skelcode*.csv'):
    with open(filename, 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header

        # Add address and skel_address pairs to the dictionary if address is in contracts_of_interest
        for row in reader:
            # Ensure these are the right indices, addresses are transformed to lower case
            contract_address = row[3].lower()
            if contract_address in contracts_of_interest.values():
                address_to_contract[contract_address] = (
                    row[7].lower(), row[8])  # Skel_address and contractname

# Navigate back to the root directory
os.chdir('../..')

filename = 'address_to_skelcode.csv'

# Writing data to a CSV file
with open(filename, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    # Write the header
    writer.writerow(["Contract Rank", "Contract Address",
                    "Skeleton Address", "Contract Name"])
    # Write the data
    for rank in sorted(contracts_of_interest.keys()):
        address = contracts_of_interest[rank]
        if address in address_to_contract:
            skel_address, contract_name = address_to_contract[address]
            writer.writerow([rank, address, skel_address, contract_name])
