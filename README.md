This repository provides a workflow for constructing a robust and representative benchmark dataset for our Ethereum smart contracts security model. This benchmark is created using the top 1000 most transacted smart contracts on the Ethereum blockchain.

The code for our experiments is implemented in Python, and all scripts can be found in this repository. The steps to set up the benchmark and calculate the thresholds are as follows:

### Extract Contract Addresses
Use the script get_addresses.py to extract the top 1000 most used contract addresses from Etherscan. This will create a CSV file named contracts.csv with the contract ranks and addresses.

### Determine Skeleton Codes
We will use the dataset by Di Angelo et al., (! This dataset can be found at https://figshare.com/s/5efef6335fa98ddc3ae2 and has to be manually put where necessary !), which contains all the results from various Ethereum analysis tools. This dataset is based on the bytecodes deployed on the Ethereum blockchain before block 14,000,000 on Ethereum's main chain. The script contract2skels.py will create a new file named address_to_skelcode.csv that maps each contract address to its corresponding skeleton code.

### Extract Property Results
The get_results.py script reads the address_to_skelcode.csv file and the dataset provided by Di Angelo et al. For each contract address in our benchmark dataset, it retrieves the corresponding skelcode from the mapping and then searches for the skelcode in Di Angelo's dataset. The results are copied to a new folder called top_results, which contains all results grouped by contract address.

### Fetch Source Code
The script get_source.py uses the Etherscan API to get the source code for each contract. These source codes are saved in a folder named sources.

### Extract Findings and Compute Metrics
The extract_findings.py script reads the files in the top_results and sources directories. It calculates metrics from the source code file for each contract in our benchmark dataset and aggregates the findings from the property-based analysis tools. The metrics are calculated with the SolMet tool using the JAR in the repository. All the resulting information is written to a metrics_and_findings.csv file, where each row corresponds to a contract and contains the occurrences of the property-based findings and the metric values.

### Compute Thresholds
The final script, treshold_calculator.py, reads the data from the metrics_and_findings.csv file and calculates each property's threshold. These thresholds are written to a new file called thresholds.csv, where each row corresponds to a property and contains the calculated thresholds.

NOTE: As this workflow requires datasets from Di Angelo et al. and scraping from Etherscan, it is necessary to manually download and set up these datasets and ensure you have the correct access and permissions to scrape data from Etherscan. An Etherscan API is needed, which can be obtained at https://etherscan.io/apis.

NOTE: All (where possible) resulting files are pre-computed and available as artifacts in this repository.

NOTE: The mappings folder contains the necessary vulnerability names detected by tools and their SWC mappings; these are obtained from https://github.com/smartbugs/smartbugs/tree/master/tools
