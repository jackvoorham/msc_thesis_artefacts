## Overview

This repository facilitates the creation of a fully functional command-line tool to measure the security of Ethereum smart contracts based on our Security Quality Model.

## Repository Structure

The repository is structured as follows:

Mappings: Contains YAML files for each Ethereum security tool mapping detected vulnerabilities to their SWC identifiers.

Results: Holds the final results of running the workflow for RQ2, such as metrics_and_findings.csv and thresholds.csv.

Tool: Contains the Python script tool.py, which is the command-line tool. It also contains smartbugs as a submodule, as this is necessary for the tool to run correclty.

Thresholds: Consists of Python scripts that form the core of the workflow for RQ3 These scripts extract contract addresses, determine skeleton codes, fetch source code, extract findings, compute metrics, and calculate thresholds.

Utils: Houses utility files, including the SolMet tool JAR file and CSV files (contracts.csv, address_to_skelcode.csv), and a taxonomy.yaml file, these are used in both the tool and treshold calculation processes.

## Note

Please note: This workflow requires datasets from Di Angelo et al. (https://figshare.com/s/5efef6335fa98ddc3ae2) and its corresponding skelcode mappings (https://github.com/gsalzer/skelcodes), which is necessary to run Tresholds/contract2skels.py and Tresholds/get_results.py. Also it requires the Solidity compiler (solcx). Ensure you have the correct permissions and access to scrape data from Etherscan. An Etherscan API, which can be obtained here (https://etherscan.io/apis), is required to run Tresholds/get_source.py.
