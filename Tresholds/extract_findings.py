import os
import json
import yaml
import csv
import subprocess
from collections import defaultdict

mappings_dir = '../Mappings'  # directory of mappings files
root_dir = './top_results'  # TODO: change to directory of tool results
dir_path = "./sources"  # TODO: change to directory of solidity files


def calculate_metrics(filename, dir_path):
    total_lloc, total_cbo, total_wmc = 0, 0, 0
    try:
        with open("temp_metrics.csv", "w") as file:
            command = ["java", "-jar", "../Utils/SolMet-1.0-SNAPSHOT.jar", "-inputFile",
                    f"{dir_path}/{filename}", "-outFile", "temp_metrics.csv"]
            with open(os.devnull, 'w') as devnull:
                subprocess.run(command, stdout=devnull, stderr=subprocess.STDOUT)
            with open('temp_metrics.csv', 'r') as file:
                reader = csv.reader(file, delimiter=';')
                next(reader)
                for row in reader:
                    lloc = int(row[5])
                    cbo = int(row[16])
                    wmc = int(row[8])
                    total_lloc += lloc
                    total_cbo += cbo * lloc
                    total_wmc += wmc * lloc
    except Exception as e:
        print(f"Failed to calculate metrics for {filename}. Error: {e}")
        
    try :
        os.remove("temp_metrics.csv")
    except Exception as e:
        print(f"Failed to remove temp_metrics.csv. Error: {e}")
        
    return total_lloc, total_cbo, total_wmc


def get_findings(root_dir, mappings_dir):
    contracts = defaultdict(lambda: defaultdict(int))

    mappings = {}
    for file in os.listdir(mappings_dir):
        if file.endswith('.yaml'):
            with open(os.path.join(mappings_dir, file), 'r') as f:
                tool_mappings = yaml.safe_load(f)
                for vulnerability, data in tool_mappings.items():
                    if 'classification' in data:
                        mappings[vulnerability] = data['classification'].split(",")[
                            0]

    for contract_rank_dir in os.listdir(root_dir):
        contract_rank_dir_path = os.path.join(root_dir, contract_rank_dir)
        if os.path.isdir(contract_rank_dir_path):
            for tool_dir in os.listdir(contract_rank_dir_path):
                tool_dir_path = os.path.join(contract_rank_dir_path, tool_dir)
                if os.path.isdir(tool_dir_path):
                    for result_file_name in os.listdir(tool_dir_path):
                        if result_file_name == 'result.json':
                            result_file_path = os.path.join(
                                tool_dir_path, result_file_name)
                            with open(result_file_path) as f:
                                result_json = json.load(f)
                                contract_address = contract_rank_dir
                                findings = result_json.get('findings', [])
                                for finding in findings:
                                    swc_code = mappings.get(
                                        finding.get('name'))
                                    if swc_code:
                                        contracts[contract_address][swc_code] += 1
    return contracts


def write_to_csv(contracts, dir_path):
    metrics_filename = "metrics_and_findings.csv"
    swc_codes = sorted(set(code for findings in contracts.values()
                       for code in findings))

    with open(metrics_filename, 'w', newline='') as csvfile:
        fieldnames = ['ContractAddress', 'LLOC', 'CBO', 'WMC'] + swc_codes
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for filename in os.listdir(dir_path):
            if filename.endswith(".sol"):
                contract_address = filename.split(".")[0]

                total_lloc, total_cbo, total_wmc = calculate_metrics(
                    filename, dir_path)
                findings = contracts.get(contract_address, {})

                row = {
                    'ContractAddress': contract_address,
                    'LLOC': total_lloc,
                    'CBO': total_cbo,
                    'WMC': total_wmc,
                }
                row.update({swc: findings.get(swc, 0) for swc in swc_codes})
                writer.writerow(row)


contracts = get_findings(root_dir, mappings_dir)
write_to_csv(contracts, dir_path)
