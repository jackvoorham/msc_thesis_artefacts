import sys
import csv
import yaml
import re
sys.path.append('./smartbugs')
import sb.errors
import sb.settings
import sb.smartbugs
from packaging.version import Version
import solcx
import subprocess
import csv
import os
import shutil
import json
from rich.console import Console
from rich.progress import track
from rich.table import Table
import argparse
from datetime import datetime
from collections import defaultdict, Counter

TEMP_RESULT = "temp_result.json"
THRESHOLDS = "../Results/thresholds.csv"
TAXONOMY = '../Utils/taxonomy.yaml'  # Path to the taxonomy file

def calculate_metrics(filename):
    total_lloc, total_cbo, total_wmc = 0, 0, 0

    try:
        if not os.path.exists("./metrics.csv"):
            # create empty metrics.csv file
            with open("./metrics.csv", 'w') as file:
                command = ["java", "-jar", "../Utils/SolMet-1.0-SNAPSHOT.jar", "-inputFile",
                        f"./{filename}", "-outFile", "metrics.csv"]
                with open(os.devnull, 'w') as devnull:
                    subprocess.run(command, stdout=devnull, stderr=subprocess.STDOUT)
                with open('metrics.csv', 'r') as file:
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
    
    try: 
        os.remove('metrics.csv')
    except OSError:
        pass
    
    return total_lloc, total_cbo, total_wmc

def load_taxonomy(taxonomy_file):
    with open(taxonomy_file, 'r') as f:
        data = yaml.safe_load(f)
    taxonomy = data.get('taxonomy', [])  # extract the list from the dictionary

    swc_to_property = {}
    all_properties = {}
    property_to_impacts = {}  # additional dictionary for impacts

    for item in taxonomy:
        if isinstance(item, dict):
            group = item.get('group')
            if group:
                for vulnerability in item.get('vulnerabilities', []):
                    property_name = vulnerability.get('property')
                    impacts = vulnerability.get('impacted', [])  # get the impacts

                    if property_name:
                        all_properties[property_name] = 0
                        property_to_impacts[property_name] = impacts  # store the impacts for this property

                    if 'swc' in vulnerability:
                        swc_to_property[str(vulnerability['swc'])] = property_name  # convert swc to str

    return swc_to_property, all_properties, property_to_impacts

# Load thresholds from csv file
def load_thresholds():
    thresholds = {}
    with open(THRESHOLDS, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            thresholds[row['Property']] = (float(row['Threshold_Lower']), float(row['Threshold_Middle']), float(row['Threshold_Upper']))
    return thresholds

# Load tools from taxonomy
def load_tools():
    with open(TAXONOMY, 'r') as file:
        taxonomy_data = yaml.safe_load(file)
    tools = set()
    for group in taxonomy_data['taxonomy']:
        for vuln in group['vulnerabilities']:
            if 'tools' in vuln:
                tools.update(vuln['tools'])
    # Exclude SolMet manually
    if "SolMet" in tools:
        tools.remove("SolMet")
        
    # change all to lowercase
    tools = set([tool.lower() for tool in tools])
    return list(tools)

# Calculate utility function
def calculate_property_utility(s, t_l, t_m, t_u):
    if s <= t_l:
        return 1
    elif t_l <= s <= t_m:
        return 0.5 / (t_l - t_m) * (s + t_l - 2 * t_m)
    elif t_m <= s <= t_u:
        return 0.5 ** 2 / (t_m - t_u) * (s - t_u)
    elif s >= t_u:
        return 0

# Read contract file and return solidity version
def read_contract(file_name):
    with open(file_name, 'r') as file:
        content = file.read()
    match = re.search(r'pragma solidity\s*([^;]*);', content)
    if match:
        version = match.group(1).strip()
        # Select first version in case of a version range
        version = version.split()[0] if ' ' in version else version
        version = version.lstrip('^').lstrip('~')  # Remove caret and tilde
        version = '0.4.11' if Version(version) < Version('0.4.11') else version
        return version, content
    return None, content

def compile_contract(solc_version, contract_source_code):
    # Check if the required Solidity compiler version is installed or not.
    solcx.install_solc(solc_version)

    solcx.set_solc_version(solc_version)

    compiled_json = solcx.compile_source(contract_source_code, output_values=["bin-runtime"])

    contract_name = contract_source_code.split("contract")[1].split("{")[0].strip()
    
    bytecode = compiled_json[f'<stdin>:{contract_name}']['bin-runtime']

    return bytecode

def load_json_results(file_path):
    with open(file_path, 'r') as f:
        results_data = json.load(f)
    return results_data

def extract_findings_from_directory(results_folder, mappings):
    # Create a dictionary to store all findings
    all_findings = defaultdict(Counter)

    # Iterate over all files in the given directory
    for root, dirs, files in os.walk(results_folder):
        for file in files:
            # Check if file is result.json
            if file == "result.json":
                file_path = os.path.join(root, file)
                contract_address = root.split('/')[-1]  # Extract the contract address from the path
                
                # Load JSON results
                with open(file_path) as f:
                    result_json = json.load(f)

                findings = result_json.get('findings', [])
                for finding in findings:
                    swc_code = mappings.get(finding.get('name'))
                    if swc_code:
                        all_findings[contract_address][swc_code] += 1

    return all_findings

def calculate_M(total_metric, total_lloc):
    return total_metric / total_lloc if total_lloc != 0 else 0

def calculate_savd_and_group_by_property(swc_counts, total_lloc, swc_to_property):
    swc_savd = {swc_code: (count / total_lloc) *
                1000 for swc_code, count in swc_counts.items() if total_lloc != 0}

    property_counts = defaultdict(int)
    property_savd = defaultdict(float)
    for swc_code, count in swc_counts.items():
        swc_code = swc_code.replace("SWC-", "")  # remove the "SWC-" prefix
        property = swc_to_property.get(swc_code, 'Unknown')
        if property != 'Unknown':
            property_counts[property] += count
            property_savd[property] += swc_savd.get("SWC-" + swc_code, 0)
    return property_counts, property_savd

def write_results(score, duration, date, contract_name, output_file):
    result = {
        "Contract Name": contract_name,
        "Security Score": score,
        "Analysis Duration (Minutes)": duration,
        "Analysis Date": date
    }
    with open(output_file, 'w') as outfile:
        json.dump(result, outfile, indent=4)

        
def main(file_name, output_file):
    console = Console()

    settings = sb.settings.Settings()

    tools = load_tools()
    tools = ["mythril"]

    version, contract_source_code = read_contract(file_name)

    bytecode = compile_contract(version, contract_source_code)

    with open('bytecode.rt.hex', 'w') as file:
        file.write(bytecode)

    settings.update({
        "tools": tools,
        "files": ["./bytecode.rt.hex"],
        "json": True,
    })

    thresholds = load_thresholds()

    try:
        start_time = datetime.now()
        sb.smartbugs.main(settings)
        mappings_dir = '../mappings'
        
        # Create a table for the utility scores
        utility_table = Table(title="Utility Scores")
        utility_table.add_column("Property", justify="right")
        utility_table.add_column("Score", justify="right")

        characteristics_table = Table(title="Characteristic Scores")
        characteristics_table.add_column("Characteristic", justify="right")
        characteristics_table.add_column("Score", justify="right")

        mappings = {}
        for file in os.listdir(mappings_dir):
            if file.endswith('.yaml'):
                with open(os.path.join(mappings_dir, file), 'r') as f:
                    tool_mappings = yaml.safe_load(f)
                    for vulnerability, data in tool_mappings.items():
                        if 'classification' in data:
                            mappings[vulnerability] = data['classification'].split(",")[0]

        swc_to_property, all_properties, property_to_impacts = load_taxonomy(TAXONOMY)

        all_findings = extract_findings_from_directory("./results", mappings)
        lloc, cbo, wmc = calculate_metrics(file_name)

        # Add the counts from all findings to the all_properties dictionary
        for contract_address, findings in all_findings.items():
            for swc, count in findings.items():
                # Get the property name for the SWC number
                property_name = swc_to_property.get(swc.replace("SWC-", ""), "Unknown property")
                if property_name in all_properties:
                    all_properties[property_name] += count

        # Associate metrics with their corresponding properties
        all_properties["Weighted Methods per Class"] = wmc
        all_properties["Coupling Between Object classes"] = cbo

        # For each property in the taxonomy, calculate and print its utility score
        property_to_utility = {}  # Store the utility for each property
        for property in all_properties:
            score = all_properties[property]
            if property in thresholds:
                t_l, t_m, t_u = thresholds[property]
                utility = calculate_property_utility(score, t_l, t_m, t_u)
            else:
                print("No threshold found for property, skipping: ", property)

            if (utility < 0.5):
                utility_table.add_row(property, f"[red]{utility}[/red]")
            else:
                utility_table.add_row(property, f"[green]{utility}[/green]")

            property_to_utility[property] = utility

        # Initialize a dictionary to store the characteristic scores
        characteristic_scores = {
            "Confidentiality": 0,
            "Integrity": 0,
            "Availability": 0,
            "Access Control": 0
        }
        
        console.print(utility_table)
        print("\n")

        # Map from characteristics to the number of properties that impact each one
        characteristic_to_properties = {}
        for property, impacts in property_to_impacts.items():
            for impact in impacts:
                if impact not in characteristic_to_properties:
                    characteristic_to_properties[impact] = set()
                characteristic_to_properties[impact].add(property)

        # For each property, add its utility to the scores of its corresponding characteristics
        for property, utility in property_to_utility.items():
            if property in property_to_impacts:
                impacts = property_to_impacts[property]
                for impact in impacts:
                    if impact in characteristic_scores:
                        impact_weight = 1.0 / len(characteristic_to_properties[impact])  # The weight of each impact is 1 divided by the number of properties impacting the characteristic
                        characteristic_scores[impact] += utility * impact_weight  # The contribution of a property to a characteristic is its utility multiplied by the impact's weight

        # Print the characteristic scores
        for characteristic, score in characteristic_scores.items():
            if(score < 0.5):
                characteristics_table.add_row(characteristic, f"[red]{score}[/red]")
            else: # add green color to scores above 0.5
                characteristics_table.add_row(characteristic, f"[green]{score}[/green]")
        
        console.print(characteristics_table)
        
        print("\n")

        # Calculate the final score
        final_score = sum(characteristic_scores.values())/len(characteristic_scores)
        console.print(f"Security score: [bold blue]{final_score}[/bold blue]")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds() / 60.0  # in minutes

        write_results(final_score, duration, str(end_time), file_name, output_file)
        
        # Remove temporary files
        try:
            os.remove('bytecode.rt.hex')
        except OSError:
            pass 
        try:
            shutil.rmtree('./results')
        except OSError:
            pass  

    except sb.errors.SmartBugsError as e:
        console.print(f"[red]Something didn't work:[/red] {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate metrics from a contract file")
    parser.add_argument('file_name', type=str, help='The contract file name')
    parser.add_argument('output_file', type=str, help='The output file name')

    args = parser.parse_args()

    main(args.file_name, args.output_file)