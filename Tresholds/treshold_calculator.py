import csv
import os
import json
import yaml
from collections import defaultdict
from pprint import pprint
import numpy as np
from scipy.stats import iqr
import yaml
import csv

# path to metrics_and_findings.csv
metrics_and_findings_path = "./metrics_and_findings.csv" #TODO: change to metrics and findings path
mappings_dir = '../Mappings'  # directory of mappings files


def load_mappings(mappings_dir):
    mappings = {}
    for file in os.listdir(mappings_dir):
        if file.endswith('.yaml'):
            with open(os.path.join(mappings_dir, file), 'r') as f:
                tool_mappings = yaml.safe_load(f)
                for vulnerability, data in tool_mappings.items():
                    if 'classification' in data:
                        mappings[vulnerability] = data['classification'].split(",")[
                            0]
    return mappings


def load_taxonomy():
    with open('../Utils/taxonomy.yaml', 'r') as file:
        taxonomy_data = yaml.safe_load(file)
    return taxonomy_data['taxonomy']


def create_swc_to_property_mapping(taxonomy):
    swc_to_property = {}
    for group in taxonomy:
        for vuln in group['vulnerabilities']:
            if 'swc' in vuln:
                swc_to_property[f"SWC-{vuln['swc']}"] = vuln['property']
    return swc_to_property


def load_metrics_and_findings(metrics_and_findings_path):
    with open(metrics_and_findings_path, 'r') as file:
        reader = csv.DictReader(file)
        metrics_and_findings = {row['ContractAddress']: row for row in reader}
    return metrics_and_findings


def calculate_M(total_metric, total_lloc):
    return total_metric / total_lloc if total_lloc != 0 else 0


def calculate_savd_and_group_by_property(swc_counts, total_lloc, swc_to_property):
    swc_savd = {swc_code: (count / total_lloc) *
                1000 for swc_code, count in swc_counts.items() if total_lloc != 0}
    property_counts = defaultdict(int)
    property_savd = defaultdict(float)
    for swc_code, count in swc_counts.items():
        property = swc_to_property.get(swc_code, 'Unknown')
        property_counts[property] += count
        property_savd[property] += swc_savd.get(swc_code, 0)
    return property_counts, property_savd


def calculate_property_utility(s, t_l, t_m, t_u):
    if s <= t_l:
        return 1
    elif t_l <= s <= t_m:
        return 0.5 / (t_l - t_m) * (s + t_l - 2 * t_m)
    elif t_m <= s <= t_u:
        return 0.5 ** 2 / (t_m - t_u) * (s - t_u)
    elif s >= t_u:
        return 0


def calculate_thresholds(s_values):
    t_l = min(s for s in s_values if s >= np.percentile(
        s_values, 25) - 1.5 * iqr(s_values))
    t_m = np.median(s_values)
    t_u = max(s for s in s_values if s <= np.percentile(
        s_values, 75) + 1.5 * iqr(s_values))
    return t_l, t_m, t_u


def process_files(metrics_and_findings, swc_to_property):
    property_scores = defaultdict(list)
    abbrev_to_fullname = {"WMC": "Weighted Methods per Class",
                          "CBO": "Coupling Between Object classes"}
    contract_count = 0

    for contract_address, data in metrics_and_findings.items():
        contract_count += 1
        total_lloc = int(data['LLOC'])
        total_cbo = int(data['CBO'])
        total_wmc = int(data['WMC'])
        swc_counts = {k: int(v)
                      for k, v in data.items() if k.startswith('SWC-')}

        average_cbo = calculate_M(total_cbo, total_lloc)
        average_wmc = calculate_M(total_wmc, total_lloc)

        property_counts, property_savd = calculate_savd_and_group_by_property(
            swc_counts, total_lloc, swc_to_property)

        property_scores['CBO'].append(average_cbo)
        property_scores['WMC'].append(average_wmc)
        for prop, value in property_savd.items():
            if prop != 'Unknown':
                property_scores[prop].append(value)

    # Calculate thresholds for each property
    thresholds = {}
    for prop, values in property_scores.items():
        t_l, t_m, t_u = calculate_thresholds(values)
        thresholds[prop] = (t_l, t_m, t_u)

    # Write thresholds to CSV file
    with open('thresholds.csv', 'w', newline='') as csvfile:
        fieldnames = ['Property', 'Threshold_Lower',
                      'Threshold_Middle', 'Threshold_Upper']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        # Handle the rest of the properties
        for prop, (t_l, t_m, t_u) in thresholds.items():
            prop_full_name = abbrev_to_fullname.get(
                prop, prop)  # map abbreviation to full name
            writer.writerow({'Property': prop_full_name, 'Threshold_Lower': t_l,
                            'Threshold_Middle': t_m, 'Threshold_Upper': t_u})


mappings = load_mappings(mappings_dir)
taxonomy = load_taxonomy()
swc_to_property = create_swc_to_property_mapping(taxonomy)
metrics_and_findings = load_metrics_and_findings(metrics_and_findings_path)
process_files(metrics_and_findings, swc_to_property)
