import os
import csv
import random
import subprocess
import json
import time
from collections import Counter
import math

# 설정된 파일 경로
repo_dir = './DikeDataset/files/malware'
rules_path = '/home/onzl/capa/capa-rules'
yara_rules_path = '/home/onzl/yara-rules'  # YARA 룰 경로 추가
output_csv = './onzl_final_dataset.csv'

# 정의된 카테고리
att_tactics = [
    'Collection', 'Command and Control', 'Credential Access', 'Defense Evasion',
    'Discovery', 'Execution', 'Exfiltration', 'Impact', 'Impair Process Control',
    'Inhibit Response Function', 'Initial Access', 'Lateral Movement', 'Persistence',
    'Privilege Escalation'
]
malware_behavior = [
    'Anti-Behavioral Analysis', 'Anti-Static Analysis', 'Collection', 'Command and Control',
    'Communication', 'Cryptography', 'Data', 'Defense Evasion', 'Discovery', 'Excution', 'File System',
    'Hardware', 'Impact', 'Memory', 'Operating System', 'Persistence', 'Process'
]
namespaces = [
    'anti-analysis', 'collection', 'communication', 'compiler',
    'data-manipulation', 'doc', 'executable', 'host-interaction',
    'impact', 'internal', 'lib', 'linking', 'load-code',
    'malware-family', 'nursery', 'persistence', 'runtime', 'targeting'
]

top_apis = [
    'CreateFileW', 'ReadFile', 'WriteFile', 'GetProcAddress', 'LoadLibraryA',
    'VirtualAlloc', 'CreateProcessW', 'RegOpenKeyExW', 'InternetOpenA', 'WinExec'
]

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = -sum((count / data_len) * math.log2(count / data_len) for count in byte_counts.values())
        return entropy

def run_capa(binary_path, rules_path, output_log_file):
    try:
        capa_command = ["capa", binary_path, "-r", rules_path, "--signatures", rules_path, "-j"]
        start = time.time()
        result = subprocess.run(capa_command, capture_output=True, text=True, timeout=60)
        elapsed = time.time() - start
        if result.returncode != 0 or not result.stdout.strip():
            print(f"Error running capa: {binary_path}")
            return None, 0
        with open(output_log_file, 'w') as f:
            f.write(result.stdout)
        return output_log_file, elapsed
    except Exception as e:
        print(f"Error running capa: {e}")
        return None, 0

def run_yara(binary_path, yara_rules_path):
    try:
        yara_command = ["yara", "-r", yara_rules_path, binary_path]
        result = subprocess.run(yara_command, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()
        return []
    except Exception as e:
        print(f"YARA error on {binary_path}: {e}")
        return []

def extract_api_features(rule):
    apis = []
    if 'features' in rule:
        for k, v in rule['features'].items():
            if k == 'api' and isinstance(v, list):
                apis.extend([item for item in v if isinstance(item, str)])
            elif isinstance(v, list):
                for sub in v:
                    if isinstance(sub, dict) and 'api' in sub:
                        apis.append(sub['api'])
    return apis

def analyze_with_capa(binary_path, rules_path, yara_rules_path, csv_writer):
    try:
        parent_dir = os.path.dirname(os.path.dirname(binary_path))
        mal_csv_dir = os.path.join(parent_dir, "mal_csv")
        os.makedirs(mal_csv_dir, exist_ok=True)

        file_name = os.path.basename(binary_path)
        output_log_file = os.path.join(mal_csv_dir, f"{file_name}.json")
        log_file_path, elapsed = run_capa(binary_path, rules_path, output_log_file)
        if not log_file_path or not os.path.exists(log_file_path):
            return

        with open(log_file_path, 'r') as log_file:
            capa_result = json.load(log_file)

        entropy = calculate_entropy(binary_path)
        att_tactic_matches = {t: 0 for t in att_tactics}
        mbc_behavior_matches = {b: 0 for b in malware_behavior}
        namespace_matches = {ns: 0 for ns in namespaces}
        matched_rules = set()
        all_api_calls = []
        string_count = 0
        number_count = 0
        mnemonic_count = 0
        capability_num_matches = 0

        for rule_name, rule in capa_result.get('rules', {}).items():
            matched_rules.add(rule_name)
            if 'meta' in rule:
                meta = rule['meta']
                for attack in meta.get('attack', []):
                    tactic = attack.get('tactic')
                    if tactic in att_tactic_matches:
                        att_tactic_matches[tactic] += 1
                for mbc in meta.get('mbc', []):
                    objective = mbc.get('objective')
                    if objective in mbc_behavior_matches:
                        mbc_behavior_matches[objective] += 1
                ns = meta.get('namespace', '').split('/')[0]
                if ns in namespace_matches:
                    namespace_matches[ns] += 1
            all_api_calls.extend(extract_api_features(rule))
            string_count += len(rule.get('features', {}).get('string', []))
            number_count += len(rule.get('features', {}).get('number', []))
            mnemonic_count += len(rule.get('features', {}).get('mnemonic', []))
            capability_num_matches += len(rule.get('matches', []))

        yara_matched = run_yara(binary_path, yara_rules_path)

        row = {
            'file_name': file_name,
            'entropy': entropy,
            'analysis_time_sec': round(elapsed, 3),
            'capabilityNum_matches': capability_num_matches,
            'matched_rule_count': len(matched_rules),
            'string_count': string_count,
            'number_count': number_count,
            'mnemonic_count': mnemonic_count,
            'unique_api_calls': len(set(all_api_calls)),
            'yara_match_count': len(yara_matched),
            'malicious': 1 if capability_num_matches > 0 else 0
        }

        for api in top_apis:
            row[f'api_{api}'] = int(api in all_api_calls)
        for t in att_tactics:
            row[f'ATT_Tactic_{t}'] = att_tactic_matches[t]
        for b in malware_behavior:
            row[f'MBC_obj_{b}'] = mbc_behavior_matches[b]
        for ns in namespaces:
            row[f'namespace_{ns}'] = namespace_matches[ns]

        csv_writer.writerow(row)

    except Exception as e:
        print(f"Error analyzing {binary_path}: {e}")

def analyze_random_samples(repo_dir, rules_path, yara_rules_path, output_csv, num_samples=10):
    all_files = []
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith((".exe", ".bin", ".elf")):
                all_files.append(os.path.join(root, file))
    selected_files = all_files if len(all_files) <= num_samples else random.sample(all_files, num_samples)

    with open(output_csv, mode='w', newline='') as f:
        csv_columns = [
            'file_name', 'entropy', 'analysis_time_sec', 'capabilityNum_matches', 'matched_rule_count',
            'string_count', 'number_count', 'mnemonic_count', 'unique_api_calls', 'yara_match_count'
        ] + [f'api_{api}' for api in top_apis] + \
            [f'ATT_Tactic_{t}' for t in att_tactics] + \
            [f'MBC_obj_{b}' for b in malware_behavior] + \
            [f'namespace_{ns}' for ns in namespaces] + ['malicious']

        writer = csv.DictWriter(f, fieldnames=csv_columns)
        writer.writeheader()
        for file_path in selected_files:
            analyze_with_capa(file_path, rules_path, yara_rules_path, writer)

# 실행
if __name__ == "__main__":
    num = 2 # number of test files
    analyze_random_samples(repo_dir, rules_path, yara_rules_path, output_csv, num_samples=num)