import os
import csv
import subprocess
import json
import time
import math
from collections import Counter
import pandas as pd

# ===== 경로 설정 =====
repo_dir = '/home/taeyun-ryu/Desktop/aimlp/dataset'
rules_path = '/home/taeyun-ryu/Desktop/aimlp/capa/rules'
output_csv = '/home/taeyun-ryu/Desktop/aimlp/output/dataset.csv'
label_csv = '/home/taeyun-ryu/Desktop/aimlp/label.csv'
capa_script_path = '/home/taeyun-ryu/Desktop/aimlp/capa/capa/main.py'

# ===== 주요 피처 =====
att_tactics = ['Collection', 'Command and Control', 'Credential Access', 'Defense Evasion',
               'Discovery', 'Execution', 'Exfiltration', 'Impact', 'Impair Process Control',
               'Inhibit Response Function', 'Initial Access', 'Lateral Movement', 'Persistence',
               'Privilege Escalation']

malware_behavior = ['Anti-Behavioral Analysis', 'Anti-Static Analysis', 'Collection', 'Command and Control',
                    'Communication', 'Cryptography', 'Data', 'Defense Evasion', 'Discovery', 'Excution',
                    'File System', 'Hardware', 'Impact', 'Memory', 'Operating System', 'Persistence', 'Process']

namespaces = ['anti-analysis', 'collection', 'communication', 'compiler', 'data-manipulation', 'doc',
              'executable', 'host-interaction', 'impact', 'internal', 'lib', 'linking', 'load-code',
              'malware-family', 'nursery', 'persistence', 'runtime', 'targeting']

top_apis = ['CreateFileW', 'ReadFile', 'WriteFile', 'GetProcAddress', 'LoadLibraryA',
            'VirtualAlloc', 'CreateProcessW', 'RegOpenKeyExW', 'InternetOpenA', 'WinExec']

# ===== 엔트로피 계산 =====
def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = -sum((count / data_len) * math.log2(count / data_len) for count in byte_counts.values())
        return entropy

# ===== capa 실행 =====
def run_capa(binary_path, rules_path, output_log_file):
    try:
        capa_command = [
            'python3', capa_script_path, binary_path,
            '-r', rules_path, '--signatures', rules_path, '--json'
        ]
        start = time.time()
        result = subprocess.run(capa_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        elapsed = time.time() - start

        if result.stderr:
            print(f"[stderr] {result.stderr}")
        if result.returncode != 0:
            print(f"[capa error] return code {result.returncode}")
            return None, 0

        if not result.stdout.strip():
            print(f"[warning] capa returned empty output for {binary_path}")
            return None, 0

        with open(output_log_file, 'w') as f:
            f.write(result.stdout)
        return output_log_file, elapsed

    except Exception as e:
        print(f"E: Error running capa: {e}")
        return None, 0

# ===== capa 결과 분석 =====
def analyze_with_capa(binary_path, rules_path):
    try:
        file_name = os.path.basename(binary_path)
        csv_dir = os.path.join(repo_dir, "csv")
        os.makedirs(csv_dir, exist_ok=True)
        output_log_file = os.path.join(csv_dir, f"{file_name}.json")

        log_file_path, elapsed = run_capa(binary_path, rules_path, output_log_file)
        if not log_file_path or not os.path.exists(log_file_path):
            return None

        with open(log_file_path, 'r') as log_file:
            capa_result = json.load(log_file)

        entropy = calculate_entropy(binary_path)
        att_tactic_matches = {t: 0 for t in att_tactics}
        mbc_behavior_matches = {b: 0 for b in malware_behavior}
        namespace_matches = {ns: 0 for ns in namespaces}
        matched_rules = set()
        string_count = 0
        number_count = 0
        mnemonic_count = 0
        all_api_calls = []
        capability_num_matches = 0

        for rule_name, rule in capa_result.get('rules', {}).items():
            matched_rules.add(rule_name)
            meta = rule.get('meta', {})
            for attack in meta.get('attack', []):
                if attack.get('tactic') in att_tactic_matches:
                    att_tactic_matches[attack['tactic']] += 1
            for mbc in meta.get('mbc', []):
                if mbc.get('objective') in mbc_behavior_matches:
                    mbc_behavior_matches[mbc['objective']] += 1
            ns = meta.get('namespace', '').split('/')[0]
            if ns in namespace_matches:
                namespace_matches[ns] += 1

            features = rule.get('features', {})
            all_api_calls.extend([item for item in features.get('api', []) if isinstance(item, str)])
            string_count += len(features.get('string', []))
            number_count += len(features.get('number', []))
            mnemonic_count += len(features.get('mnemonic', []))
            capability_num_matches += len(rule.get('matches', []))

        row = {
            'filename': file_name,
            'entropy': entropy,
            'analysis_time_sec': round(elapsed, 3),
            'capabilityNum_matches': capability_num_matches,
            'matched_rule_count': len(matched_rules),
            'string_count': string_count,
            'number_count': number_count,
            'mnemonic_count': mnemonic_count,
            'unique_api_calls': len(set(all_api_calls))
        }

        for api in top_apis:
            row[f'api_{api}'] = int(api in all_api_calls)
        for t in att_tactics:
            row[f'ATT_Tactic_{t}'] = att_tactic_matches[t]
        for b in malware_behavior:
            row[f'MBC_obj_{b}'] = mbc_behavior_matches[b]
        for ns in namespaces:
            row[f'namespace_{ns}'] = namespace_matches[ns]

        return row

    except Exception as e:
        print(f"Error analyzing {binary_path}: {e}")
        return None

# ===== 전체 실행 =====
def analyze_and_merge():
    df = pd.read_csv(label_csv)
    df.set_index('filename', inplace=True)

    all_files = []
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.exe', '.bin', '.elf', '.vir')):
                all_files.append(os.path.join(root, file))

    for file_path in all_files:
        row = analyze_with_capa(file_path, rules_path)
        if row and row['filename'] in df.index:
            for key, value in row.items():
                if key != 'filename':
                    df.at[row['filename'], key] = value

    df.reset_index().to_csv(output_csv, index=False)
    print(f"✅ Saved final dataset to: {output_csv}")

# ===== main 실행 =====
if __name__ == "__main__":
    analyze_and_merge()
