import os
import csv
import subprocess
import json
import time
import math
from collections import Counter
import pandas as pd

# 경로 설정
repo_dir = '/home/taeyun-ryu/Desktop/aimlp/dataset'
rules_path = '/home/taeyun-ryu/Desktop/aimlp/capa/rules'
output_dir = '/home/taeyun-ryu/Desktop/aimlp/output'
label_csv = '/home/taeyun-ryu/Desktop/aimlp/label.csv'
output_csv = os.path.join(output_dir, 'dataset.csv')
capa_main = '/home/taeyun-ryu/Desktop/aimlp/capa/capa/main.py'

# 전처리용 feature 리스트
att_tactics = [ 'Collection', 'Command and Control', 'Credential Access', 'Defense Evasion',
    'Discovery', 'Execution', 'Exfiltration', 'Impact', 'Impair Process Control',
    'Inhibit Response Function', 'Initial Access', 'Lateral Movement', 'Persistence', 'Privilege Escalation'
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

# 엔트로피 계산
def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        byte_counts = Counter(data)
        entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in byte_counts.values())
        return entropy

# capa 실행 함수
def run_capa(binary_path, rules_path, output_log_file):
    try:
        capa_command = [
            'python3', capa_main,
            '-j',
            '-r', rules_path,
            binary_path
        ]
        print(f"▶ Running capa: {' '.join(capa_command)}")
        start = time.time()
        result = subprocess.run(capa_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        elapsed = time.time() - start

        if result.returncode != 0:
            print(f"❌ capa error: {result.stderr}")
            return None, 0
        if not result.stdout.strip():
            print("❌ capa returned empty result.")
            return None, 0

        with open(output_log_file, 'w') as f:
            f.write(result.stdout)
        return output_log_file, elapsed

    except Exception as e:
        print(f"🔥 Exception in run_capa(): {e}")
        return None, 0

# capa 분석 및 feature 추출
def analyze_with_capa(binary_path, rules_path):
    try:
        file_name = os.path.basename(binary_path)
        csv_dir = os.path.join(output_dir, "csv")
        os.makedirs(csv_dir, exist_ok=True)
        output_log_file = os.path.join(csv_dir, f"{file_name}.json")

        log_path, elapsed = run_capa(binary_path, rules_path, output_log_file)
        if not log_path or not os.path.exists(log_path):
            return None

        with open(log_path, 'r') as f:
            capa_result = json.load(f)

        entropy = calculate_entropy(binary_path)
        att = {t: 0 for t in att_tactics}
        mbc = {b: 0 for b in malware_behavior}
        ns_match = {ns: 0 for ns in namespaces}
        all_api_calls = []
        rule_count = 0
        str_cnt = num_cnt = mnem_cnt = match_cnt = 0

        for rule_name, rule in capa_result.get("rules", {}).items():
            rule_count += 1
            meta = rule.get("meta", {})
            for a in meta.get("attack", []):
                if a.get("tactic") in att: att[a["tactic"]] += 1
            for m in meta.get("mbc", []):
                if m.get("objective") in mbc: mbc[m["objective"]] += 1
            ns = meta.get("namespace", "").split('/')[0]
            if ns in ns_match: ns_match[ns] += 1

            features = rule.get("features", {})
            all_api_calls.extend([a for a in features.get("api", []) if isinstance(a, str)])
            str_cnt += len(features.get("string", []))
            num_cnt += len(features.get("number", []))
            mnem_cnt += len(features.get("mnemonic", []))
            match_cnt += len(rule.get("matches", []))

        row = {
            'filename': file_name,
            'entropy': entropy,
            'analysis_time_sec': round(elapsed, 3),
            'capabilityNum_matches': match_cnt,
            'matched_rule_count': rule_count,
            'string_count': str_cnt,
            'number_count': num_cnt,
            'mnemonic_count': mnem_cnt,
            'unique_api_calls': len(set(all_api_calls))
        }
        for api in top_apis:
            row[f'api_{api}'] = int(api in all_api_calls)
        for t in att_tactics: row[f'ATT_Tactic_{t}'] = att[t]
        for b in malware_behavior: row[f'MBC_obj_{b}'] = mbc[b]
        for ns in namespaces: row[f'namespace_{ns}'] = ns_match[ns]

        return row

    except Exception as e:
        print(f"🔥 Error in analyze_with_capa(): {e}")
        return None

# 분석 및 CSV merge
def analyze_and_merge():
    df = pd.read_csv(label_csv)
    df.set_index('filename', inplace=True)
    file_list = []

    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.exe', '.bin', '.elf', '.vir')):
                file_list.append(os.path.join(root, file))

    for path in file_list:
        print(f"🔍 Processing: {path}")
        row = analyze_with_capa(path, rules_path)
        if row and row['filename'] in df.index:
            for k, v in row.items():
                if k != 'filename':
                    df.at[row['filename'], k] = v

    df.reset_index().to_csv(output_csv, index=False)
    print(f"✅ Saved final dataset to: {output_csv}")

# 실행
if __name__ == "__main__":
    analyze_and_merge()
