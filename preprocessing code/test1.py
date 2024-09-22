import os
import csv
import random
import subprocess
import json
from collections import Counter
import math

# 설정된 파일 경로
repo_dir = './DikeDataset/files/malware'
rules_path = '/home/onzl/capa/capa-rules'
output_csv = './onzl_final_dataset.csv'

# ATT&CK Tactic, MBC Behavior, Namespace 정의
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
    'impact', 'internal/limitation/file', 'lib', 'linking', 'load-code',
    'malware-family/plugx', 'nursery', 'persistence', 'runtime/dotnet', 'targeting'
]

#print("Collection" in att_tactics)
#print(malware_behavior)
#print(namespaces)

# 엔트로피 계산 함수
def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        if not data:
            return 0
        byte_counts = Counter(data)
        data_len = len(data)
        entropy = 0
        for count in byte_counts.values():
            p_x = count / data_len
            entropy += -p_x * math.log2(p_x)
        return entropy

# capa-rule 실행 및 결과 JSON 파일로 저장 함수 (터미널 출력 포함)
def run_capa_and_save_log(binary_path, rules_path, output_log_file):
    try:
        # capa 명령어 준비 (JSON 형식으로 실행)
        capa_command = [
            "capa", binary_path, "-r", rules_path, "--signatures", rules_path, "-j"
        ]
        # capa 명령어 실행 (JSON 형식으로 결과 캡처)
        result = subprocess.run(capa_command, capture_output=True, text=True)

        # capa 실행 결과가 성공적이지 않으면 오류 처리
        if result.returncode != 0:
            print(f"Error running capa for {binary_path}: {result.stderr}")
            return None

        # capa 결과가 비어 있는지 확인 (비어 있을 경우 None 반환)
        if not result.stdout.strip():
            print(f"No output from capa for {binary_path}")
            return None

        # capa 결과를 JSON 파일로 저장
        with open(output_log_file, 'w') as log_file:
            log_file.write(result.stdout)
        
        print(f"Saved capa result to {output_log_file}")  # 디버깅 정보 추가

        return output_log_file
    
    except Exception as e:
        print(f"Error: {e}")
        return None

# 파일 분석 및 CSV 작성 함수
def analyze_with_capa(binary_path, rules_path, csv_writer):
    try:
        # 상위 디렉토리에 mal_csv 디렉토리 생성
        parent_dir = os.path.dirname(os.path.dirname(binary_path))  # binary_path에서 디렉토리 경로만 추출
        mal_csv_dir = os.path.join(parent_dir, "mal_csv")
        os.makedirs(mal_csv_dir, exist_ok=True)  # mal_csv 디렉토리 생성 (존재하지 않을 경우)

        # mal_csv 디렉토리에 JSON 파일 저장 경로 생성
        file_name = os.path.basename(binary_path)
        output_log_file = os.path.join(mal_csv_dir, f"{file_name}.json")

        # CAPA 결과를 JSON 로그 파일로 저장하고 터미널에 출력
        log_file_path = run_capa_and_save_log(binary_path, rules_path, output_log_file)

        if log_file_path is None:
            print(f"Failed to save or retrieve capa results for {binary_path}")
            return  # 분석 실패 시 반환

        # 로그 파일에서 capa 결과 읽기 (필요한 경우 추가 작업)
        if not os.path.exists(log_file_path):  # 파일 존재 여부 확인
            print(f"Log file {log_file_path} not found.")
            return

        with open(log_file_path, 'r') as log_file:
            file_content = log_file.read().strip()
            if not file_content:
                print(f"Log file {log_file_path} is empty or invalid.")
                return

            try:
                capa_result = json.loads(file_content)
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {log_file_path}: {e}")
                return

        # 엔트로피 계산
        entropy = calculate_entropy(binary_path)

        # capa 결과 분석
        att_tactic_matches = {tactic: 0 for tactic in att_tactics}
        mbc_behavior_matches = {behavior: 0 for behavior in malware_behavior}
        namespace_matches = {ns: 0 for ns in namespaces}

        capability_num_matches = 0  # 기능 매칭 횟수

        # capa 결과에서 ATT&CK Tactic, MBC Behavior, Namespace 매칭 카운트
        for rule in capa_result.get('rules', {}).values():
            # 'meta'가 rule 안에 있는지 확인
            if 'meta' in rule:
                meta = rule['meta']
                
                # ATT&CK Tactic 매칭
                if 'attack' in meta:
                    for attack in meta.get('attack', []):
                        # tactic과 technique을 각각 매칭
                        tactic_name = attack.get('tactic', 'N/A')
                        technique_name = attack.get('technique', 'N/A')

                        # tactic 매칭 체크
                        if tactic_name in att_tactics:
                            att_tactic_matches[tactic_name] = att_tactic_matches.get(tactic_name, 0) + 1
                            # print(f"Matched ATT&CK Tactic: {tactic_name}")

                # MBC Behavior 매칭
                if 'mbc' in meta:
                    for mbc in meta.get('mbc', []):
                        # objective와 behavior 매칭
                        objective_name = mbc.get('objective', 'N/A')
                        behavior_name = mbc.get('behavior', 'N/A')
                        # print(f"Matched MBC Objective: {objective_name}")

                        if objective_name in malware_behavior:
                            mbc_behavior_matches[objective_name] = mbc_behavior_matches.get(objective_name, 0) + 1
                            # print(f"Matched and incremented MBC Objective: {objective_name}")

                # Namespace 매칭 (슬래시(/) 앞의 string만 사용)
                if 'namespace' in meta:
                    namespace_full = meta.get('namespace', 'N/A')
                    namespace_prefix = namespace_full.split('/')[0]  # / 앞의 string만 추출
                    if namespace_prefix in namespaces:
                        namespace_matches[namespace_prefix] = namespace_matches.get(namespace_prefix, 0) + 1
                        # print(f"Matched Namespace: {namespace_prefix}")

            else:
                print(f"No 'meta' field found in rule: {rule}")

            # 기능 매칭 카운트
            matches = rule.get('matches', [])
            capability_num_matches += len(matches)

        # CSV 행 생성
        row = {
            'file_name': file_name,
            'entropy': entropy,
            'capabilityNum_matches': capability_num_matches
        }

        # 각 ATT&CK Tactic, MBC Behavior, Namespace에 대해 매칭 횟수를 기록
        for tactic in att_tactics:
            row[f'ATT_Tactic_{tactic}'] = att_tactic_matches[tactic]
        for behavior in malware_behavior:
            row[f'MBC_obj_{behavior}'] = mbc_behavior_matches[behavior]
        for ns in namespaces:
            row[f'namespace_{ns}'] = namespace_matches[ns]

        # 악성 여부 판정
        row['malicious'] = 1 if capability_num_matches > 0 else 0  # 1 : malware, 0 : benign

        # CSV에 행 추가
        csv_writer.writerow(row)

    except Exception as e:
        print(f"Error analyzing {binary_path}: {e}")

# 랜덤으로 파일을 분석하여 CSV에 기록
def analyze_random_samples(repo_dir, rules_path, output_csv, num_samples=10):
    all_files = []

    # 디렉토리에서 파일 수집
    for root, dirs, files in os.walk(repo_dir):
        for file_name in files:
            if file_name.endswith((".bin", ".exe", ".elf")):  # 바이너리 파일만 선택
                file_path = os.path.join(root, file_name)
                all_files.append(file_path)

    # 파일이 충분하지 않을 경우 경고
    if len(all_files) < num_samples:
        print(f"Warning: Only {len(all_files)} files found, analyzing all of them.")
        selected_files = all_files
    else:
        # 랜덤으로 num_samples 개의 파일 선택
        selected_files = random.sample(all_files, num_samples)

    # CSV 파일에 저장하기 위한 설정
    with open(output_csv, mode='w', newline='') as file:
        csv_columns = ['file_name', 'entropy', 'capabilityNum_matches'] + \
                      [f'ATT_Tactic_{tactic}' for tactic in att_tactics] + \
                      [f'MBC_obj_{behavior}' for behavior in malware_behavior] + \
                      [f'namespace_{ns}' for ns in namespaces] + ['malicious']

        writer = csv.DictWriter(file, fieldnames=csv_columns)
        writer.writeheader()

        # 선택된 각 파일을 분석하고 CSV에 기록
        for file_path in selected_files:
            analyze_with_capa(file_path, rules_path, writer)

# 실행 부분
if __name__ == "__main__":
    # 랜덤으로 파일을 분석하고 결과를 CSV 파일로 저장
    analyze_random_samples(repo_dir, rules_path, output_csv, num_samples=2)