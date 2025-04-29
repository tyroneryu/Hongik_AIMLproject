import boto3
import botocore
import os

s3 = boto3.client('s3')
bucket_name = 'aiml-project-artifact-taeyunryu'

try:
    response = s3.list_objects_v2(Bucket=bucket_name)
    if 'Contents' not in response:
        print("No objects found in the bucket.")
    else:
        print("Objects found. Proceeding with training.")
except botocore.exceptions.ClientError as error:
    print(f"Error accessing S3 bucket: {error}")
    exit(1)  # 안전하게 실패 처리

os.makedirs('output', exist_ok=True)

with open('output/dummy_result.txt', 'w') as f:
    f.write('Dummy training result.\n')

print("Training done. Dummy output generated.")
