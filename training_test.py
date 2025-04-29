import boto3
import time
import os

# SageMaker 세션 및 클라이언트 생성
sagemaker_client = boto3.client('sagemaker', region_name='ap-southeast-2')

# 설정
job_name = "aiml-training-job-" + str(int(time.time()))
role_arn = "arn:aws:iam::937319036547:role/aiml-sagemaker-execution-role"
input_s3_uri = "s3://aiml-project-artifact-taeyunryu/input/"
output_s3_uri = "s3://aiml-project-artifact-taeyunryu/output/"

# Training Job 생성
response = sagemaker_client.create_training_job(
    TrainingJobName=job_name,
    AlgorithmSpecification={
        'TrainingImage': '382416733822.dkr.ecr.ap-southeast-2.amazonaws.com/linear-learner:1',  # AWS 제공 기본 알고리즘
        'TrainingInputMode': 'File'
    },
    RoleArn=role_arn,
    InputDataConfig=[
        {
            'ChannelName': 'train',
            'DataSource': {
                'S3DataSource': {
                    'S3DataType': 'S3Prefix',
                    'S3Uri': input_s3_uri,
                    'S3DataDistributionType': 'FullyReplicated',
                }
            },
            'ContentType': 'text/csv',
        }
    ],
    OutputDataConfig={
        'S3OutputPath': output_s3_uri
    },
    ResourceConfig={
        'InstanceType': 'ml.m5.large',
        'InstanceCount': 1,
        'VolumeSizeInGB': 10,
    },
    StoppingCondition={
        'MaxRuntimeInSeconds': 3600
    }
)

print(f"Training job {job_name} submitted successfully!")
os.makedirs("output", exist_ok=True)
