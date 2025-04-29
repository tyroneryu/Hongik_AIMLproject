import boto3
import time
import os

# SageMaker client 생성
sagemaker = boto3.client('sagemaker', region_name='ap-southeast-2')

# Job 이름 (유니크해야 함)
job_name = f"aiml-dummy-training-{int(time.time())}"

response = sagemaker.create_training_job(
    TrainingJobName=job_name,
    AlgorithmSpecification={
        'TrainingImage': '382416733822.dkr.ecr.ap-southeast-2.amazonaws.com/xgboost:latest',  # 임시로 XGBoost 이미지 사용 (커스텀 변경 가능)
        'TrainingInputMode': 'File'
    },
    RoleArn='arn:aws:YOUR-AWS-ACCOUNT-ID:role/YOUR-SAGEMAKER-ROLE-NAME',  # 너의 SageMaker 역할 ARN
    InputDataConfig=[{
        'ChannelName': 'train',
        'DataSource': {
            'S3DataSource': {
                'S3DataType': 'S3Prefix',
                'S3Uri': 's3://aiml-project-artifact-taeyunryu/input/',
                'S3DataDistributionType': 'FullyReplicated'
            }
        }
    }],
    OutputDataConfig={
        'S3OutputPath': 's3://aiml-project-artifact-taeyunryu/outputs/'  # 결과 S3 경로
    },
    ResourceConfig={
        'InstanceType': 'ml.m5.large',
        'InstanceCount': 1,
        'VolumeSizeInGB': 10
    },
    StoppingCondition={
        'MaxRuntimeInSeconds': 600
    }
)

print(f"Triggered SageMaker Training Job: {job_name}")

os.makedirs("output", exist_ok=True)

