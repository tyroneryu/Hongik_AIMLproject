import argparse
import os

def main():
    print("Hello from SageMaker Dummy Training Job!")

    # 결과 저장
    output_dir = os.environ.get('SM_MODEL_DIR', '/opt/ml/model')
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "dummy_model.txt"), "w") as f:
        f.write("This is a dummy model output.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--epochs', type=int, default=1)
    args = parser.parse_args()
    main()
