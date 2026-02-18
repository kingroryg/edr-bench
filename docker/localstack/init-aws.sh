#!/bin/bash
# init-aws.sh - Initialize AWS resources in LocalStack for edr-bench cloud scenarios.
# This script runs automatically when LocalStack is ready.

set -euo pipefail

echo "[init-aws] Creating S3 bucket: test-bucket"
awslocal s3 mb s3://test-bucket

echo "[init-aws] Creating IAM user: test-user"
awslocal iam create-user --user-name test-user
awslocal iam create-access-key --user-name test-user

echo "[init-aws] Creating Lambda function placeholder"
# Create a minimal Lambda function with a dummy zip
mkdir -p /tmp/lambda-init
cat > /tmp/lambda-init/index.py <<'PYEOF'
def handler(event, context):
    return {"statusCode": 200, "body": "ok"}
PYEOF
cd /tmp/lambda-init && zip -q function.zip index.py

awslocal lambda create-function \
    --function-name test-function \
    --runtime python3.11 \
    --handler index.handler \
    --zip-file fileb:///tmp/lambda-init/function.zip \
    --role arn:aws:iam::000000000000:role/lambda-role

echo "[init-aws] Creating CloudTrail trail"
awslocal s3 mb s3://cloudtrail-logs
awslocal cloudtrail create-trail \
    --name test-trail \
    --s3-bucket-name cloudtrail-logs
awslocal cloudtrail start-logging --name test-trail

echo "[init-aws] AWS resource initialization complete."
