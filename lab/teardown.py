"""Tears down all lab resources created by create_insecure_lab.py."""

import sys
import boto3
from botocore.exceptions import ClientError

LAB_PREFIX = "compliance-lab"


def teardown_lab(profile_name: str = None, region: str = "us-east-1"):
    print(f"[*] Starting teardown of lab resources in '{region}'...")
    session = boto3.Session(profile_name=profile_name, region_name=region)
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # 1. Teardown IAM User
    iam = session.client("iam")
    username = f"{LAB_PREFIX}-user"
    print(f"[*] Removing IAM user: {username}")
    try:
        # Delete inline policies
        policies = iam.list_user_policies(UserName=username).get("PolicyNames", [])
        for p in policies:
            iam.delete_user_policy(UserName=username, PolicyName=p)
        # Delete access keys
        keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
        for k in keys:
            iam.delete_access_key(UserName=username, AccessKeyId=k["AccessKeyId"])
        # Delete user
        iam.delete_user(UserName=username)
        print("  ✓ IAM user deleted")
    except ClientError as e:
        print(f"  [-] IAM cleanup notice: {e}")

    # 2. Teardown S3 Bucket
    s3 = session.client("s3")
    bucket_name = f"{LAB_PREFIX}-insecure-{account_id}"
    print(f"[*] Removing S3 bucket: {bucket_name}")
    try:
        s3.delete_bucket(Bucket=bucket_name)
        print("  ✓ S3 bucket deleted")
    except ClientError as e:
        print(f"  [-] S3 cleanup notice: {e}")

    # 3. Teardown Security Group
    ec2 = session.client("ec2")
    sg_name = f"{LAB_PREFIX}-insecure-sg"
    print(f"[*] Removing Security Group: {sg_name}")
    try:
        sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [sg_name]}]).get("SecurityGroups", [])
        for sg in sgs:
            ec2.delete_security_group(GroupId=sg["GroupId"])
            print(f"  ✓ Security Group {sg['GroupId']} deleted")
    except ClientError as e:
        print(f"  [-] Security Group cleanup notice: {e}")

    print("\n[+] Lab teardown completed successfully!")


if __name__ == "__main__":
    profile = sys.argv[1] if len(sys.argv) > 1 else None
    teardown_lab(profile_name=profile)
