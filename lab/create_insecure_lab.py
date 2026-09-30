"""Creates deliberately misconfigured resources for before/after compliance audit demonstrations."""

import sys
import boto3
from botocore.exceptions import ClientError

LAB_PREFIX = "compliance-lab"


def setup_insecure_lab(profile_name: str = None, region: str = "us-east-1"):
    print(f"[*] Setting up insecure lab in region '{region}'...")
    session = boto3.Session(profile_name=profile_name, region_name=region)
    sts = session.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    print(f"[*] Connected to AWS Account: {account_id}")

    # 1. Deliberately insecure S3 bucket (Empty, public BPA off, no encryption, no versioning)
    s3 = session.client("s3")
    bucket_name = f"{LAB_PREFIX}-insecure-{account_id}"
    print(f"[*] Creating insecure S3 bucket: {bucket_name}")
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        # Explicitly turn off Block Public Access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        print("  ✓ S3 bucket created with Block Public Access OFF")
    except ClientError as e:
        print(f"  [-] S3 bucket error: {e}")

    # 2. Insecure EC2 Security Group (Port 22 SSH open to 0.0.0.0/0)
    ec2 = session.client("ec2")
    sg_name = f"{LAB_PREFIX}-insecure-sg"
    print(f"[*] Creating insecure security group: {sg_name}")
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}]).get("Vpcs", [])
        vpc_id = vpcs[0]["VpcId"] if vpcs else None

        sg_args = {"GroupName": sg_name, "Description": "Lab security group with open SSH for testing"}
        if vpc_id:
            sg_args["VpcId"] = vpc_id

        sg = ec2.create_security_group(**sg_args)
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpProtocol="tcp",
            FromPort=22,
            ToPort=22,
            CidrIp="0.0.0.0/0",
        )
        print(f"  ✓ Security group {sg_id} created with open SSH (22) from 0.0.0.0/0")
    except ClientError as e:
        print(f"  [-] Security group error: {e}")

    # 3. Insecure IAM User (Password with no MFA, active access key, direct policy)
    iam = session.client("iam")
    username = f"{LAB_PREFIX}-user"
    print(f"[*] Creating insecure IAM user: {username}")
    try:
        iam.create_user(UserName=username)
        # Create access key
        iam.create_access_key(UserName=username)
        # Attach direct inline policy
        iam.put_user_policy(
            UserName=username,
            PolicyName="DirectAttachedPolicy",
            PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]}',
        )
        print(f"  ✓ IAM user {username} created without MFA and with direct policy")
    except ClientError as e:
        print(f"  [-] IAM error: {e}")

    print("\n[+] Insecure lab resources created successfully!")
    print("Run `python -m scanner scan` to produce the 'before' audit findings.")


if __name__ == "__main__":
    profile = sys.argv[1] if len(sys.argv) > 1 else None
    setup_insecure_lab(profile_name=profile)
