import boto3
import botocore
import os

def load_credentials(file_path="creds.txt"):
    creds = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    creds[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"❌ Credential file '{file_path}' not found!")
        exit(1)
    return creds

def init_base_session(creds):
    os.environ["AWS_ACCESS_KEY_ID"] = creds["AWS_ACCESS_KEY_ID"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = creds["AWS_SECRET_ACCESS_KEY"]
    os.environ["AWS_DEFAULT_REGION"] = creds.get("AWS_REGION", "us-east-1")
    return boto3.session.Session(
        aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        region_name=creds.get("AWS_REGION", "us-east-1")
    )

def assume_role_if_specified(base_session, creds):
    if "ASSUME_ROLE_ARN" not in creds or not creds["ASSUME_ROLE_ARN"].strip():
        print("ℹ️ No role ARN specified — using static credentials.")
        return base_session
    sts_client = base_session.client("sts")
    try:
        print(f"🔄 Attempting to assume role: {creds['ASSUME_ROLE_ARN']} ...")
        response = sts_client.assume_role(
            RoleArn=creds["ASSUME_ROLE_ARN"],
            RoleSessionName="secretReaderSession"
        )
        creds_sts = response["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=creds_sts["AccessKeyId"],
            aws_secret_access_key=creds_sts["SecretAccessKey"],
            aws_session_token=creds_sts["SessionToken"],
            region_name=creds.get("AWS_REGION", "us-east-1")
        )
        print("✅ Role assumed successfully.")
        return session
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print("\n❌ Could not assume role!")
        print("Error Code:", code)
        print("Reason:", msg)
        if code == "AccessDenied":
            print("⚠️ Your IAM user lacks 'sts:AssumeRole' permission for this role.")
            print("   Check the trust policy and your IAM permissions.")
        elif code == "NoSuchEntity":
            print("⚠️ The specified role ARN does not exist.")
        elif code == "MalformedPolicyDocument":
            print("⚠️ The role policy might be invalid.")
        else:
            print("⚠️ Unexpected error while assuming role.")
        print("↩️ Reverting to base session with static credentials.\n")
        return base_session

def list_secrets(client):
    try:
        print("\n🔍 Fetching secrets from AWS Secrets Manager...\n")
        paginator = client.get_paginator("list_secrets")
        secrets = []
        index = 1
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                print(f"{index}. {secret['Name']}")
                secrets.append(secret["Name"])
                index += 1
        if not secrets:
            print("ℹ️ No secrets found in this region.")
        return secrets
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print("\n❌ Could not list secrets!")
        print("Error Code:", code)
        print("Reason:", msg)
        if code == "AccessDeniedException":
            print("⚠️ Missing 'secretsmanager:ListSecrets' permission.")
        return []

def get_secret(client, secret_name):
    try:
        response = client.get_secret_value(SecretId=secret_name)
        print("\n✅ Secret Retrieved Successfully!\n")
        print("Secret Name:", secret_name)
        if "SecretString" in response:
            print("Secret Value:", response["SecretString"])
        else:
            print("Binary Secret (Base64 Encoded):", response["SecretBinary"])
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        print("\n❌ Could not retrieve secret!")
        print("Error Code:", code)
        print("Reason:", msg)
        if code == "AccessDeniedException":
            print("⚠️ Missing 'secretsmanager:GetSecretValue' or 'kms:Decrypt' permission.")
        elif code == "DecryptionFailure":
            print("⚠️ KMS decryption failed — check key policy or permissions.")
        elif code == "ResourceNotFoundException":
            print("⚠️ Secret not found — check name or region.")
        else:
            print("⚠️ Unexpected AWS error occurred.")

def main():
    creds = load_credentials("creds.txt")
    base_session = init_base_session(creds)
    session = assume_role_if_specified(base_session, creds)
    client = session.client("secretsmanager")
    secrets = list_secrets(client)
    if not secrets:
        return
    choice = input("\nEnter secret name or number to retrieve: ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(secrets):
            secret_name = secrets[idx]
        else:
            print("❌ Invalid selection.")
            return
    else:
        secret_name = choice
    get_secret(client, secret_name)

if __name__ == "__main__":
    main()
