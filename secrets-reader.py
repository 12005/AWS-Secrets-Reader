#!/usr/bin/env python3
import boto3
import getpass
import jwt  # pip install PyJWT
from botocore.exceptions import ClientError

# ---------- CONFIGURATION ----------
REGION = "ap-south-1"
USER_POOL_ID = "ap-south-1_"
CLIENT_ID = ""
IDENTITY_POOL_ID = "ap-south-1:"
# ---------- END CONFIG ----------


def prompt_credentials():
    print("\n🔐 AWS Cognito Authentication")
    username = input("Enter your Cognito username: ").strip()
    password = getpass.getpass("Enter your password: ")
    return username, password


def cognito_authenticate(username, password):
    """Authenticate user via Cognito User Pool"""
    client = boto3.client("cognito-idp", region_name=REGION)
    try:
        resp = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
            ClientId=CLIENT_ID,
        )
        print("✅ Cognito authentication successful.")
        return resp["AuthenticationResult"]
    except ClientError as e:
        print(f"❌ Authentication failed: {e.response['Error']['Message']}")
        return None


def decode_token(id_token):
    """Decode JWT token locally (no signature verification)"""
    decoded = jwt.decode(id_token, options={"verify_signature": False})
    return decoded


def get_temp_creds(id_token):
    """Exchange Cognito IdToken for temporary AWS credentials"""
    cognito_identity = boto3.client("cognito-identity", region_name=REGION)
    identity = cognito_identity.get_id(
        IdentityPoolId=IDENTITY_POOL_ID,
        Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
    )
    creds = cognito_identity.get_credentials_for_identity(
        IdentityId=identity["IdentityId"],
        Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
    )["Credentials"]

    print("✅ Temporary AWS credentials obtained (IAM role applied via role mapping).")
    return creds


def make_sm_client(creds):
    """Create a Secrets Manager client using temporary credentials"""
    return boto3.client(
        "secretsmanager",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
    )


# --- Secrets Manager Operations --- #
def create_secret(sm_client, username):
    name = input("Enter a name for your secret (e.g. 'db-pass'): ").strip()
    if "/" in name:
        print("Do not include '/' — it will be prefixed automatically.")
        return
    value = getpass.getpass("Enter your secret value: ")

    full_name = f"{username}/{name}"
    try:
        resp = sm_client.create_secret(Name=full_name, SecretString=value)
        print(f"✅ Secret created: {resp['ARN']}")
    except ClientError as e:
        print(f"❌ Could not create secret: {e.response['Error']['Message']}")


def list_my_secrets(sm_client, username):
    print("\n📜 Your Secrets:\n")
    try:
        paginator = sm_client.get_paginator("list_secrets")
        found = False
        for page in paginator.paginate():
            for s in page.get("SecretList", []):
                name = s.get("Name", "")
                if name.startswith(f"{username}/"):
                    print("-", name)
                    found = True
        if not found:
            print("(no secrets found for your account)")
    except ClientError as e:
        print(f"❌ Error listing secrets: {e.response['Error']['Message']}")


def view_secret(sm_client, username):
    secret_name = input("Enter the full secret name to retrieve: ").strip()
    if not secret_name.startswith(f"{username}/"):
        print("❌ You can only view secrets that belong to your user prefix.")
        return
    try:
        resp = sm_client.get_secret_value(SecretId=secret_name)
        print(f"\n🔓 Secret value:\n{resp.get('SecretString')}")
    except ClientError as e:
        print(f"❌ Error retrieving secret: {e.response['Error']['Message']}")


# --- Main --- #
def main():
    print("=== AWS Secrets Manager (Per-User IAM Roles) ===")
    username, password = prompt_credentials()
    auth = cognito_authenticate(username, password)
    if not auth:
        return

    id_token = auth["IdToken"]
    decoded = decode_token(id_token)
    username = decoded.get("cognito:username") or decoded.get("username") or "unknown"

    print(f"👤 Logged in as: {username}")

    creds = get_temp_creds(id_token)
    sm_client = make_sm_client(creds)

    while True:
        print("\nSelect an action:")
        print("1) Create a new secret")
        print("2) List my secrets")
        print("3) View a secret value")
        print("4) Exit")
        choice = input("Enter choice: ").strip()
        if choice == "1":
            create_secret(sm_client, username)
        elif choice == "2":
            list_my_secrets(sm_client, username)
        elif choice == "3":
            view_secret(sm_client, username)
        elif choice == "4":
            print("👋 Exiting...")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user.")
