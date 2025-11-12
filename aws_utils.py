import boto3
import botocore
import base64
import json
import hmac
import hashlib

# -------------------- CONFIGURATION --------------------
REGION = "ap-south-1"
USER_POOL_ID =
CLIENT_ID = 
CLIENT_SECRET = 
IDENTITY_POOL_ID =  

# -------------------- COGNITO AUTH --------------------
def get_secret_hash(username: str) -> str:
    """Generate Cognito client secret hash."""
    msg = username + CLIENT_ID
    dig = hmac.new(CLIENT_SECRET.encode(), msg.encode(), hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


def authenticate_user(username: str, password: str):
    """Authenticate a user against Cognito User Pool and return ID token."""
    client = boto3.client("cognito-idp", region_name=REGION)
    try:
        resp = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": get_secret_hash(username),
            },
            ClientId=CLIENT_ID,
        )
        return resp["AuthenticationResult"]["IdToken"], username
    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        raise Exception(f"Authentication failed: {code} - {msg}")


def get_temporary_credentials(id_token: str):
    """Exchange Cognito ID token for temporary AWS credentials via Identity Pool."""
    client = boto3.client("cognito-identity", region_name=REGION)
    try:
        identity = client.get_id(
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
        )["IdentityId"]

        creds = client.get_credentials_for_identity(
            IdentityId=identity,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token},
        )["Credentials"]

        return creds
    except botocore.exceptions.ClientError as e:
        raise Exception(f"Failed to get temporary credentials: {e.response['Error']['Message']}")


def init_client(creds: dict, service: str):
    """Initialize AWS client using temporary credentials."""
    return boto3.client(
        service,
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"],
    )

# -------------------- KMS UTILS --------------------
def list_kms_keys(kms_client, usage_filter=None):
    """List all KMS keys with human-readable alias names."""
    keys = []
    paginator = kms_client.get_paginator("list_keys")

    for page in paginator.paginate():
        for key in page["Keys"]:
            meta = kms_client.describe_key(KeyId=key["KeyId"])["KeyMetadata"]

            if meta["KeyState"] != "Enabled":
                continue
            if usage_filter and meta["KeyUsage"] != usage_filter:
                continue

            # Find a friendly alias name if exists
            alias_name = None
            alias_list = kms_client.list_aliases(KeyId=meta["KeyId"]).get("Aliases", [])
            for alias in alias_list:
                if alias.get("AliasName") and not alias["AliasName"].startswith("alias/aws/"):
                    alias_name = alias["AliasName"]
                    break

            keys.append({
                "KeyId": meta["KeyId"],
                "AliasName": alias_name or f"(no alias) {meta['KeyId'][:8]}",
                "Description": meta.get("Description", "No description"),
                "KeySpec": meta["KeySpec"],
                "KeyUsage": meta["KeyUsage"]
            })
    return keys

def kms_encrypt(kms_client, key_id: str, plaintext: str):
    """Encrypt data using symmetric or RSA KMS key."""
    desc = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    algo = "RSAES_OAEP_SHA_256" if "RSA" in desc["KeySpec"] else None

    if desc["KeySpec"] == "SYMMETRIC_DEFAULT":
        resp = kms_client.encrypt(KeyId=key_id, Plaintext=plaintext.encode("utf-8"))
    else:
        resp = kms_client.encrypt(KeyId=key_id, Plaintext=plaintext.encode("utf-8"), EncryptionAlgorithm=algo)

    return base64.b64encode(resp["CiphertextBlob"]).decode("utf-8")


def kms_decrypt(kms_client, key_id: str, ciphertext_b64: str):
    """Decrypt data using symmetric or RSA KMS key."""
    blob = base64.b64decode(ciphertext_b64)
    desc = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    algo = "RSAES_OAEP_SHA_256" if "RSA" in desc["KeySpec"] else None

    if desc["KeySpec"] == "SYMMETRIC_DEFAULT":
        resp = kms_client.decrypt(CiphertextBlob=blob, KeyId=key_id)
    else:
        resp = kms_client.decrypt(CiphertextBlob=blob, KeyId=key_id, EncryptionAlgorithm=algo)

    return resp["Plaintext"].decode("utf-8")


def kms_sign_message(kms_client, key_id: str, message: str):
    """Sign message with RSA/ECC KMS key."""
    desc = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    algo = "RSASSA_PSS_SHA_256" if "RSA" in desc["KeySpec"] else "ECDSA_SHA_256"
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    resp = kms_client.sign(KeyId=key_id, Message=digest, MessageType="DIGEST", SigningAlgorithm=algo)
    return base64.b64encode(resp["Signature"]).decode("utf-8")


def kms_verify_signature(kms_client, key_id: str, message: str, signature_b64: str):
    """Verify message signature with KMS."""
    desc = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
    algo = "RSASSA_PSS_SHA_256" if "RSA" in desc["KeySpec"] else "ECDSA_SHA_256"
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    resp = kms_client.verify(
        KeyId=key_id,
        Message=digest,
        Signature=base64.b64decode(signature_b64),
        MessageType="DIGEST",
        SigningAlgorithm=algo,
    )
    return bool(resp.get("SignatureValid", False))
