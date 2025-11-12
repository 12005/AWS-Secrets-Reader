from flask import Flask, render_template, request, redirect, url_for, session, flash
from aws_utils import (
    authenticate_user,
    get_temporary_credentials,
    init_client,
    list_kms_keys,
    kms_encrypt,
    kms_decrypt,
    kms_sign_message,
    kms_verify_signature,
)
import json

# -------------------- FLASK CONFIG --------------------
app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"  # ⚠️ Change this in production
account_id = "991046440595"  # your AWS Account ID

# -------------------- KMS POLICY --------------------
key_policy = {
    "Version": "2012-10-17",
    "Id": "key-policy-secrets-manager-access",
    "Statement": [
        {
            "Sid": "EnableRootAndAdminFullAccess",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    f"arn:aws:iam::{account_id}:role/SecretsAdminRole",
                    f"arn:aws:iam::{account_id}:root"
                ]
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "AllowSecretsManagerToUseKey",
            "Effect": "Allow",
            "Principal": {"Service": "secretsmanager.amazonaws.com"},
            "Action": [
                "kms:GenerateDataKey",
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "AllowAllProjectRolesToUseKey",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    f"arn:aws:iam::{account_id}:role/SecretsAdminRole",
                    f"arn:aws:iam::{account_id}:role/SecretsRole",
                    f"arn:aws:iam::{account_id}:role/EncryptRole",
                    f"arn:aws:iam::{account_id}:role/SignRole",
                    f"arn:aws:iam::{account_id}:role/SecretsUserRole"
                ]
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "kms:DescribeKey",
                "kms:ReEncrypt*",
                "kms:Sign",
                "kms:Verify"
            ],
            "Resource": "*"
        }
    ]
}

# -------------------- HOME --------------------
@app.route("/")
def home():
    """Redirect user based on their assigned role."""
    if "id_token" not in session:
        return redirect(url_for("login"))

    role = session.get("role")
    if role in ["Admin", "Secrets"]:
        return redirect(url_for("secrets_manager"))
    elif role == "Encrypt":
        return redirect(url_for("encrypt_decrypt"))
    elif role == "Sign":
        return redirect(url_for("sign_verify"))
    else:
        flash("⚠️ Unknown or unauthorized role.", "danger")
        return redirect(url_for("login"))

# -------------------- LOGIN --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticate using AWS Cognito and map IAM role."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        try:
            id_token, username = authenticate_user(username, password)
            session["id_token"] = id_token
            session["username"] = username

            creds = get_temporary_credentials(id_token)
            sts_client = init_client(creds, "sts")
            identity = sts_client.get_caller_identity()
            arn = identity["Arn"]

            # --- Determine user role based on IAM role name ---
            if "SecretsAdminRole" in arn:
                session["role"] = "Admin"
            elif "SecretsRole" in arn:
                session["role"] = "Secrets"
            elif "EncryptRole" in arn:
                session["role"] = "Encrypt"
            elif "SignRole" in arn:
                session["role"] = "Sign"
            else:
                session["role"] = "User"

            flash(f"✅ Logged in as {session['role']}!", "success")
            return redirect(url_for("home"))

        except Exception as e:
            flash(f"⚠️ Login failed: {e}", "danger")

    return render_template("login.html")

# -------------------- SECRETS MANAGER --------------------
@app.route("/secrets-manager", methods=["GET", "POST"])
def secrets_manager():
    """List, view, create, and delete AWS Secrets."""
    if "id_token" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "User")
    if role not in ["Admin", "Secrets"]:
        flash("🚫 You do not have permission to access Secrets Manager.", "danger")
        return redirect(url_for("home"))

    creds = get_temporary_credentials(session["id_token"])
    secrets_client = init_client(creds, "secretsmanager")

    secrets_list, result = [], None
    try:
        paginator = secrets_client.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                desc = secrets_client.describe_secret(SecretId=secret["ARN"])
                tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
                if role == "Admin" or tags.get("AccessLevel", "").lower() == "user":
                    secrets_list.append({
                        "Name": secret["Name"],
                        "AccessLevel": tags.get("AccessLevel", "Unknown")
                    })
    except Exception as e:
        flash(f"Error listing secrets: {e}", "danger")

    if request.method == "POST":
        action = request.form.get("action")

        if action == "view":
            name = request.form.get("secret_name")
            try:
                resp = secrets_client.get_secret_value(SecretId=name)
                result = resp.get("SecretString", "<Binary Secret>")
                flash(f"✅ Secret '{name}' fetched successfully.", "success")
            except Exception as e:
                flash(f"Error fetching secret: {e}", "danger")

        elif action == "create":
            name = request.form.get("name")
            value = request.form.get("value")
            level = request.form.get("access_level", "User")
            if role == "User":
                level = "User"
            try:
                secrets_client.create_secret(
                    Name=name,
                    SecretString=value,
                    Tags=[{"Key": "AccessLevel", "Value": level}]
                )
                flash(f"✅ Secret '{name}' created successfully.", "success")
                return redirect(url_for("secrets_manager"))
            except Exception as e:
                flash(f"Error creating secret: {e}", "danger")

        elif action == "delete" and role == "Admin":
            name = request.form.get("secret_name")
            try:
                secrets_client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
                flash(f"🗑 Secret '{name}' deleted.", "success")
                return redirect(url_for("secrets_manager"))
            except Exception as e:
                flash(f"Error deleting secret: {e}", "danger")

    return render_template("secrets_manager.html", secrets=secrets_list, result=result, role=role)

# -------------------- ENCRYPT / DECRYPT --------------------
@app.route("/encrypt-decrypt", methods=["GET", "POST"])
def encrypt_decrypt():
    """Encrypt and decrypt data using KMS keys."""
    if "id_token" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "User")
    if role not in ["Admin", "Encrypt"]:
        flash("🚫 You do not have permission to access Encrypt/Decrypt.", "danger")
        return redirect(url_for("home"))

    creds = get_temporary_credentials(session["id_token"])
    kms_client = init_client(creds, "kms")
    result = None

    try:
        keys = list_kms_keys(kms_client, usage_filter="ENCRYPT_DECRYPT")
    except Exception as e:
        flash(f"Error loading KMS keys: {e}", "danger")
        keys = []

    if request.method == "POST":
        action = request.form.get("action")

        # --- Create Key (Admin only) ---
        if action == "create_key" and role == "Admin":
            key_type = request.form.get("key_type")
            alias = request.form.get("alias", "").strip()
            description = request.form.get("description", "")
            try:
                params = {
                    "Description": description or f"Encryption key {alias or 'user-key'}",
                    "KeyUsage": "ENCRYPT_DECRYPT",
                    "Origin": "AWS_KMS",
                    "Policy": json.dumps(key_policy)
                }
                params["KeySpec"] = "SYMMETRIC_DEFAULT" if key_type == "SYMMETRIC" else "RSA_2048"
                resp = kms_client.create_key(**params)

                if alias:
                    kms_client.create_alias(
                        AliasName=f"alias/{alias}",
                        TargetKeyId=resp["KeyMetadata"]["KeyId"]
                    )

                flash("✅ KMS key created successfully.", "success")
                return redirect(url_for("encrypt_decrypt"))
            except Exception as e:
                flash(f"Key creation failed: {e}", "danger")

        elif action == "encrypt":
            key_id = request.form.get("encrypt_key_id")
            plaintext = request.form.get("plaintext", "")
            try:
                result = kms_encrypt(kms_client, key_id, plaintext)
                flash("✅ Data encrypted successfully.", "success")
            except Exception as e:
                flash(f"Encryption failed: {e}", "danger")

        elif action == "decrypt":
            key_id = request.form.get("decrypt_key_id")
            ciphertext = request.form.get("ciphertext", "")
            try:
                result = kms_decrypt(kms_client, key_id, ciphertext)
                flash("✅ Data decrypted successfully.", "success")
            except Exception as e:
                flash(f"Decryption failed: {e}", "danger")

    return render_template("encrypt_decrypt.html", keys=keys, result=result, role=role)

# -------------------- SIGN / VERIFY --------------------
@app.route("/sign-verify", methods=["GET", "POST"])
def sign_verify():
    """Sign and verify data using KMS asymmetric keys."""
    if "id_token" not in session:
        return redirect(url_for("login"))

    role = session.get("role", "User")
    if role not in ["Admin", "Sign"]:
        flash("🚫 You do not have permission to access Sign/Verify.", "danger")
        return redirect(url_for("home"))

    creds = get_temporary_credentials(session["id_token"])
    kms_client = init_client(creds, "kms")
    result = None

    try:
        keys = list_kms_keys(kms_client, usage_filter="SIGN_VERIFY")
    except Exception as e:
        flash(f"Error loading signing keys: {e}", "danger")
        keys = []

    if request.method == "POST":
        action = request.form.get("action")

        # --- Create signing key (Admin only) ---
        if action == "create_key" and role == "Admin":
            key_name = request.form.get("key_name", "").strip()
            key_type = request.form.get("key_type")
            description = request.form.get("description", "")
            try:
                params = {
                    "Description": description or f"Signing key {key_name}",
                    "KeyUsage": "SIGN_VERIFY",
                    "Origin": "AWS_KMS",
                    "Policy": json.dumps(key_policy)
                }
                params["KeySpec"] = (
                    "RSA_2048" if key_type == "RSA_2048"
                    else "ECC_NIST_P256" if key_type == "ECC_P256"
                    else "ECC_SECG_P256K1"
                )
                resp = kms_client.create_key(**params)
                kms_client.create_alias(AliasName=f"alias/{key_name}", TargetKeyId=resp["KeyMetadata"]["KeyId"])
                flash(f"✅ Created new signing key '{key_name}'", "success")
                return redirect(url_for("sign_verify"))
            except Exception as e:
                flash(f"Key creation failed: {e}", "danger")

        elif action == "sign":
            key_id = request.form.get("sign_key_id")
            message = request.form.get("message", "")
            try:
                result = kms_sign_message(kms_client, key_id, message)
                flash("✅ Message signed successfully.", "success")
            except Exception as e:
                flash(f"Signing failed: {e}", "danger")

        elif action == "verify":
            key_id = request.form.get("verify_key_id")
            message = request.form.get("message_to_verify", "")
            signature = request.form.get("signature", "")
            try:
                valid = kms_verify_signature(kms_client, key_id, message, signature)
                flash("✅ Signature valid!" if valid else "❌ Invalid signature.", "success" if valid else "danger")
            except Exception as e:
                flash(f"Verification failed: {e}", "danger")

    return render_template("sign_verify.html", keys=keys, result=result, role=role)

# -------------------- LOGOUT --------------------
@app.route("/logout")
def logout():
    session.clear()
    flash("👋 Logged out successfully.", "info")
    return redirect(url_for("login"))

# -------------------- MAIN --------------------
if __name__ == "__main__":
    app.run(debug=True)
