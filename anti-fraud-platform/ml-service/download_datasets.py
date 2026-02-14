import kagglehub
import os

print("Downloading datasets from Kaggle...")
print("=" * 60)

# Download web phishing dataset
print("\n1. Downloading web-page-phishing-detection-dataset...")
web_path = kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")
print(f"✓ Web dataset downloaded to: {web_path}")

# Download email phishing dataset
print("\n2. Downloading phishing-email-dataset...")
email_path = kagglehub.dataset_download("naserabdullahalam/phishing-email-dataset")
print(f"✓ Email dataset downloaded to: {email_path}")

print("\n" + "=" * 60)
print("✓ All datasets downloaded successfully!")
print(f"\nWeb dataset: {web_path}")
print(f"Email dataset: {email_path}")
