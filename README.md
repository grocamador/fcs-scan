# FCS Scan

A GitHub Actions workflow that performs CrowdStrike Falcon Cloud Security (FCS) Infrastructure-as-Code scans on local CloudGoat samples.

## What it does

- Scans Terraform files in the `samples/` folder for security vulnerabilities
- Uses CloudGoat privilege escalation scenarios for testing
- Automatically uploads security findings to GitHub Code Scanning when issues are found
- Generates SARIF reports for integration with GitHub's Security tab

## Samples included

- **IAM Privilege Escalation by Rollback** - Demonstrates IAM policy version vulnerabilities
- **Lambda Privilege Escalation** - Shows Lambda function security misconfigurations

## Usage

1. Configure your Falcon credentials in GitHub secrets:
   - `FALCON_CLIENT_ID` (repository variable)
   - `FALCON_CLIENT_SECRET` (repository secret)

2. Run the workflow manually via GitHub Actions → "FCS Scan" → "Run workflow"

3. View security findings in the repository's **Security** → **Code scanning** tab

## Documentation

For detailed configuration options and advanced usage, see the [CrowdStrike FCS Action documentation](https://github.com/CrowdStrike/fcs-action?tab=readme-ov-file#upload-sarif-report-to-github-code-scanning-on-non-zero-exit-code).
