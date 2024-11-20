# Office 365 Audit Reports Script

This Python script is designed to gather and manage Office 365 audit logs, specifically focusing on capturing relevant security information such as login activities, access details, and sign-in logs. The script integrates with Microsoft Graph API to fetch these logs and process them for analysis and reporting.

## Features

- **Audit Logs Collection:** Fetches sign-in and audit logs from Office 365 via Microsoft Graph API.
- **Real-Time Security Alerts:** Identifies and generates alerts for login issues, security concerns, and phishing attempts.
- **Data Transformation:** Converts hard-to-understand app names in logs to more user-friendly terms (e.g., transforming app names like `Office365 Shell WCSS-Client` to `Teams`).
- **Email Alerts:** Sends automated email reports for detected security risks (if configured).
- **Secret Scanning Protection:** Includes protection from accidentally pushing sensitive information like API keys or client secrets to public repositories.

## Requirements

Before running this script, ensure the following dependencies are installed:

- **Python 3.x**
- **Microsoft Graph API access credentials**
- Required Python libraries:
  - `requests` (for making HTTP requests to Microsoft Graph API)
  - `msal` (for authenticating and obtaining access tokens from Azure Active Directory)
  - `pandas` (for data manipulation and storage, if necessary)
  - `smtplib` (for email notifications)

You can install these dependencies via pip:

```bash
pip install requests msal pandas
