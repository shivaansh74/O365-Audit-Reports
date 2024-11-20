import os
import requests
import datetime
import pytz
import pandas as pd
from collections import defaultdict
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Azure AD credentials from environment variables
client_id = "YOUR CLIENT ID"
client_secret = "YOUR CLIENT SECRET"
tenant_id = "YOUR TENANT ID"

# Email credentials from environment variables
email_sender = "YOUREMAIL@EXAMPLE.COM"
email_password = "YOUREMAILPASSWORD"
email_recipient = "RECIPIENTEMAIL@EXAMPLE.COM"

# Mapping of complex app names to simplified versions
app_name_mapping = {
    "Office Online Core SSO": "Office Online",
    "Office365 Shell WCSS-Client": "Office 365 Shell",
    "Microsoft Account Controls V2": "Microsoft Account",
    "Office 365 SharePoint Online": "SharePoint Online",
    "Office 365 Exchange Online": "Exchange Online",
    "Graph Explorer": "Graph Explorer",
    "Microsoft 365 Security and Compliance Center": "Microsoft 365 Security",
    "OfficeHome": "Office Home",
    "Microsoft 365 Support Service": "Microsoft 365 Support",
    "Azure Portal": "Azure Portal",
    "Microsoft Office": "Microsoft Office",
    "Microsoft Authentication Broker": "Microsoft Auth Broker",
    "Microsoft Teams": "Teams"
}

# Get access token
def get_access_token():
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }

    response = requests.post(url, headers=headers, data=data)
    response.raise_for_status()
    return response.json().get('access_token')

# Fetch sign-in logs
def fetch_sign_in_logs(token):
    # Convert the current system time to UTC
    end_time = datetime.datetime.now(pytz.utc)  # Current time in UTC
    start_time = end_time - datetime.timedelta(hours=24)  # Subtract 24 hours

    url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
    params = {
        "$filter": f"createdDateTime ge {start_time.isoformat()} and createdDateTime le {end_time.isoformat()}"
    }
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json().get('value', [])

# Process logs
def process_logs(logs):
    user_first_login = defaultdict(lambda: None)
    user_last_activity = defaultdict(lambda: None)
    user_os_browser = defaultdict(lambda: set())
    user_ips = defaultdict(lambda: defaultdict(set))
    user_apps_accessed = defaultdict(lambda: defaultdict(set))  # Updated to store apps by IP address

    for log in logs:
        user_principal_name = log.get('userPrincipalName')
        created_time = log.get('createdDateTime')
        device_detail = log.get('deviceDetail', {})
        ip_address = log.get('ipAddress')
        city = log.get('location', {}).get('city', 'N/A')
        state = log.get('location', {}).get('state', 'N/A')
        app_display_name = log.get('appDisplayName', 'N/A')  # Capture the app accessed

        # Simplify app name if available in the mapping
        if app_display_name in app_name_mapping:
            app_display_name = app_name_mapping[app_display_name]

        # Check for the specific IP address to update city and state
        if ip_address == '216.122.175.239':
            city = 'New York City'
            state = 'New York'

        if user_principal_name and created_time:
            # Convert created_time to UTC
            created_time_utc = datetime.datetime.fromisoformat(created_time).replace(tzinfo=pytz.utc)

            # First login (earliest)
            if user_first_login[user_principal_name] is None or created_time_utc < user_first_login[user_principal_name]:
                user_first_login[user_principal_name] = created_time_utc

            # Last activity (latest)
            if user_last_activity[user_principal_name] is None or created_time_utc > user_last_activity[user_principal_name]:
                user_last_activity[user_principal_name] = created_time_utc

            # Collect OS and browser details
            os = device_detail.get('operatingSystem', 'N/A')
            browser = device_detail.get('browser', 'N/A')

            if os != 'N/A' and browser != 'N/A':
                user_os_browser[user_principal_name].add((os, browser))

            # Collect unique IP addresses along with city and state
            if ip_address:
                user_ips[user_principal_name][(city, state)].add(ip_address)

            # Capture the app accessed (now using simplified names)
            if app_display_name != 'N/A' and ip_address:
                user_apps_accessed[user_principal_name][ip_address].add(app_display_name)

    return user_first_login, user_last_activity, user_os_browser, user_ips, user_apps_accessed

# Prepare the report data
def prepare_report_data(user_first_login, user_last_activity, user_os_browser, user_ips, user_apps_accessed):
    first_last_login_data = []
    os_browser_data = []
    ip_data = []
    apps_data = []

    # First and Last Login table
    for user in user_first_login.keys():
        first_login_est = user_first_login[user].astimezone(pytz.timezone("America/New_York")).strftime('%Y-%m-%d %H:%M:%S') if user_first_login[user] else 'N/A'
        last_activity_est = user_last_activity[user].astimezone(pytz.timezone("America/New_York")).strftime('%Y-%m-%d %H:%M:%S') if user_last_activity[user] else 'N/A'
        
        first_last_login_data.append({
            'User': user,
            'First Login (EST)': first_login_est,
            'Last Activity (EST)': last_activity_est
        })

    # OS and Browser table (separate columns for OS and Browser)
    for user, os_browsers in user_os_browser.items():
        for os, browser in os_browsers:
            os_browser_data.append({
                'User': user,
                'Operating System': os,
                'Browser': browser
            })

    # IP Address table (consolidating IPs based on city and state, limit to 2 IPs)
    for user, locations in user_ips.items():
        for (city, state), ips in locations.items():
            limited_ips = list(ips)[:2]  # Limit to two IPs
            for ip in limited_ips:
                # Collect the list of apps accessed for this IP address
                apps_for_ip = ', '.join(user_apps_accessed[user][ip])  # Get apps for the IP
                ip_data.append({
                    'User': user,
                    'IP Address': ip,
                    'City': city,
                    'State': state,
                    'Apps Accessed': apps_for_ip if apps_for_ip else 'N/A'
                })

    # Apps Accessed table (using simplified names)
    for user, apps in user_apps_accessed.items():
        apps_data.append({
            'User': user,
            'Apps Accessed': ', '.join(set(app for ip_apps in apps.values() for app in ip_apps)) if apps else 'N/A'
        })

    return first_last_login_data, os_browser_data, ip_data, apps_data

# Generate HTML report
def generate_html_report(first_last_login_data, os_browser_data, ip_data, apps_data):
    df_first_last = pd.DataFrame(first_last_login_data)
    df_os_browsers = pd.DataFrame(os_browser_data)
    df_ips = pd.DataFrame(ip_data)
    df_apps = pd.DataFrame(apps_data)

    html_content = f"""
    <html>
    <head>
        <style>
            table, th, td {{ border: 1px solid black; border-collapse: collapse; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <h2>User Activity Report (Last 24 Hours)</h2>
        <h3>First Login and Last Activity</h3>
        {df_first_last.to_html(index=False, border=0)}
        <h3>Operating Systems and Browsers Used by Users</h3>
        {df_os_browsers.to_html(index=False, border=0)}
        <h3>IP Addresses of Users</h3>
        {df_ips.to_html(index=False, border=0)}
        <h3>Applications Accessed by Users</h3>
        {df_apps.to_html(index=False, border=0)}
    </body>
    </html>
    """
    return html_content

# Send email with the report
def send_email(html_content):
    subject = "User Activity Report"

    # Create the message
    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_recipient
    msg['Subject'] = subject

    # Attach the HTML content
    msg.attach(MIMEText(html_content, 'html'))

    # Configure Outlook SMTP server
    try:
        server = smtplib.SMTP('smtp.office365.com', 587)
        server.starttls()  # Start TLS encryption

        # Use app password if 2FA is enabled
        server.login(email_sender, email_password)
        
        # Send the email
        server.sendmail(email_sender, email_recipient, msg.as_string())
        print("Email sent successfully.")
    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication failed: {e}")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")
    finally:
        server.quit()

# Main function to run the whole process
def main():
    try:
        # Get access token
        token = get_access_token()

        # Fetch sign-in logs for the last 24 hours
        logs = fetch_sign_in_logs(token)

        # Process the logs
        user_first_login, user_last_activity, user_os_browser, user_ips, user_apps_accessed = process_logs(logs)

        # Prepare the data for the report
        first_last_login_data, os_browser_data, ip_data, apps_data = prepare_report_data(user_first_login, user_last_activity, user_os_browser, user_ips, user_apps_accessed)

        # Generate the HTML report
        html_report = generate_html_report(first_last_login_data, os_browser_data, ip_data, apps_data)

        # Send the email with the report
        send_email(html_report)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
