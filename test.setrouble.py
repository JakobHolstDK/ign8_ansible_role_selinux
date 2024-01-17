import requests
import json

# Set the URL of your Django REST API endpoint
api_url = "https://ignite.openknowit.com/selinux/api/setroubleshoot/upload/"  # Replace with your actual URL

# Replace with your SetroubleshootEntry data
entry_data = {
    "cursor": "your_cursor",
    "realtime_timestamp": 1234567890,
    "monotonic_timestamp": 9876543210,
    # Add more fields as needed
}

# Serialize the data to JSON
json_data = json.dumps(entry_data)

# Set the headers for the request
headers = {
    "Content-Type": "application/json",
}

# Make the POST request
response = requests.post(api_url, data=json_data, headers=headers)

# Check the response
if response.status_code == 201:  # HTTP status code for Created
    print("SetroubleshootEntry uploaded successfully!")
else:
    print(f"Failed to upload SetroubleshootEntry. Status code: {response.status_code}")
    print(response.text)

