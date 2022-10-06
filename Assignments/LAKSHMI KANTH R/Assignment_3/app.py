from flask import Flask, redirect, url_for, render_template, request
import ibm_boto3
from ibm_botocore.client import Config, ClientError

# Constants for IBM COS values
# Current list avaiable at https://control.cloud-object-storage.cloud.ibm.com/v2/endpoints
COS_ENDPOINT = "https://s3.jp-tok.cloud-object-storage.appdomain.cloud"
# eg "W00YixxxxxxxxxxMB-odB-2ySfTrFBIQQWanc--P3byk"
COS_API_KEY_ID = "y95bSk60m26-YNNQtAJiq7jaVdalIZAcU8eEMbZc5mdN"
COS_INSTANCE_CRN = "crn:v1:bluemix:public:iam-identity::a/25404e232915448d893570237a3a168c::serviceid:ServiceId-0a342b1e-5976-4301-9bb8-dba42d47f5cb"
# eg "crn:v1:bluemix:public:cloud-object-storage:global:a/3bf0d9003xxxxxxxxxx1c3e97696b71c:d6f04d83-6c4f-4a62-a165-696756d63903::"

# Create resource
cos = ibm_boto3.resource("s3",
                         ibm_api_key_id=COS_API_KEY_ID,
                         ibm_service_instance_id=COS_INSTANCE_CRN,
                         config=Config(signature_version="oauth"),
                         endpoint_url=COS_ENDPOINT
                         )

app = Flask(__name__)


def get_item(bucket_name, item_name):
    print("Retrieving item from bucket: {0}, key: {1}".format(
        bucket_name, item_name))
    try:
        file = cos.Object(bucket_name, item_name).get()

        print("File Contents: {0}".format(file["Body"].read()))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve file contents: {0}".format(e))


def get_bucket_contents(bucket_name):
    print("Retrieving bucket contents from: {0}".format(bucket_name))
    try:
        files = cos.Bucket(bucket_name).objects.all()
        files_names = []
        for file in files:
            files_names.append(file.key)
            print("Item: {0} ({1} bytes).".format(file.key, file.size))
        return files_names
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve bucket contents: {0}".format(e))


@app.route('/')
def index():
    files = get_bucket_contents('boopathi')
    return render_template('index.html', files=files)


if __name__ == '__main__':
    app.run(debug=True)
