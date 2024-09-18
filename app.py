import logging

from flask import Flask, request, jsonify
from openai import OpenAI
from flask_cors import CORS
import json
import boto3
from botocore.exceptions import ClientError


def get_secret():
    secret_name = "arn:aws:secretsmanager:us-east-1:767398095220:secret:OpenAI-364y4I"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        logging.info("success")
    except ClientError as e:
        logging.info("error")
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']
    secret = json.loads(secret)
    return secret["OpenAI"].replace("\"", "")
    # Your code goes here.




app = Flask(__name__)
CORS(app, resources={"/*": {"origins": ["https://chatbot-frontend-indol.vercel.app", "http://localhost:5173/"]}})
key = get_secret()
print(key)
if not key:
    print("eror")
openai_api_key = key


client = OpenAI(api_key=openai_api_key)

#Creating a post route with "/" endpoint

@app.route("/", methods=["GET"])
def hello_world():
    return "Hello World"
@app.route('/', methods = ['POST', 'OPTIONS'])
def is_phising():  # put application's code here
    if request.method == "OPTIONS":
        return "", 200
    #Grabbing request body
    content = request.get_json()

    #Checking if all the required information is sent
    errors = []
    if not content.get("subject", None):
        errors.append("subject")
    if not content.get("body", None):
        errors.append("body")
    if not content.get("sender", None):
        errors.append("sender")

    #If not, send a 400 error alongside with what is missing
    if errors:
        output = ""
        for x in errors:
            output += f"{x}, "
        output += "is needed in the request body"
        print(output)
        return output, 400

    #Make Request to OpenAI API
    subject, body, sender = content['subject'], content['body'], content['sender']
    prompt = f"Classify this email as normal or phishing:\nSubject: {subject}\nBody: {body}\nSender: {sender}"
    completion = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system",
             "content": "You are an assistant skilled in cybersecurity, especially in identifying phishing emails."},
            {"role": "user", "content": prompt},
        ]
    )
    content = completion.choices[0].message.content
    content.strip()
    print(content)
    if content:
        return jsonify(content), 200
    else:
        return "Something went wrong!!", 500
