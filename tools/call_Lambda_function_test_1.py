import requests
import subprocess
import json

def call_Lambda_Summary_GenAI(context):
    lambda_url = "https://oau94eheqf.execute-api.us-east-1.amazonaws.com/test/Lambda_Summary_GenAI"

    context = f"Please send me an Summary of the following context.\n context : {context}"

    json_body = {
    # "promtp" : "",
    "inputs": context,
    "parameters": {
        "max_new_tokens": 256,
        "top_p": 0.9,
        "temperature": 0.6,
        "stop": ""
        }
    }
    response = requests.post(lambda_url, json=json_body)


    return response

def call_Lambda_Cybersecurity_GenAI(context):
    lambda_url = "https://oau94eheqf.execute-api.us-east-1.amazonaws.com/test/Lambda_Cybersecurity_GenAI"

    json_body = {
    "inputs": context,
    "parameters": {
        "max_new_tokens": 256,
        "top_p": 0.9,
        "temperature": 0.6,
        "stop": ""
        }
    }
    dsl_response = requests.post(lambda_url, json=json_body) # {"year" : , "mouth", ""}

    # elk dump Cybersecurity information
    dsl_response


    Cybersecurity_information = "" # url : , 文章摘要。
    return "Cybersecurity_information "

def call_Lambda_Mitre_attack_GenAI(context):
    # Mitre_one
    lambda_url = "https://oau94eheqf.execute-api.us-east-1.amazonaws.com/test/Lambda_Mitre_attack_GenAI_one"

    # 這個放在一個文字檔好了。
    Cybersecurity_Classification_define = ""


    context = f"Please help me select the Cybersecurity Classification from {context} based on cybersecurity classification, and return them in JSON format. Only tell me the category names. The Cybersecurity Classification contain {Cybersecurity_Classification_define}"

    json_body = {
    "inputs": context,
    "parameters": {
        "max_new_tokens": 256,
        "top_p": 0.9,
        "temperature": 0.6,
        "stop": ""
        }   
    }
    mitre_one_response = requests.post(lambda_url, json=json_body)

    # elk dump TID
    # 根據 TID dump 出 Cybersecurity_Question

    Cybersecurity_Question =""
    
    # Mitre_two
    lambda_url = "https://oau94eheqf.execute-api.us-east-1.amazonaws.com/test/Lambda_Mitre_attack_GenAI_two"

    # 這個放在一個文字檔好了。
    context = f"Please help me select the Cybersecurity Questions from {context} based on cybersecurity classification, and return them in JSON format. Only tell me the question names. The Cybersecurity Questions contain {Cybersecurity_Question}"

    json_body = {
    "inputs": context,
    "parameters": {
        "max_new_tokens": 256,
        "top_p": 0.9,
        "temperature": 0.6,
        "stop": ""
        }   
    }
    mitre_two_response = requests.post(lambda_url, json=json_body)


    # Mitre_att&ck_TID_table
    Mitre_attack_TID_table = ""

    return Mitre_attack_TID_table
