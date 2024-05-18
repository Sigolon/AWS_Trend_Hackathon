import requests
import subprocess
import json
import pandas

def call_Lambda_Summary_GenAI(api_gatway_url, deploy_version, context):
    lambda_url = f"{api_gatway_url}/{deploy_version}/Lambda_Summary_GenAI"
    
    instruction = "Please help me summarize the context. And summary limit 200 word"
    context = context
    
    template = {
        "prompt": "Below is an instruction that describes a task, paired with an input that provides further context. "
        "Write a response that appropriately completes the request.\n\n"
        "### Instruction:\n{instruction}\n\n### Input:\n{context}\n\n",
        "completion": " {response}",
    }

    datapoint = {
        "instruction" : instruction,
        "context" : context
    }

    input_output_demarkation_key = "\n\n### Response:\n"

    payload = {
        "inputs": template["prompt"].format(
            instruction=datapoint["instruction"], context=datapoint["context"]
        )
        + input_output_demarkation_key,
        "parameters": {"max_new_tokens": 256},
    }
    response = requests.post(lambda_url, json=payload)

    print(response)


def call_Lambda_Mitre_attack_GenAI(api_gatway_url, deploy_version, context):
    
    def call_Mitre_one(context) : 
        lambda_url = f"{api_gatway_url}/{deploy_version}/Lambda_Mitre_attack_GenAI_one"

        with open("Cybersecurity_Classification_define.json", "r") as f : 
            Cybersecurity_Classification_define = f.read()

        prompt = {
            "prompt": "Below is an instruction that describes a task, paired with an input that provides further context. "
            "Write a response that appropriately completes the request.\n\n"
            "### Instruction:\n{instruction}\n\n### Input:\n{context}\n\n",
            "completion": "{response}",
        }

        datapoint = {
            "instruction" : "Please help me select the Cybersecurity Classification from content based on cybersecurity classification, and return them in JSON format. Only tell me the category names.",
            "context" : f"content : {context}\n\n Mitre_Attack Tactics definition : {Cybersecurity_Classification_define}"
        }

        context = f"Please help me select the Cybersecurity Classification from {context} based on cybersecurity classification, and return them in JSON format. Only tell me the category names. The Cybersecurity Classification contain {Cybersecurity_Classification_define}"

        json_body = {
        "inputs": prompt["prompt"].format(
            instruction=datapoint["instruction"], context=datapoint["context"]
        ),
        "parameters": {
            "max_new_tokens": 256,
            "top_p": 0.9,
            "temperature": 0.6,
            "stop": ""
            }   
        }
        mitre_one_response = requests.post(lambda_url, json=json_body)
        return mitre_one_response
    
    def call_Mitre_two(mitre_one_context) : 
        with open("Cybersecurity_Question_list.txt", "r") as f :    
            Cybersecurity_Question_list = f.read()
            
        lambda_url = f"{api_gatway_url}/{deploy_version}/Lambda_Mitre_attack_GenAI_two"

        prompt = {
            "prompt": "Below is an instruction that describes a task, paired with an input that provides further context. "
            "Write a response that appropriately completes the request.\n\n"
            "### Instruction:\n{instruction}\n\n### Input:\n{context}\n\n",
            "completion": "{response}",
        }

        datapoint = {
            "instruction" : "Please help me select the Cybersecurity Questions from content based on cybersecurity classification, and return them in JSON format. Only tell me the category names. The Cybersecurity Questions contain Cybersecurity_Question_list",
            "context" : f"content : {mitre_one_context}\n\n Cybersecurity_Question_list : {Cybersecurity_Question_list}"
        }

        json_body = {
        "inputs": prompt["prompt"].format(
            instruction=datapoint["instruction"], context=datapoint["context"]
        ),
        "parameters": {
            "max_new_tokens": 256,
            "top_p": 0.9,
            "temperature": 0.6,
            "stop": ""
            }   
        }

        mitre_two_response = requests.post(lambda_url, json=json_body)
        return mitre_two_response

    mitre_one_response = call_Mitre_one(context)
    mitre_two_response = call_Mitre_two(context)

    mitre_one = json.loads(mitre_one_response["completion"])["Cybersecurity Classification"]
    mitre_two = json.loads(mitre_two_response["completion"])["Cybersecurity Question"]

    df = pandas.read_json("/home/sigolon/AWS_Trend_Hakethon/data/database/Mitre_Attack_GenAI_related_table.json")
    result_list = []
    for tactic	in mitre_one : 
        for technique in mitre_two : 
            if len(df[(df["tactic"] == tactic) & (df["technique"] == technique)]) != 0 : 
                result = {
                    "tactic" : tactic,
                    "technique" : technique,
                    "TID" : df[(df["tactic"] == tactic) & (df["technique"] == technique)]["TID"].values[0]
                }
                result_list.append(result)

    
    mitre_table = pandas.DataFrame(result_list)
    mitre_table.to_json("call_Lambda_Mitre_attack_GenAI_output.json")

    # Mitre_att&ck_TID_table
    with open("call_Lambda_Mitre_attack_GenAI_output.json", "r") as f :  
        Mitre_attack_TID_table = f.read()

    print(Mitre_attack_TID_table)


def call_Lambda_Cybersecurity_GenAI(api_gatway_url, deploy_version, context):
    def elasticsearch_data_dump(hostip, pattern_index, dsl_query) : 
        INPUT_URL = f"https://@{hostip}/{pattern_index}" # "https://user:password@hostip/winlogbeat-*"
        OUTPUT_FILE = "elk_dump.json"

        SEARCH_BODY = dsl_query

        '''''
        "query": {
            "bool": {
            "must": [
                {
                "exists": {
                    "field": "technique_id"
                }
                },
                {
                "range": {
                    "@timestamp": {
                    "gte": "2024-04-10T09:50:00.000Z",
                    "lte": "2024-04-10T19:00:00.000Z"
                    }
                }
                }
            ]
            }
        }
        }
        '''''

        # 轉換SEARCH_BODY為JSON字符串
        search_body_json = json.dumps(SEARCH_BODY)

        # 使用subprocess運行elasticdump命令
        subprocess.run([
            "elasticdump",
            "--ssl-allow-unauthorized",
            "--input=" + INPUT_URL,
            "--output=" + OUTPUT_FILE,
            "--type=data",
            "--searchBody=" + search_body_json
        ], check=True)

    lambda_url = f"{api_gatway_url}/{deploy_version}/Lambda_Cybersecurity_GenAI"
    # check this elasticsearch mapping 
    mapping = {
        "stocks": {
            "mappings": {
            "properties": {
                "url": {"type": "text"},
                "content": {"type":"text"},
                "post_year" : {"type":"date"},
                "post_mouth" : {"type":"float"},
                "post_day"  : {"type":"float"},
                "name" : {
                "type": "text",
                "fields": {
                    "keyword":{"type":"keyword", "ignore_above":256}
                    }
                },
                "open"  : {"type":"float"},
                "volume": {"type":"long"}
                }
            }
        }
    }

    context = f'Given the mapping delimited by triple backticks ```{mapping}``` translate the text delimited by triple quotes in a valid Elasticsearch DSL query """{context}""". Give me only the json code part of the answer. Compress the json output removing spaces.'

    json_body = {
    "inputs": context,
    "parameters": {
        "max_new_tokens": 256,
        "top_p": 0.9,
        "temperature": 0.6,
        "stop": ""
        }
    }
    dsl_response = requests.post(lambda_url, json=json_body)

    # elk dump Cybersecurity information
    # password 可能要改
    elasticsearch_data_dump(hostip = "127.0.0.1", pattern_index = "Cybersecurity_information", dsl_query = dsl_response["body"])
    df = pandas.read_json("elk_dump.json")

    df_return = df.sample(1)
    url = df_return["url"].values()[0]
    content = df_return["content"].values()[0]

    Cybersecurity_information = {
        "url" : url,
        "content" : content[0][0:200].replace("\xa0", " ") + "... ...",
    }
    print(Cybersecurity_information)
