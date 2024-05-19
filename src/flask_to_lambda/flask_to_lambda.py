import sys
import os

sys.path.append("/home/ubuntu/AWS_Trend_Hakethon")

from tools.call_Lambda_function_test_1 import (
    call_Lambda_Summary_GenAI, 
    call_Lambda_Cybersecurity_GenAI, 
    call_Lambda_Mitre_attack_GenAI
)
if len(sys.argv) != 3:
    print("Usage: python script.py <context> <GenAI_Model>")
    sys.exit(1)

context = sys.argv[1]
GenAI_Model = sys.argv[2] # only Summary_GenAI, Cybersecurity_GenAI, Mitre_attack_GenAI

api_gatway_url = "https://3qkpidhy64.execute-api.us-west-2.amazonaws.com" 
deploy_version = "test"

field = {
    "Summary_GenAI": call_Lambda_Summary_GenAI,
    "Cybersecurity_GenAI": call_Lambda_Cybersecurity_GenAI,
    "Mitre_attack_GenAI": call_Lambda_Mitre_attack_GenAI
}

for model_name, model_function in field.items():
    if GenAI_Model == model_name:
        response_to_flask = model_function(api_gatway_url, deploy_version, context) 
    else:
        pass



