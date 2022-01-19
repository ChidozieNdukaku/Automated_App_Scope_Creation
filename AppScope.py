import os, requests, urllib3, json, sys, yaml, string, random,itertools , operator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

allowed_parameters = ["eng", "nonp", "prod"]
if len(sys.argv) < 2 or sys.argv[1] not in allowed_parameters:
     print ("Usage: python Aqua.py <env> <username> <password> <registry>")
     exit()
if "eng" in sys.argv[1]:
     hostname = "aquasec.canadacentral.aks.eng.c1.rbc.com"
elif "nonp" in sys.argv[1]:
     hostname = "aquasec.canadacentral.aks.nonp.c1.rbc.com"
elif "prod" in sys.argv[1]:
     hostname = "aquasec.canadacentral.aks.prod.c1.rbc.com"
else:
     print ("Unknown environment", sys.argv[1]); exit()
 # Lots of input sanitation.
switches = ["--username", "--password"]
try:
     USERNAME = sys.argv[sys.argv.index("--username")+1]
     PASSWORD = sys.argv[sys.argv.index("--password")+1]
     if USERNAME in switches or PASSWORD in switches:
         print ("A switch was declared but its value seems to be the same as a switch name."); exit()
 except IndexError as error:
     print ("A switch was declared but its value was never provided."); exit()
 except ValueError as error:
     print ("Lacking one of the necessary switches.")
     print ("\t", error); exit()
 def get_jwt_token(hostname):
     request_headers = {
         "Accept": "application/json",
         "Content-Type": "application/json; charset=UTF-8"
     }
     endpoint = "https://" + hostname + "/api/v1/login"
     payload = {
         "id": USERNAME,
         "password": PASSWORD
     }
     d = json.dumps(payload)
     r = requests.post(
         url=endpoint,
         verify=False,
         headers=request_headers,
         data=d)
     if str(r.status_code) == "200":
         return r.json()["token"]
     else:
         print (r.json())
         return None
 def create_role(token, hostname, payload):
     request_headers = {
         "Accept": "application/json",
         "Content-Type": "application/json; charset=UTF-8",
         "Authorization": "Bearer " + token
     }
     endpoint = "https://" + hostname + "/api/v2/access_management/roles"
     res = requests.post(url=endpoint, verify=False, headers=request_headers, json=payload)
     return res
 def update_role(token, hostname, payload):
     request_headers = {
         "Accept": "application/json",
         "Content-Type": "application/json; charset=UTF-8",
         "Authorization": "Bearer " + token
     }
     endpoint = "https://" + hostname + f"/api/v2/access_management/roles/{payload['name']}"
     res = requests.put(url=endpoint, verify=False, headers=request_headers, json=payload)
     return res
 def create_user(token, hostname, role_name, user):
     request_headers = {
         "Accept": "application/json",
         "Content-Type": "application/json; charset=UTF-8",
         "Authorization": "Bearer " + token
     }
     endpoint = "https://" + hostname + f"/api/v1/users"
     # Random password generator. Will make use of all possible characters and ensure the string is 25-35 characters long.
     character_bank = string.ascii_letters + string.digits + string.punctuation; password = "".join(random.sample(character_bank, random.randrange(25, 35)))
     payload = {"id": user,
         "name": user,
         "password": password,
         "admin": False,
         "roles": [role_name]
     }
     print ("THIS IS PAYLOAD =>", json.dumps(payload))
     res = requests.post(url=endpoint, verify=False, headers=request_headers, data=json.dumps(payload))
     return res
 def update_user(token, hostname, role_name, user):
     request_headers = {
         "Accept": "application/json",
         "Content-Type": "application/json; charset=UTF-8",
         "Authorization": "Bearer " + token
     }
     endpoint = "https://" + hostname + f"/api/v1/users/{user}"
     res = requests.put(url=endpoint, verify=False, headers=request_headers, json={"roles": [role_name]})
     return res
 token = get_jwt_token(hostname)
 details = yaml.load_all(open("mapping.yaml", "r"), Loader=yaml.FullLoader)
 for role in details:
     payload = {}
     role_to_ldap = {role["name"]: role["ldap"]}
     # Because Aqua cannot develop API properly it seems, we cannot provide a group or a user right when creating the role - will throw unmarshal error.
     # Consequently, the approach is to create a role to best of our ability and then modify a user that is to be associated with the role.
     for item in role:
         if item == "users":
             users = [role[item]]    # needed for future when modifying users
             continue
         if item == "ldap":      # there is no such a parameter but we need it for role integration with LDAP
             continue
         payload[item] = role[item]
     request = create_role(token, hostname, payload)
     if request.status_code == 201:
         print (f"""Successfully created role '{payload["name"]}'""")
     else:
         if f'role {payload["name"]} already exists' in request.content.decode():
             print (f"""Failed to create role '{payload["name"]}' because it already exists. Attempting to update.""")
             request = update_role(token, hostname, payload)
             if request.status_code == 204:
                 print (f"""\tSuccessfully updated role '{payload["name"]}'""")
             else:
                 print (f"""\tFailed to update role '{payload["name"]}':""")
                 print ("\t\t", request.content)
                 print (request.status_code)
         else:
             print (f"""Failed to create role '{payload["name"]}':""")
             print ("\t", request.content)
             print (request.status_code)
             continue        # no role means there is not much point in tackling user
     # Going through every single user and modifying it. If that fails, attempt to create.
     for user in users:
         request = update_user(token, hostname, payload["name"], user)
         if request.status_code == 204:
             print (f"""\tSuccessfully assigned user '{user}' to role '{payload["name"]}'""")
         else:
             if "No such user" in request.content.decode():
                 print (f"""\tFailed to update user '{user}' because it does not exist. Attempting to create.""")
                 request = create_user(token, hostname, payload["name"], user)
                 if request.status_code == 204:
                     print (f"""\tSuccessfully created user '{user}'""")
                 else:
                     print (f"""\tFailed to update role '{payload["name"]}':""")
                     print ("\t\t", request.content)
                     print (request.status_code)
             else:
                 print (f"""\tFailed to assign user '{user}' to role '{payload["name"]}':""")
                 print ("\t\t", request.content)
                 print (request.status_code)
                
 # NEED to add LDAP part as well
 #request = update_ldap
@@ -3,7 +3,7 @@ urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
allowed_parameters = ["eng", "nonp", "prod"]
if len(sys.argv) < 2 or sys.argv[1] not in allowed_parameters:
    print ("Usage: python Aqua.py <env> <username> <password> <registry>")
    print ("Usage: python Aqua.py <env> --username <username> --password <password>")
    exit()
if "eng" in sys.argv[1]:
@@ -90,7 +90,6 @@ def create_user(token, hostname, role_name, user):
        "admin": False,
        "roles": [role_name]
    }
    print ("THIS IS PAYLOAD =>", json.dumps(payload))
    res = requests.post(url=endpoint, verify=False, headers=request_headers, data=json.dumps(payload))
    return res
@@ -105,21 +104,124 @@ def update_user(token, hostname, role_name, user):
    res = requests.put(url=endpoint, verify=False, headers=request_headers, json={"roles": [role_name]})
    return res
token = get_jwt_token(hostname)
# get list of repos, classify them into categories based on team appcode,
#send results to mapping.yaml
def get_repos(token,hostname,):
  request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=UTF-8",
        "Authorization": "Bearer " + token
    }
    endpoint = "https://" + hostname + "api/v2/repositories" 
    res = requests.get(url =endpoint,verify=False, headers=request_headers, payload=json)
    repos = requests.get.json
    
    list_of_repos = json.loads[repos]
# sort the list of dictionaries based on the value of the key name which is split before /
    for d in list_of_repos:
        for value in d.items:
            repo_name = str('name').split('/')[0]
                str1 = repo_name
                    if str1.isalpha():
             
                    elif str1.isalanum():
            
                    else:
           
   )    
#writing the json to mapping.yaml
reposJSON = json.dumps(list_of_repos, indent=4)
with open("requirements.yaml", "w+",) as file:
    documents = yaml.dump(reposJSON, f , allow_unicode=True, indent=4)


def create_scope(token, hostname, scope_name, scope, scope_description):
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=UTF-8",
        "Authorization": "Bearer " + token
    }
    endpoint = "https://" + hostname + "/api/v2/access_management/scopes"
    payload = {"name": scope_name,
        "categories": {
            "artifacts": {
                "image": {
                    "expression": ""
                }
            }
        }
    }
    expression, image_vars = construct_expression(scope)
    payload["categories"]["artifacts"]["image"]["expression"] = expression
    payload["categories"]["artifacts"]["image"]["variables"] = image_vars
    payload["description"] = scope_description
    res = requests.post(url=endpoint, verify=False, headers=request_headers, json=payload)
    return res
def update_scope(token, hostname, scope_name, scope, scope_description):
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=UTF-8",
        "Authorization": "Bearer " + token
    }
    endpoint = "https://" + hostname + f"/api/v2/access_management/scopes/{scope_name}"
    payload = {"name": scope_name,
        "categories": {
            "artifacts": {
                "image": {
                    "expression": ""
                }
            }
        }
    }
    expression, image_vars = construct_expression(scope)
    payload["categories"]["artifacts"]["image"]["expression"] = expression
    payload["categories"]["artifacts"]["image"]["variables"] = image_vars
    payload["description"] = scope_description
    res = requests.put(url=endpoint, verify=False, headers=request_headers, json=payload)
    return res
def construct_expression(scope):
    # This is an expression constructor. Every expression has two attributes, each attribute has a value.
    # In scope definition, expressions are tied with a logical OR (||) while attributes are tied with a logical AND (&&).
    counter = 1; isFirst = True
    for value in scope:
        #
        if len(scope) == 1:
            expression = f"(v{counter} && v{counter+1})"
        else:
            if isFirst:
                expression = f"(v{counter} && v{counter+1})"
                isFirst = False
            else:
                expression += f" || (v{counter} && v{counter+1})"
        counter += 2    # 1 expression = 2 attributes hence we have a step of 2
    image_vars = []
    for definition in scope:
        image_vars.extend([{"attribute": "aqua.registry", "value": "*"}, {"attribute": "image.repo", "value": definition}])
    return expression, image_vars
token = get_jwt_token(hostname)
details = yaml.load_all(open("mapping.yaml", "r"), Loader=yaml.FullLoader)
for role in details:
    payload = {}
    role_to_ldap = {role["name"]: role["ldap"]}
    # Because Aqua cannot develop API properly it seems, we cannot provide a group or a user right when creating the role - will throw unmarshal error.
    # Consequently, the approach is to create a role to best of our ability and then modify a user that is to be associated with the role.
    role_to_ldap = {role["name"]: role["ldap"]}; scope_name = role["scopes"]; scope = role["image_scopes"]
    # We cannot provide a group or a user right when creating the role - will throw unmarshal error (what documentation says is a mistake).
    # The approach is to create a role to best of our ability and then modify a user that is to be associated with the role.
    for item in role:
        if item == "users":
            users = [role[item]]    # needed for future when modifying users
            continue
        if item == "ldap":      # there is no such a parameter but we need it for role integration with LDAP
        elif item == "scopes":
            payload[item] = [role[item]]    # we only recognize one scope per role but Aqua expects an array
            continue
        elif item == "scope_description":
            scope_description = role[item]
        if item == "ldap" or item == "image_scopes":      # there is no such a parameter but we need it for role integration with LDAP
            continue
        payload[item] = role[item]
    ##############
    ### Scopes ###
    ##############
    request = create_scope(token, hostname, scope_name, scope, scope_description)
    if request.status_code == 201:
        print (f"""Successfully created scope '{scope_name}'""")
    else:
        if f'application scope {scope_name} already exists' in request.content.decode():
            print (f"""Failed to create scope '{scope_name}' because it already exists. Attempting to update.""")
            request = update_scope(token, hostname, scope_name, scope, scope_description)
            if request.status_code == 204:
                print (f"""\tSuccessfully updated scope '{scope_name}'""")
            else:
                print (f"""\tFailed to update scope '{scope_name}':""")
                print ("\t\t", request.content)
                print (request.status_code)
        else:
            print (f"""Failed to create scope '{scope_name}':""")
            print ("\t", request.content)
            print (request.status_code)
            continue        # no scope means there is not much point in tackling everything else
    #############
    ### Roles ###
    #############
    request = create_role(token, hostname, payload)
    if request.status_code == 201:
        print (f"""Successfully created role '{payload["name"]}'""")
@@ -139,6 +241,9 @@ for role in details:
            print (request.status_code)
            continue        # no role means there is not much point in tackling user
    #############
    ### Users ###
    #############
    # Going through every single user and modifying it. If that fails, attempt to create.
    for user in users:
        request = update_user(token, hostname, payload["name"], user)
