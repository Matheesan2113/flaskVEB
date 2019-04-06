from Crypto.Signature import PKCS1_PSS as PKCS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from flask import Flask, render_template, request
from OpenSSL import SSL
import string, random, requests
# SSL setup
context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file("./keys/private_key.pem")
context.use_certificate_file("./keys/server.pem")
ctf = Flask(__name__)
voters = {} # PreRegCode : { "valid_num" : valid_num, "vote": vote }
validation_numbers = {} # valid_num : ifVoted
votes = { "Lib" : 0, "Con" : 0, "NDP" : 0 }
names = []
# stores CSRF token
session = {}

# Vote main page form
@ctf.route("/")
def main():
    return render_template("ctf_vote.html")

# If voter is added, verify with digital signature that was sent through the POST and add that voter hasn't voted
@ctf.route("/add_voter", methods=["POST"])
def add_voter():
    if request.method == "POST":
        signature = request.form["digsig"]
        valid_num = request.form["valid_num"]
        regCodeCLA = request.form["reg_Code"]
        verified = False
        print("Reached Add Voters, waiting to verify digital sig")
        if verify_dig_sig(signature, valid_num):
            validation_numbers[valid_num] = {"votedYet":False,"reg_Code":regCodeCLA}
    return "add_voter"

# If name is sent from CLA, verify with digital signature and append name to list of names that voted
@ctf.route("/get_name", methods=["POST"])
def get_names():
    if request.method == "POST":
        signature = request.form["digsig"]
        name = request.form["name"]
        if verify_dig_sig(signature, name):
            names.append(name)
    return "get_name"

# Voting page confirming whether or not voter's vote is valid by checking with PreRegCode and valid_num
@ctf.route("/confirmation", methods=["POST"])
def confirmation():
    if request.method == "POST":
        message = validate_voter(request.form["PreRegCode"], request.form["valid_num"], request.form["party"])
        print(voters)
        if "thanks" in message:
            request_voter_name(request.form["valid_num"])
        return render_template("ctf_confirmation.html", message = message)

# Displays results page. Mostly static
@ctf.route("/results")
def display_results():
    return render_template("ctf_results.html", voters=voters, votes=votes, names=names)

# Ask CLA for voter name by sending digital sig and validation num that matches to name
def request_voter_name(valid_num):
    signature = create_dig_sig(valid_num)
    info = { "digsig" : signature , "valid_num" : valid_num }
    req = requests.post("https://0.0.0.0:1234/voter_name", data=info, verify=False)

# Create signature of CTF client through importing private key of CTF
def create_dig_sig(message):
    f = open("./keys/MMCTF", "r") # get ctf's private key
    key = RSA.import_key(f.read())
    h = SHA.new()
    h.update(bytearray(message,'utf8'))
    signer = PKCS.new(key)
    signature = signer.sign(h)
    return b64encode(signature)

# Verify signature using CLA's PUBLIC key
def verify_dig_sig(signature, message):
    f = open("./keys/MMCLA.pub", "r") # get cla's public key
    key = RSA.import_key(f.read())
    h = SHA.new()
    h.update(bytearray(message,'utf8'))
    verifier = PKCS.new(key)
    if verifier.verify(h, b64decode(signature)):
        return True
    else:
        print("\n\n\n\n\nPCKS IS NOT A MATCH\n\n\n\n\n")
        return False

# Check to see if voter's vote is valid
def validate_voter(PreRegCode, valid_num, vote):
    eligible = False
    Voted = False
    nerr = False
    print("\n\n\n\n")
    print(validation_numbers)
    print("\n\n\n\n")
    if not PreRegCode or not valid_num or vote is None:
        return "Please fill all of the fields."
    # If the randomNumGenerated of the person voting right now is already listed, they've already voted
    elif PreRegCode in voters:
        return "Your registration code is already taken, please try again."
    
    elif valid_num in validation_numbers:
        
        # If valid number in the list hasn't voted yet
        if validation_numbers[valid_num]["votedYet"] == False:
            if validation_numbers[valid_num]["reg_Code"]!=PreRegCode:
                return "PreReg Code and ValidationCode are not for the same user"
            info = { "valid_num" : valid_num, "vote" : vote }
            voters[PreRegCode] = info # store voting info
            votes[vote] = votes[vote] + 1 # increase count of votes
            validation_numbers[valid_num]["votedYet"] = True # update: voter has voted
            eligible = True # Setting status to send result message later
        else:
            Voted = True # Has already voted CHECK TO SEE IF Voter Votes ONCE
    else:
       return "validation number does not exist"

    # Decide what to display on result web page by sending back message
    if eligible == True:
        party = ""
        if vote == "Lib":
            party = "Liberal Party"
        elif vote == "Con":
            party = "Conservative Party"
        elif vote == "NDP":
            party = "NDP"
        return PreRegCode + ", thanks for voting for the " + party + "!"
    elif Voted == True:
        return "You have already voted."
    else:
        return "You are not registered to vote."

# Generate random string for csrf
def generate_random_str():
    lst = [random.choice(string.ascii_letters + string.digits)
      for n in range(30)]
    rand = "".join(lst)
    return rand

# CSRF check before each request
@ctf.before_request
def csrf_protect():
    if request.method == "POST" and request.path != "/add_voter" and request.path != "/get_name":
        token = session["csrf_token"]
        if not token or token != request.form["csrf_token"]:
            return "CSRF"

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = generate_random_str()
    return session["csrf_token"]

ctf.jinja_env.globals["csrf"] = generate_csrf_token() #global csrc token

if __name__ == "__main__":
    ctf.run(host="0.0.0.0", port=4321, debug=True, threaded=True, ssl_context=context)
