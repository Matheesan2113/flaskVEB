from Crypto.Signature import PKCS1_PSS as PKCS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from flask import Flask, render_template, request
from OpenSSL import SSL
import string, random, requests
print(RSA.__file__)
# SSL setup
context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file("./keys/private_key.pem")
context.use_certificate_file("./keys/server.pem")
#Flask Framework Initialization
cla = Flask(__name__)
# stores CSRF token
session = {}
# Voters List
eligible_voters = { "100" : ["matt", "mano", False],
                    "200" : ["ragu", "sauce", False],
                    "300" : ["sianara", "migos", False],
                    "400" : ["old", "town", False],
                    "500" : ["tent", "acion", False],
                    "600" : ["k", "d", False],
                    "700" : ["lb", "j", False],
                    "800" : ["s", "c", False],
                    "900" : ["g", "a", False]
                  }

# Routes for Flask

# When called, Present user with homepage so user can register
@cla.route("/")
def main():
    return render_template("cla_register.html")

# Validate whether or not the form is filled out accuratley and fully
@cla.route("/validation", methods=["POST"])
def validation():
    if request.method == "POST":
        #sends validation name and number to CTF
        message = validate_voters(request.form["fname"], request.form["lname"], request.form["regCode"])
        return render_template("cla_validation.html", message = message) # Returns web result page with validation number

# verifies signature of form and sends name to CTF
@cla.route("/voter_name", methods=["POST"])
def get_name():
    if request.method == "POST":
        signature = request.form["digsig"]
        valid_num = request.form["valid_num"]
        name = ""
        if verify_dig_sig(signature, valid_num):
            for voter in eligible_voters: #iterate through every possible voter
                if eligible_voters[voter][2] == True and eligible_voters[voter][3] == valid_num: #If match exists in voter table
                    name = eligible_voters[voter][0] + " " + eligible_voters[voter][1] 
                    send_name(name) # gather and send name of matched valid_num to results table of voters that voted
                    break
    return "voter_name"

# Specific method handling the sending of the name attached with digital signature of CLA
def send_name(name):
    signature = create_dig_sig(name)
    info = { "digsig" : signature , "name" : name }
    requests.post("https://0.0.0.0:4321/get_name", data=info, verify=False) # Send with CLA Private Sig to CTF

# When a voter is registered, the possible voters that can vote now, have their validation numbers sent to CTF w DigSig
def send_valid_num(validation_num,regCode):
    signature = create_dig_sig(validation_num)
    info = { "digsig" : signature , "valid_num" : validation_num , "reg_Code": regCode}
    requests.post("https://0.0.0.0:4321/add_voter", data=info, verify=False)

# Create signature of CLA client through importing private key of CLA
def create_dig_sig(message):
    f = open('./keys/MMCLA','r')
    key = RSA.import_key(f.read())
    h = SHA.new()
    h.update(bytearray(message,'utf8')) # Cannot use string here because it needs to be in byte format
    signer = PKCS.new(key)
    signature = signer.sign(h) # bundle private key with message
    return b64encode(signature) #Encode with B64

# Verify signature using CTF's PUBLIC key
def verify_dig_sig(signature, message):
    f = open("./keys/MMCTF.pub", "r") # get ctf's public key
    key = RSA.import_key(f.read())
    h = SHA.new()
    h.update(bytearray(message,'utf8'))
    verifier = PKCS.new(key)
    if verifier.verify(h, b64decode(signature)): # Check to see if b64 decoded signature is correct
        return True
    else:
        return False

# random keygen of length "l"
def generate_valid_num(l):
    rnd = [random.choice(string.ascii_letters + string.digits)
      for n in range(l)]
    rand = "".join(rnd)
    return rand

# Random String gen to create csrf token
def generate_random_str():
    rnd = [random.choice(string.ascii_letters + string.digits)
      for n in range(30)]
    rand = "".join(rnd)
    return rand

# After user fills out form and clicks register, this method is called and returns a message for result page
def validate_voters(fname, lname, regCode):
    eligible = False # isvoter? eligible : Not
    registered = False # hasVoter? Registered: Not
    validation_num = None
    if not fname or not lname or not regCode:
        return "Please fill all of the fields."
    # If registration Code exists in eligible voters list, voter is selected
    elif regCode in eligible_voters:
        voter = eligible_voters[regCode]
        if voter[0] == fname and voter[1] == lname: # If first and last name match..
            if voter[2] == False: # If voter hasn't voted yet
                validation_num = generate_valid_num(15) # Generate rndm # for registered voter to use with CTF
                voter.append(validation_num) # add validation num to registered voter list
                send_valid_num(validation_num, regCode) # send validation number to CTF
                voter[2] = True # update: voter has alredy registered so they cannot vote again
                eligible = True # Set so that following structure can determine what message to return
                print(eligible_voters)
            else:
                registered = True
# Decide on message to return to validation page
    if eligible == True and validation_num is not None:
        return fname + " " + lname + ", your validation number is: " + str(validation_num)
    elif registered == True:
        return "You have already registered."
    else:
        return "You are not eligible to register."

# CSRF check before each request
@cla.before_request
def csrf_protect():
    if request.method == "POST" and request.path != "/voter_name":
        token = session["csrf_token"]
        if not token or token != request.form["csrf_token"]:
            return "CSRF"

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = generate_random_str()
    return session["csrf_token"]

cla.jinja_env.globals["csrf"] = generate_csrf_token() #global csrc token

#Flask Run command on port 1234
if __name__ == "__main__":
    cla.run(host="0.0.0.0", port=1234, debug=True, threaded=True, ssl_context=context)
