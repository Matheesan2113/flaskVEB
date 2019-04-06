### flaskVEB
# Virtual Election Booth

***REMEMBER TO NEVER PUSH IMPORTANT KEYS/CERTIFICATES TO GITHUB***

I've left a folder of keys I don't use so feel free to use them

TO run, pip3 install flask and try out the following sets of commands in individual terminal shells

Menu Server:


export FLASK_APP=menu.py

flask run --host=0.0.0.0 --port=5000 --with-threads --cert ./keys/server.pem --key ./keys/private_key.pem


CLA Server:

export FLASK_APP=cla.py

flask run --host=0.0.0.0 --port=1234 --cert ./keys/server.pem --key ./keys/private_key.pem

CTF Server:

export FLASK_APP=ctf.py

flask run --host=0.0.0.0 --port=4321 --with-threads --no-debugger  --cert ./keys/server.pem --key ./keys/private_key.pem


