#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode
from flask import Flask
from flask import request
import time

KEY = "privkey.pem"
app = Flask(__name__)

@app.route("/session",methods=['POST'])
def session():
    rensession = request.form['ensession']
    rsa = RSA.importKey(open(KEY,"rb").read())
    session = rsa.decrypt(b64decode(rensession))
    print(session.hex()[382:].upper())
    return session.hex()[382:].upper()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=3000)
