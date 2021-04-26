#!/usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64decode
from base64 import b64encode
from flask import Flask,send_from_directory
from flask import request
import os
import time

KEY = "privkey.pem"
app = Flask(__name__)
DOWNLOAD_DIRECTORY = os.getcwd() + "/script/"

@app.route('/file/<path:path>',methods = ['GET'])
def get_files(path):
    """Download a file."""
    try:
        return send_from_directory(DOWNLOAD_DIRECTORY, path, as_attachment=True)
    except FileNotFoundError:
        abort(404)

@app.route("/session",methods=['POST'])
def session():
    rensession = request.form['ensession']
    rsa = RSA.importKey(open(KEY,"rb").read())
    session = rsa.decrypt(b64decode(rensession))
    print(session.hex()[382:].upper())
    return session.hex()[382:].upper()

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=8080,debug = True)
