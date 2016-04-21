from Crypto import Random
from Crypto.Cipher import AES
import base64
import os
from hashlib import sha256 as sha
import json
import argparse

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def setPassword(password, key, salt):
    password = pad(password)
    password = password.encode('utf-8')
    AESKey = "".join([key, salt])
    AESKey = sha(AESKey.encode()).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(AESKey, AES.MODE_CFB, iv)
    pwd = iv + cipher.encrypt(password)
    return base64.encodebytes(pwd).decode('utf-8')

def getPassword(password, key, salt):
    passwd = base64.decodebytes(password.encode())
    AESKey = "".join([key, salt])
    AESKey = sha(AESKey.encode()).digest()
    iv = passwd[:AES.block_size]
    cipher = AES.new(AESKey, AES.MODE_CFB, iv )
    passwd = cipher.decrypt(passwd[AES.block_size:]).decode()
    passwd = unpad(passwd)
    return passwd

def getFile(f_name):
    content = None
    with open(f_name) as f:
        content = f.read()
        pass
    try:
        return json.loads(content)
    except:
        return {}
    pass

def add(master, passwds, password, name):
    salt = str(Random.new().read(32))
    password = dict(passwd=setPassword(password, master, salt), salt=salt)
    passwds[name] = password
    pass

def get(master, passwds, _, name):
    info = passwds.get(name, None)
    if info is None:
        print("Account not found")
        pass
    pwd = getPassword(info["passwd"], master, info["salt"])
    salt = str(Random.new().read(32))
    password = dict(passwd=setPassword(pwd, master, salt), salt=salt)
    passwds[name] = password
    print(pwd)

def del_(master, passwds, _, name):
    info = passwds.get(name)
    if info is None:
        print("Account not found")
        pass
    del passwds[name]
    pass

def save(passwds, f):
    content = json.dumps(passwds)
    with open(f, "w") as fi:
        fi.write(content)
        pass
    pass

def main(cmds, passwd):
    actions = {
        "add": add,
        "get": get,
        "del": del_
    }
    home = os.environ['HOME']
    f = os.path.join(home, ".manager/passwords.json")
    try:
        passwds = getFile(f)
        pass
    except:
        with open(f, "w+") as f:
            pass
        passwds = getFile(f)
        pass
    cmd = "a"
    masterPwd = input("Enter Master Password: ")
    masterPwd = sha(masterPwd.encode()).hexdigest()
    cmd = cmds.command
    accountName = cmds.account
    action = actions.get(cmd)
    if action is None:
        print("undefined action must be: add, get, del")
        return
    action(masterPwd, passwds, passwd, accountName)
    save(passwds, f)
    pass

parser = argparse.ArgumentParser(description='A Commandline Password manager')
parser.add_argument('command', metavar='CMD', type=str, help='The command to run, add, get del')

parser.add_argument('account', metavar='NAME', type=str, help='The name of the account')
parser.add_argument("-p", '--password', metavar='PASSWD', type=str, default="", help='The password to save')
args = parser.parse_args()
password = args.password
if args.command == "add" and password == "":
    password = input("enter password: ")
    pass

main(args, password)
