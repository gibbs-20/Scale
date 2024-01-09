import json
import time
import os
import sys
import random
import secrets
import hashlib

global username

do_clear = True

class dict_tools():

  def write_dict(self, filename, data):
    with open(filename, "w") as f:
      json.dump(data, f)

  def read_dict(self, filename):
    try:
      with open(filename, "r") as f:
        data = json.load(f)
      return data
    except (FileNotFoundError, json.JSONDecodeError):
      return None


def cmd():
  while True:
    cmd = input("  >>> ")
    if cmd == 'exit':
      duh()
    else:
      try:
        exec(cmd)
      except:
        print('error')


def clear():
  if do_clear:
    os.system('clear')
    return
  else:
    return


def val():
  if authenticated == True:
    return
  else:
    login()


def terminate():
  sys.exit()


def calc():
  val()
  while True:
    calc = input("  >>> ")
    if calc == '2+2':
      print('5')
    elif calc == 'exit':
      duh()
    else:
      exec(f"print(" + calc + ")")


def login():
  global authenticated
  authenticated = False
  global username
  username = input("Enter your username: ")
  password = input("Enter your password: ")
  clear()
  # Read the credentials file
  try:
    with open("credentials.txt", "r") as file:
      credentials = file.readlines()
  except FileNotFoundError:
    print('File not found')
    return

  # Check if the username and password match
  global auth
  for cred in credentials:
    hashp, aauth = cred.strip().split(",")
    auth = int(aauth)
    if hash_password(username, password)== hashp:
      print("Login successful!")
      authenticated = True
      return

  # If no match is found
  print("Invalid username or password. Please try again.")


def hash_password(password: str, user: str) -> str:
  # Checking if the password is empty
  if not password:
      raise ValueError("Password cannot be empty.")

  # Generating a random salt if not provided
  if user is None:
      user = os.urandom(16)
  else:
      # Converting the user parameter to bytes if not already
      if not isinstance(user, bytes):
          user = user.encode()

  # Hashing the password using the salt
  hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), user, 100000)

  # Returning the hashed password as a hexadecimal string
  return hashed_password.hex()


def register():
  val()
  username = input("Choose a username: ")
  password = input("Choose a password: ")
  uauth = input('Choose user privileges (1-5): ')

  try:
    uauth = int(uauth)
    if not 1 <= uauth <= 5:
      raise ValueError('User privileges should be between 1 and 5.')
  except ValueError:
    print('Invalid input for user privileges.')
    return

  # Open the credentials file in append mode and store the new credentials
  if input('Are you sure you want to register? (y/n)').lower.startswith('n'):
    duh()
  else:
    clear()
    with open("credentials.txt", "a") as file:
      file.write('\n' +  hash_password(username, password) + ',' + str(uauth) + "\n")
    print("Registration successful!")
    return


def duh():
  # dynamic user home
  if authenticated == False:
    login()
  #greets the user
  print(f'Welcome {username}!')

  #loops through tools and prints ones you have sufficient privileges to access
  a_tools = []

  for i in tools:
    if tools[i]['auth'] <= auth:
      a_tools.append(i)
      print(i)

  #asks for tool
  while True:
    tool = input('What tool would you like to use? ').lower()
    for a in a_tools:
      if tool == a:
        break
    else:
      print('Tool not found')
      continue
    break

  eval(tools[tool]['func'] + '()')


tools = {
    'cmd': {
      'auth': 5,
      'func': 'cmd'
    },
    'log out': {
        'auth': 1,
        'func': 'terminate'
    },
    'register': {
        'auth': 5,
        'func': 'register',
    },
    'calc': {
        'auth': 1,
        'func': 'calc',
    },
}


login()
duh()
