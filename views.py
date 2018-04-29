import configparser
import os
import logging
import subprocess
from django.conf import settings
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponseRedirect
from . import convert
from utils import QueryParams
from utillib import crypto
log = logging.getLogger(__name__)

# How many dice rolls per word.
GROUP_LENGTH = 5
# How many horcruxes are required to recover the secret. Keys are versions.
THRESHOLDS = {1: 3, 2: 3, 3: 3}
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WORD_LIST_PATH = os.path.join(SCRIPT_DIR, 'words.txt')
VAULT_PATH = os.path.join(SCRIPT_DIR, 'vault.enc')


class HorcruxError(Exception):
  def __init__(self, type, message=None):
    self.type = type
    self.message = message
    if self.message is None:
      self.args = (self.type,)
    else:
      self.args = (self.message,)


##### Views #####

def main(request):
  return render(request, 'horcrux/main.tmpl')


def shares(request):
  params = QueryParams()
  params.add('version', type=int, choices=(1, 2, 3))
  params.parse(request.GET)
  log.info(str(params.keys()))
  if not params['version']:
    return HttpResponseRedirect(reverse('horcrux:main'))
  context = {'version':params['version']}
  return render(request, 'horcrux/shares.tmpl', context)


def combine(request):
  params = QueryParams()
  params.add('version', type=int, choices=(1, 2, 3))
  params.parse(request.POST)
  error = None
  password = None
  password2 = None
  shares = []
  for i in range(15):
    share_key = 'share{}'.format(i)
    if share_key in params:
      shares.append(params[share_key])
  threshold = THRESHOLDS[params['version']]
  try:
    if params['version'] == 1:
      password = combine_shares(shares, threshold, hex=False)
    elif params['version'] == 2:
      if os.path.exists(WORD_LIST_PATH):
        words_hex = combine_shares(shares, threshold, hex=True)
        words = convert.hex_to_words(words_hex, WORD_LIST_PATH, group_length=GROUP_LENGTH)
        password = ' '.join(words)
      else:
        error = "Couldn't find word list file on the server."
    elif params['version'] == 3:
      if os.path.exists(VAULT_PATH):
        vault_password = combine_shares(shares, threshold, hex=True)
        plaintext = decrypt_vault(VAULT_PATH, vault_password)
        password, password2 = parse_vault(plaintext)
      else:
        error = "Couldn't find encrypted vault file on the server."
    else:
      return HttpResponseRedirect(reverse('horcrux:main'))
  except HorcruxError as exception:
    if exception.type == 'binary':
      error = 'Wrong input type. Are you sure you selected the right version?'
    elif exception.type == 'inconsistent':
      error = 'Inconsistent codes. Did you enter one of them twice?'
    elif exception.type == 'syntax':
      error = ('Invalid code(s). Make sure there was no typo, and that you included the number and '
               'dash in front of each one.')
    elif exception.type == 'wrong_key':
      error = 'Incorrect key. Check for typos in the codes you entered.'
    else:
      error = 'Encountered error {!r}: {}.'.format(exception.type, exception.message)
  if error:
    log.error(error)
  context = {'version':params['version'], 'password':password, 'password2':password2, 'error':error}
  return render(request, 'horcrux/combine.tmpl', context)


##### Functions #####

def combine_shares(shares, threshold, hex=True):
  shares_bytes = [bytes(share, 'utf8') for share in shares]
  stdin = b'\n'.join(shares_bytes)+b'\n'
  if hex:
    command = ['ssss-combine', '-x']
  else:
    command = ['ssss-combine']
  process = subprocess.Popen(command + ['-t', str(threshold)],
                             stdin=subprocess.PIPE, stderr=subprocess.PIPE)
  stdout, stderr = process.communicate(input=stdin)
  return parse_ssss_output(stderr)


def parse_ssss_output(stderr_bytes):
  secret = None
  warnings = []
  stderr = str(stderr_bytes, 'utf8')
  for line in stderr.splitlines():
    if line.startswith('WARNING: '):
      if 'binary data detected' in line:
        raise HorcruxError('binary', 'Input was binary data, but mode was set to ascii.')
      elif "couldn't get memory lock" in line:
        warnings.append('memlock')
    elif line.startswith('FATAL: '):
      if 'shares inconsistent' in line:
        raise HorcruxError('inconsistent', 'Inconsistent combination of shares.')
      elif 'invalid syntax' in line:
        raise HorcruxError('syntax', 'Invalid shares.')
      elif 'invalid share' in line:
        raise HorcruxError('syntax', 'Invalid shares.')
    elif line.startswith('Resulting secret: '):
      secret = line[18:]
  return secret


def decrypt_vault(vault_path, vault_password):
  key = crypto.derive_key(vault_password)
  with open(vault_path, 'rb') as vault_file:
    ciphertext = vault_file.read()
  try:
    return crypto.decrypt(ciphertext, key)
  except ValueError as error:
    if error.args[0] == 'Wrong key.':
      raise HorcruxError('wrong_key', 'Wrong key.')
    else:
      raise HorcruxError(type(error).__name__, error.args[0])


def parse_vault(vault_contents):
  #TODO: Catch exceptions due to incorrect format.
  config = configparser.RawConfigParser()
  config.read_string(vault_contents)
  lastpass = config.get('passwords', 'lastpass')
  veracrypt = config.get('passwords', 'veracrypt')
  return lastpass, veracrypt
