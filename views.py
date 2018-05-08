import collections
import configparser
import os
import logging
import shutil
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
THRESHOLDS = {1: 3, 2: 3, 3: 4}
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WORD_LIST_PATH = os.path.join(SCRIPT_DIR, 'words.txt')
SHARE1_PATH = os.path.join(SCRIPT_DIR, 'share1.txt')
VAULT_PATH = os.path.join(SCRIPT_DIR, 'vault.enc')

ERROR_MESSAGES = collections.defaultdict(lambda: 'Encountered error {type!r}: {message}.')
ERROR_MESSAGES['share1_missing'] = ('Could not find the horcrux stored on the server. You will need '
                                    'to enter 1 additional horcrux.')
ERROR_MESSAGES['share1_permissions'] = ('Could not read the horcrux stored on the server. You will '
                                        'need to enter 1 additional horcrux.')
ERROR_MESSAGES['single_word'] = ('Invalid words {value!r}. Looks like a single word. Make sure to '
                                 'put spaces between the words.')
ERROR_MESSAGES['invalid_word'] = 'Invalid word {value!r}. Did you type it correctly?'
ERROR_MESSAGES['invalid_senary'] = 'Error converting words to decryption key.'
ERROR_MESSAGES['too_few_shares'] = 'Too few horcruxes entered. I only saw {value!r}.'
ERROR_MESSAGES['binary'] = 'Wrong input type. Are you sure you selected the right version?'
ERROR_MESSAGES['inconsistent'] = 'Inconsistent codes. Did you enter one of them twice?'
ERROR_MESSAGES['syntax'] = ('Invalid code(s). Make sure there was no typo, and that you included '
                            'the number and dash in front of each one.')
ERROR_MESSAGES['lengths'] = ("Invalid code(s). Were they different lengths? Check to make sure you "
                             "didn't miss a character.")
ERROR_MESSAGES['ssss_missing'] = ('Could not combine the horcruxes. The "ssss" program may not be '
                                  'installed on the server.')
ERROR_MESSAGES['ssss_command'] = ('Could not combine the horcruxes. There was a problem executing '
                                  'the "ssss" program on the server.')
ERROR_MESSAGES['ssss_output_unknown'] = ('Could not combine the horcruxes. There was a problem '
                                         'interpreting the output of the "ssss" program.')
ERROR_MESSAGES['wrong_key'] = ('Combined the horcruxes, but got the wrong output. Check for typos '
                               'in the codes you entered (including in the numbers before the dashes).')
ERROR_MESSAGES['empty_vault'] = ('Successfully combined the horcruxes and decrypted the vault file '
                                 'on the server, but it was empty.')


class HorcruxError(Exception):
  def __init__(self, type, message=None, **kwargs):
    self.type = type
    self.message = message
    if self.message is None:
      self.args = (self.type,)
    else:
      self.args = (self.message,)
    for key, value in kwargs.items():
      setattr(self, key, value)


##### Views #####

def main(request):
  return render(request, 'horcrux/main.tmpl')


def shares(request):
  params = QueryParams()
  params.add('version', type=int, choices=(1, 2, 3))
  params.parse(request.GET)
  if not params['version']:
    return HttpResponseRedirect(reverse('horcrux:main'))
  threshold = THRESHOLDS[params['version']]
  share_nums = range(1, threshold+1)
  context = {'version':params['version'], 'share_nums':share_nums}
  return render(request, 'horcrux/shares.tmpl', context)


def combine(request):
  params = QueryParams()
  params.add('version', type=int, choices=(1, 2, 3))
  params.parse(request.POST)
  error = None
  secrets = {'lastpass_email':settings.PERSONAL_EMAIL, 'accounts_link':settings.ACCOUNTS_LINK}
  threshold = THRESHOLDS[params['version']]
  try:
    # Gather the shares.
    shares = gather_shares(params, threshold, WORD_LIST_PATH)
    if params['version'] == 1:
      secrets['lastpass'] = combine_shares(shares, threshold, hex=False)
    elif params['version'] == 2:
      if os.path.exists(WORD_LIST_PATH):
        words_hex = combine_shares(shares, threshold, hex=True)
        word_map = convert.read_word_list(WORD_LIST_PATH)
        try:
          words = convert.hex_to_words(words_hex, word_map, group_length=GROUP_LENGTH)
          secrets['lastpass'] = ' '.join(words)
        except ValueError:
          error = ('Combined horcruxes to get {!r}, but could not convert to the actual password.'
                   .format(words_hex))
      else:
        error = "Couldn't find word list file on the server."
      #TODO: Detect if the password is just numbers, which indicates the user entered version 1 codes.
    elif params['version'] == 3:
      # Read in the share stored on the server, if needed.
      if len(shares) < threshold:
        try:
          share1 = read_share(SHARE1_PATH)
          shares.append(share1)
        except HorcruxError:
          if len(shares) < threshold:
            raise
      # Combine the shares and get the passwords from the vault.
      vault_password = combine_shares(shares, threshold, hex=True)
      if os.path.exists(VAULT_PATH):
        plaintext = decrypt_vault(VAULT_PATH, vault_password)
        secrets.update(parse_vault(plaintext))
      else:
        error = ("Couldn't find encrypted vault file on the server, but successfully combined the "
                 "horcruxes to obtain its password: {!r}".format(vault_password))
    else:
      return HttpResponseRedirect(reverse('horcrux:main'))
  except HorcruxError as exception:
    log.error('HorcruxError {!r}: {}'.format(exception.type, exception.message))
    error = ERROR_MESSAGES[exception.type].format(**vars(exception))
    log.error(error)
  plural = params['version'] > 2
  context = {'version':params['version'], 'secrets':secrets, 'plural':plural, 'error':error}
  return render(request, 'horcrux/combine.tmpl', context)


##### Functions #####


def get_hex_shares(params):
  hex_shares = []
  for i in range(15):
    share_key = 'share{}'.format(i)
    if share_key in params:
      share_value = params[share_key].strip()
      if share_value:
        hex_shares.append(share_value)
  return hex_shares


def get_word_shares(params):
  word_shares = []
  share_ids = []
  for i in range(15):
    share_key = 'share{}-words'.format(i)
    share_id_key = 'share{}-id'.format(i)
    if share_key in params:
      share_value = params[share_key].strip()
      share_id_value = params.get(share_id_key, '').strip()
      if share_value:
        if ' ' not in share_value:
          raise HorcruxError('single_word', 'Invalid words {!r}. No spaces detected.',
                             value=share_value)
        word_shares.append(share_value)
        share_ids.append(share_id_value)
  return share_ids, word_shares


def gather_shares(params, threshold, word_list_path):
  hex_shares = get_hex_shares(params)
  share_ids, word_shares = get_word_shares(params)
  if len(hex_shares) >= threshold:
    return hex_shares
  elif len(hex_shares) > len(word_shares):
    return hex_shares
  else:
    return word_shares_to_hex(word_shares, share_ids, word_list_path)


def word_shares_to_hex(shares_words, share_ids, word_list_path):
  reverse_word_map = convert.read_word_list(word_list_path, reverse=True)
  max_len = 0
  shares_hex = []
  for words in shares_words:
    try:
      hex = convert.words_to_hex(words.split(), reverse_word_map, base=1)
    except ValueError as error:
      raise HorcruxError('invalid_senary', 'Problem converting senary {!r} to hex.'.format(error.value),
                         value=error.value)
    except KeyError as error:
      raise HorcruxError('invalid_word', 'Word {!r} not found in word list.'.format(error.value),
                         value=error.value)
    max_len = max(max_len, len(hex))
    shares_hex.append(hex)
  for i in range(len(shares_hex)):
    shares_hex[i] = convert.pad_number(shares_hex[i], width=max_len, base=0)
  shares = []
  for share_id, share_hex in zip(share_ids, shares_hex):
    shares.append('{}-{}'.format(share_id, share_hex))
  return shares


def read_share(share_path):
  try:
    with open(share_path) as share_file:
      share = share_file.readline().strip()
  except FileNotFoundError:
    raise HorcruxError('share1_missing', 'Share file {!r} not found.'.format(share_path))
  except PermissionError:
    raise HorcruxError('share1_permissions', 'Share file {!r} not read because of permissions.'
                                             .format(share_path))
  return share


def combine_shares(shares, threshold, hex=True):
  if len(shares) < threshold:
    raise HorcruxError('too_few_shares', 'Received {} shares when {} are needed.'
                       .format(len(shares), threshold), value=len(shares), value2=threshold)
  command = 'ssss-combine'
  if not shutil.which(command):
    raise HorcruxError('ssss_missing', 'Could not find the command {!r}.'.format(command))
  shares_bytes = [bytes(share, 'utf8') for share in shares]
  stdin = b'\n'.join(shares_bytes)+b'\n'
  if hex:
    command_line = [command, '-x']
  else:
    command_line = [command]
  command_line += ['-t', str(threshold)]
  try:
    process = subprocess.Popen(command_line, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate(input=stdin)
  except subprocess.SubprocessError as error:
    raise HorcruxError('ssss_command', 'Problem executing ssss: {}'.format(error.args[0]))
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
      elif 'different security levels' in line:
        raise HorcruxError('lengths', 'Shares have different security levels (lengths).')
    elif line.startswith('Resulting secret: '):
      secret = line[18:]
  if secret is None:
    raise HorcruxError('ssss_output_unknown', 'No valid output found.')
  else:
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
  if not vault_contents or not vault_contents.strip():
    raise HorcruxError('empty_vault', 'Encrypted vault was decrypted, but empty.')
  config = configparser.RawConfigParser()
  config.read_string(vault_contents)
  secrets = {}
  secrets['lastpass'] = config.get('passwords', 'lastpass')
  secrets['veracrypt'] = config.get('passwords', 'veracrypt')
  return secrets
