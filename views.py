import os
import logging
import subprocess
from django.conf import settings
from django.shortcuts import render
from django.urls import reverse
from django.http import HttpResponseRedirect
from . import convert
from utils import QueryParams
log = logging.getLogger(__name__)

# How many dice rolls per word.
GROUP_LENGTH = 5
# How many horcruxes are required to recover the secret. Keys are versions.
THRESHOLDS = {1: 3, 2: 3}
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
WORD_LIST_PATH = os.path.join(SCRIPT_DIR, 'words.txt')

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
  params.add('version', type=int, choices=(1, 2))
  params.parse(request.GET)
  log.info(str(params.keys()))
  if not params['version']:
    return HttpResponseRedirect(reverse('horcrux:main'))
  context = {'version':params['version']}
  return render(request, 'horcrux/shares.tmpl', context)


def combine(request):
  params = QueryParams()
  params.add('version', type=int, choices=(1, 2))
  params.parse(request.POST)
  error = None
  password = None
  shares = []
  for i in range(15):
    share_key = 'share{}'.format(i)
    if share_key in params:
      shares.append(params[share_key])
  threshold = THRESHOLDS[params['version']]
  if params['version'] == 1:
    try:
      password = combine_shares(shares, threshold, hex=False)
    except HorcruxError as exception:
      if exception.type == 'binary':
        error = 'Wrong input type. Are you sure you selected the right version?'
      else:
        error = 'Encountered error {!r}.'.format(exception.type)
  elif params['version'] == 2:
    words_hex = combine_shares(shares, threshold, hex=True)
    words = convert.hex_to_words(words_hex, WORD_LIST_PATH, group_length=GROUP_LENGTH)
    password = ' '.join(words)
  else:
    return HttpResponseRedirect(reverse('horcrux:main'))
  context = {'password':password, 'error':error}
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
        warnings.append('binary')
      elif "couldn't get memory lock" in line:
        warnings.append('memlock')
    elif line.startswith('Resulting secret: '):
      secret = line[18:]
  if 'binary' in warnings:
    raise HorcruxError('binary', 'Input was binary data, but mode was set to ascii.')
  return secret
