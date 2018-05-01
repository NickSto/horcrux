#!/usr/bin/env python3
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
import os
import sys
import math
import getpass
import argparse

WORDLIST_NAME = 'words.txt'
HEX_DIGITS = '0123456789ABCDEFabcdef'
SENARY_DIGITS = '0123456'
USAGE = "%(prog)s [options]"
DESCRIPTION = """Convert diceware rolls to words and back again, as well as compressing them into
hexadecimal representation."""
EPILOG = """There is the possibility of losing a word when converting from hex or senary. Basically,
when the senary representation has leading zeros (dice rolls of 1), they're lost upon conversion
intenally to an integer. So we have to guess how many zeros to add back in later. In practice, this
isn't an issue, since if each word is made of 5 rolls, we know we just have to pad it out to a
multiple of 5. Words are only lost if there are actually five 1's in a row, which has a 1 in 7776
chance of happening. But if you're using a really low --group-length, beware."""


def make_argparser():
  parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EPILOG)
  parser.add_argument('input', nargs='*',
    help='The input hex, senary, or words. Can be given in multiple arguments (e.g. one argument '
         'per word, or senary group).')
  parser.add_argument('-i', '--in-format', choices=('senary', 'hex', 'words'),
    help='Specify the input format. Will attempt to detect it if not given. Senary is a base 6 '
         'number, except using digits 1-6. So "21445", for example.')
  parser.add_argument('-o', '--out-format', choices=('senary', 'hex', 'words'))
  parser.add_argument('-e', '--echo', action='store_true',
    help='When entering the input interactively, show it on-screen instead of hiding it.')
  parser.add_argument('-r', '--random', action='store_true',
    help='Use random input instead of a user-supplied number. Gets randomness from os.urandom() '
         '(/dev/urandom on Linux).')
  parser.add_argument('-d', '--senary-digits', type=int,
    help='The number of senary digits the output should have (its "width").')
  parser.add_argument('-l', '--group-length', type=int, default=5,
    help='The number of senary digits per word. Default: %(default)s')
  parser.add_argument('-n', '--num-words', type=int, default=6,
    help='When generating random input, create enough for this many words.')
  parser.add_argument('-w', '--words', action='store_true',
    help='Print words in addition to the selected --out-format.')
  parser.add_argument('-W', '--word-list',
    help='Use this Diceware-formatted word list. Defaults to a file in the script\'s directory '
         'named "{}".'.format(WORDLIST_NAME))
  return parser


def main(argv):
  parser = make_argparser()
  args = parser.parse_args(argv[1:])

  if args.words or args.in_format == 'words' or args.out_format == 'words':
    if args.word_list:
      word_list = args.word_list
    else:
      script_dir = os.path.dirname(os.path.realpath(__file__))
      word_list = os.path.join(script_dir, WORDLIST_NAME)
    if not os.path.isfile(word_list):
      raise IOError('Word list "{}" not found.'.format(word_list))

  if args.input:
    input_raw = ' '.join(args.input)
  elif args.random:
    if args.senary_digits:
      senary_digits = args.senary_digits
    else:
      senary_digits = args.num_words * args.group_length
    input_raw = get_rand_senary(senary_digits, base=1)
  elif args.echo:
    sys.stdout.write('Input: ')
    input_raw = sys.stdin.readline().rstrip('\r\n')
  else:
    try:
      input_raw = getpass.getpass(prompt='Input: ')
    except EOFError:
      print()
      return 1

  # Detect input format, if needed.
  if args.in_format:
    in_format = args.in_format
  elif args.random:
    in_format = 'senary'
  else:
    in_format = detect_base(input_raw)
    sys.stderr.write('Input base not specified. Inferred input type is {}.\n'.format(in_format))

  if in_format == 'words':
    input = input_raw
  else:
    input = input_raw.replace(' ', '')

  if not input:
    fail('Error: input is empty.')

  # What should the output format be?
  if args.out_format:
    out_format = args.out_format
  elif args.random:
    out_format = 'senary'
  elif in_format == 'hex':
    out_format = 'senary'
  elif in_format == 'senary':
    out_format = 'hex'
  elif in_format == 'words':
    out_format = 'senary'

  # Convert the input into base 1 senary.
  if in_format == 'senary':
    senary = input
  elif in_format == 'hex':
    senary = hex_to_senary(input, width=args.senary_digits, base=1)
  elif in_format == 'words':
    words = input.split()
    reverse_word_map = read_word_list(word_list, reverse=True)
    senary = words_to_senary(words, reverse_word_map)

  senary = pad_number(senary, width=args.senary_digits, group_length=args.group_length, base=1)

  # Convert the base 1 senary into the output format.
  if out_format == 'senary':
    output = senary
  elif out_format == 'hex':
    output = senary_to_hex(senary, base=1)
  elif out_format == 'words':
    word_map = read_word_list(word_list)
    words = senary_to_words(senary, word_map, group_length=args.group_length)
    output = ' '.join(words)

  print(output)

  if args.words and out_format != 'words':
    word_map = read_word_list(word_list)
    words = senary_to_words(senary, word_map, group_length=args.group_length)
    print(' '.join(words))


def detect_base(input):
  base = 'senary'
  for char in input.replace(' ', ''):
    if char not in HEX_DIGITS:
      base = 'words'
    elif char not in SENARY_DIGITS:
      if base != 'words':
        base = 'hex'
  return base


def base1_to_base0(senary_str_base1):
  # Traditionally the senary digits are 1-6. We need it in 0-5.
  senary_str_base0 = ''
  for digit_str in senary_str_base1:
    digit = int(digit_str)
    senary_str_base0 += str(digit-1)
  return senary_str_base0


def senary_to_hex(senary_str, width=None, base=0):
  if base == 1:
    senary = base1_to_base0(senary_str)
  else:
    senary = senary_str
  decimal = int(senary, 6)
  if width is None:
    hex_str = '{:x}'.format(decimal)
  else:
    format_str = '{:0'+str(width)+'x}'
    hex_str = format_str.format(decimal)
  return hex_str


def hex_to_senary(hex_str, width=None, base=0):
  all_digits = range(base, base+6)
  decimal = int(hex_str, 16)
  # Adapted from https://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python/2267446#2267446
  digits = []
  while decimal:
    digits.append(all_digits[decimal % 6])
    decimal //= 6
  senary = ''.join(map(str, reversed(digits)))
  if width is not None:
    senary = '1' * (width - len(senary)) + senary
  return senary


def digits_conv(digits_in, in_base, out_base, round='ceil'):
  combinations = in_base**digits_in
  digits_out = math.log(combinations, out_base)
  if round == 'ceil':
    return int(math.ceil(digits_out))
  elif round == 'floor':
    return int(math.floor(digits_out))


def pad_number(number_str, width=None, group_length=5, base=0):
  if width:
    pad_digits = width - len(number_str)
  else:
    pad_digits = group_length - (len(number_str) % group_length)
  if pad_digits <= 0:
    return number_str
  if pad_digits == group_length:
    return number_str
  else:
    return str(base) * pad_digits + number_str


def read_word_list(word_list_path, reverse=False):
  word_map = {}
  with open(word_list_path, 'rU') as word_list:
    for line in word_list:
      fields = line.rstrip('\r\n').split()
      try:
        key, word = fields
      except ValueError:
        sys.stderr.write('Error: Wrong number of fields in line {!r}'.format(line))
        continue
      if reverse:
        word_map[word] = key
      else:
        word_map[key] = word
  return word_map


def senary_to_words(senary, word_map, group_length=5, width=None):
  """Translate a base 1 senary string to words.
  The word map should be the output of read_word_list() with reverse=False."""
  if width or group_length:
    senary = pad_number(senary, base=1, width=width, group_length=group_length)
  words = []
  for i in range(0, len(senary), group_length):
    if i+group_length > len(senary):
      raise ValueError('Error: Number of digits ({}) in {} not a multiple of group_length ({}).'
                       .format(len(senary), senary, group_length))
    senary_word = senary[i:i+group_length]
    try:
      words.append(word_map[senary_word])
    except KeyError as error:
      error.args = ('Word corresponding to '+senary_word+' not found.',)
      raise error
  return words


def words_to_senary(words, reverse_word_map):
  """Translate a list of words to a senary string.
  The word map should be the output of read_word_list() with reverse=True."""
  senary = ''
  for word in words:
    try:
      senary += reverse_word_map[word]
    except KeyError as error:
      error.args = ('Word {!r} not found in word list.'.format(word),)
      raise error
  return senary


def hex_to_words(hex, word_map, group_length=5, width=None):
  """Translate a hex string to a list of words.
  The word map should be the output of read_word_list() with reverse=False.
  Returns None on failure."""
  try:
    senary = hex_to_senary(hex, base=1)
  except ValueError:
    sys.stderr.write('ValueError converting hex {!r} to senary.\n'.format(hex))
    return None
  senary = pad_number(senary, group_length, base=1)
  return senary_to_words(senary, word_map, group_length=group_length, width=width)


def words_to_hex(words, reverse_word_map, base=1):
  """Input: A list of words, and a reverse word map (output of read_word_list() with reverse=True).
  Set `base` to 0 if the numbers in the word list file are 0-5 instead of 1-6.
  Returns None on failure."""
  senary = words_to_senary(words, reverse_word_map)
  if base == 1:
    senary = base1_to_base0(senary)
  try:
    return senary_to_hex(senary)
  except ValueError:
    sys.stderr.write('ValueError converting senary {!r} to hex.\n'.format(senary))
    return None


def get_rand_senary(ndigits, base=0):
  """Get a string of ndigits random numbers between base and base+5 from os.urandom()."""
  # Algorithm from https://stackoverflow.com/questions/137783/expand-a-random-range-from-1-5-to-1-7/891304#891304
  senary_digits = []
  state = 0
  pow1 = 1
  pow2 = 6
  while len(senary_digits) < ndigits:
    if state // pow1 == (state + pow2) // pow1:
      result = state // pow1
      state = (state - result * pow1) * 6
      pow2 *= 6
      senary_digits.append(result+base)
    else:
      state = 256 * state + pow2 * ord(os.urandom(1))
      pow1 *= 256
    # Keep the size of the huge numbers under a googol so it doesn't slow to a crawl.
    if pow1 > 10e100 or pow2 > 10e100:
      pow1 = 1
      pow2 = 6
      state = 0
  return ''.join(map(str, senary_digits))


def fail(message):
  sys.stderr.write(message+"\n")
  sys.exit(1)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
