#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
import sys
import math
import random
import getpass
import argparse

HEX_ONLY_DIGITS = '0789ABCDEFabcdef'
ARG_DEFAULTS = {'num_words':5, 'group_length':5}
USAGE = "%(prog)s [options]"
DESCRIPTION = """"""


def main(argv):

  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.set_defaults(**ARG_DEFAULTS)

  parser.add_argument('input', nargs='?')
  parser.add_argument('-e', '--echo', action='store_true',
    help='When entering the input interactively, show it on-screen instead of hiding it.')
  parser.add_argument('-r', '--random', action='store_true',
    help='Use random input instead of a user-supplied number. WARNING: Currently the source of '
         'randomness is completely insecure.')
  parser.add_argument('-b', '--base', dest='input_base', choices=('senary', 'hex'),
    help='Specify the input base. Will attempt to detect it otherwise.')
  parser.add_argument('-x', '--to-hex', dest='output_base', action='store_const', const='hex',
    help='Return output in hexadecimal.')
  parser.add_argument('-s', '--to-senary', dest='output_base', action='store_const', const='senary',
    help='Return output in senary.')
  parser.add_argument('-d', '--senary-digits', type=int)
  parser.add_argument('-n', '--num-words', type=int,
    help='When generating random input, create enough for this many words.')
  parser.add_argument('-l', '--group-length', type=int,
    help='The number of senary digits per word. Default: %(default)s')
  parser.add_argument('-w', '--word-list', type=argparse.FileType('r'),
    help='Use this word list to print out the words as well.')

  args = parser.parse_args(argv[1:])

  if args.input:
    input_raw = args.input
  elif args.random:
    sys.stderr.write('WARNING: Random generation is completely insecure. For testing only.\n')
    if args.senary_digits:
      senary_digits = args.senary_digits
    else:
      senary_digits = args.num_words * args.group_length
    input_raw = ''.join([random.choice('123456') for i in range(senary_digits)])
  elif args.echo:
    sys.stdout.write('Input: ')
    input_raw = sys.stdin.readline().rstrip('\r\n')
  else:
    try:
      input_raw = getpass.getpass(prompt='Input: ')
    except EOFError:
      print()
      return 1

  input = input_raw.replace(' ', '')

  if not input:
    fail('Error: input is empty.')

  # Detect input format, if needed.
  if args.input_base:
    input_base = args.input_base
  elif args.random:
    input_base = 'senary'
  else:
    input_base = detect_base(input)
    sys.stderr.write('Input base not specified. Inferred input type is {}.\n'.format(input_base))

  # What should the output format be?
  if args.output_base:
    output_base = args.output_base
  elif args.random:
    output_base = 'senary'
  elif input_base == 'hex':
    output_base = 'senary'
  elif input_base == 'senary':
    output_base = 'hex'

  # Determine the width of the hex and senary numbers.
  if args.senary_digits:
    senary_digits = args.senary_digits
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif input_base == 'senary':
    senary_digits = len(input)
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif input_base == 'hex':
    hex_digits = len(input)
    senary_digits = digits_conv(hex_digits, 16, 6, round='floor')

  # Determine the output. Do conversion, if needed.
  if input_base == 'senary':
    senary = input
    if output_base == 'hex':
      senary_base0 = base1_to_base0(senary)
      output = senary_to_hex(senary_base0, width=hex_digits)
    elif output_base == 'senary':
      output = senary
  elif input_base == 'hex':
    # Convert to senary, even if that's not the output format, in case it's needed for the word list.
    senary = hex_to_senary(input, width=senary_digits, base=1)
    if output_base == 'senary':
      output = senary
    elif output_base == 'hex':
      output = input

  print(output)
  if args.word_list:
    word_map = read_word_list(args.word_list)
    print_words(senary, word_map, args.group_length)


def detect_base(input):
  base = 'senary'
  for char in input:
    if char in HEX_ONLY_DIGITS:
      base = 'hex'
      break
  return base


def base1_to_base0(senary_str_base1):
  # Traditionally the senary digits are 1-6. We need it in 0-5.
  senary_str_base0 = ''
  for digit_str in senary_str_base1:
    digit = int(digit_str)
    senary_str_base0 += str(digit-1)
  return senary_str_base0


def senary_to_hex(senary_str, width=None):
  decimal = int(senary_str, 6)
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


def read_word_list(word_list):
  word_map = {}
  for line in word_list:
    fields = line.rstrip('\r\n').split()
    try:
      key, word = fields
    except ValueError:
      continue
    word_map[key] = word
  return word_map


def print_words(senary, word_map, group_length=5):
  words = []
  for i in range(0, len(senary), group_length):
    if i+group_length > len(senary):
      sys.stderr.write('Error: Number of digits ({}) in {} not a multiple of --group-length ({}).\n'
                       .format(len(senary), senary, group_length))
      break
    senary_word = senary[i:i+group_length]
    try:
      words.append(word_map[senary_word])
    except KeyError:
      sys.stderr.write('Error: word corresponding to '+senary_word+' not found.\n')
      continue
  print(' '.join(words))


def fail(message):
  sys.stderr.write(message+"\n")
  sys.exit(1)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
