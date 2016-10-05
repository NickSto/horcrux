#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
import sys
import math
import getpass
import argparse

HEX_ONLY_DIGITS = '0789ABCDEFabcdef'
ARG_DEFAULTS = {'group_length':5}
USAGE = "%(prog)s [options]"
DESCRIPTION = """"""


def main(argv):

  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.set_defaults(**ARG_DEFAULTS)

  parser.add_argument('input', nargs='?')
  parser.add_argument('-e', '--echo', action='store_true',
    help='When entering the input interactively, show it on-screen instead of hiding it.')
  parser.add_argument('-x', '--to-hex', action='store_true')
  parser.add_argument('-s', '--to-senary', action='store_true')
  parser.add_argument('-d', '--senary-digits', type=int)
  parser.add_argument('-w', '--word-list', type=argparse.FileType('r'),
    help='Use this word list to print out the words as well.')
  parser.add_argument('-l', '--group-length', type=int,
    help='The number of senary digits per word. Default: %(default)s')

  args = parser.parse_args(argv[1:])

  if args.input:
    input_raw = args.input
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

  if args.to_hex:
    destination = 'hex'
  elif args.to_senary:
    destination = 'senary'
  else:
    input_type = 'senary'
    for char in input:
      if char in HEX_ONLY_DIGITS:
        input_type = 'hex'
        break
    if input_type == 'hex':
      destination = 'senary'
    else:
      destination = 'hex'
    sys.stderr.write('Destination format not specified. Inferred input type is {}. Converting to '
                     '{}.\n'.format(input_type, destination))

  if args.senary_digits:
    senary_digits = args.senary_digits
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif destination == 'hex':
    senary_digits = len(input)
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif destination == 'senary':
    hex_digits = len(input)
    senary_digits = digits_conv(hex_digits, 16, 6, round='floor')

  if destination == 'hex':
    senary_base0 = base1_to_base0(input)
    print(senary_to_hex(senary_base0, width=hex_digits))
  elif destination == 'senary':
    senary = hex_to_senary_base1(input, width=senary_digits)
    print(senary)
    if args.word_list:
      word_map = read_word_list(args.word_list)
      print_words(senary, word_map, args.group_length)


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


def hex_to_senary_base1(hex_str, width=None):
  decimal = int(hex_str, 16)
  # Adapted from https://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python/2267446#2267446
  digits = []
  while decimal:
    digits.append('123456'[decimal % 6])
    decimal //= 6
  senary = ''.join(reversed(digits))
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
