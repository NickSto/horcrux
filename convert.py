#!/usr/bin/env python
from __future__ import division
from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals
import sys
import math
import argparse

ARG_DEFAULTS = {}
USAGE = "%(prog)s [options]"
DESCRIPTION = """"""


def main(argv):

  parser = argparse.ArgumentParser(description=DESCRIPTION)
  parser.set_defaults(**ARG_DEFAULTS)

  parser.add_argument('input')
  parser.add_argument('-x', '--to-hex', action='store_true')
  parser.add_argument('-s', '--to-senary', action='store_true')
  parser.add_argument('-d', '--senary-digits', type=int)

  args = parser.parse_args(argv[1:])

  input_condensed = args.input.replace(' ', '')

  if args.senary_digits:
    senary_digits = args.senary_digits
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif args.to_hex:
    senary_digits = len(input_condensed)
    hex_digits = digits_conv(senary_digits, 6, 16)
  elif args.to_senary:
    hex_digits = len(input_condensed)
    senary_digits = digits_conv(hex_digits, 16, 6, round='floor')

  if args.to_hex:
    senary_base0 = base1_to_base0(input_condensed)
    print(senary_to_hex(senary_base0, width=hex_digits))
  elif args.to_senary:
    print(hex_to_senary_base1(input_condensed, width=senary_digits))
  else:
    fail('Error: Choose --to-hex or --to-senary.')


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


def fail(message):
  sys.stderr.write(message+"\n")
  sys.exit(1)


if __name__ == '__main__':
  sys.exit(main(sys.argv))
