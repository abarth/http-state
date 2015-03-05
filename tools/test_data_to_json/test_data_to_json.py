"""
Copyright (c) 2015, Ivan Nikulin (ifaaan@gmail.com)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

from optparse import OptionParser
from collections import OrderedDict
import os
import sys
import glob
import re
import json

# NOTE we use custom encoder here to keep original formatting in the parser.json
class TestDataEncoder(json.JSONEncoder):
    indentUnit = '  '

    def __init__(self, *args, **kwargs):
        super(TestDataEncoder, self).__init__(*args, **kwargs)
        self.indent = ''

    def encode(self, o):
        if isinstance(o, list):
            if len(o) == 0:
                return '[]'

            prev_indent = self.indent
            self.indent += TestDataEncoder.indentUnit
            encoded_items = [self.indent + self.encode(i) for i in o]
            self.indent = prev_indent
            encoded_list = '[\n' + ',\n'.join(encoded_items) + '\n' + self.indent + ']'
            return encoded_list

        elif isinstance(o, dict):
            if 'name' in o and 'value' in o:
                encoded_items = [json.dumps(key) + ": " + json.dumps(value) for key, value in o.iteritems()]
                return '{ ' + ', '.join(encoded_items) + ' }'

            prev_indent = self.indent
            self.indent += TestDataEncoder.indentUnit

            encoded_items = [self.indent + json.dumps(key) + ": " + self.encode(value)
                             for key, value in o.iteritems()]

            self.indent = prev_indent
            encoded_dict = '{\n' + ',\n'.join(encoded_items) + '\n' + self.indent + '}'
            return encoded_dict

        else:
            return json.dumps(o)


def parse_options():
    option_parser = OptionParser()
    option_parser.add_option('-d', '--data-dir', dest='data_dir', type='string',
                             help='Directory from which to read the test data files')
    option_parser.add_option('-o', '--output-file', dest='output_file', type='string', help='Output JSON file path')

    options, args = option_parser.parse_args()

    return options


def parse_test_file(file_path):
    location = None
    set_cookies = []

    with open(file_path, 'r') as f:
        for line in f:
            name, value = re.findall('(\S+): ?(.*)', line)[0]

            if name.lower() == 'location':
                location = value

            else:
                set_cookies.append(value)

    return location, set_cookies


def parse_expected_file(file_path):
    expected_cookies = []

    with open(file_path, 'r') as f:
        data = f.read()

    cookie_header_match = re.findall('Cookie:\s*(.*)', data)

    if len(cookie_header_match) == 1:
        cookie_header_str = cookie_header_match[0]
        cookie_strings = [c.strip() for c in cookie_header_str.split(';')]

        for cookie_str in cookie_strings:
            chunks = cookie_str.split('=')
            expected_cookies.append({
                'name': chunks.pop(0),
                'value': '='.join(chunks)
            })

    return expected_cookies


def read_data_dir(data_dir):
    tests = []
    test_file_glob = os.path.join(data_dir, '*-test')

    for test_file in glob.glob(test_file_glob):
        file_name = os.path.basename(test_file)
        test_name = re.findall('(.*)-test', file_name)[0]
        expected_file = os.path.join(data_dir, test_name + '-expected')
        location, set_cookies = parse_test_file(test_file)

        # NOTE: use OrderedDict here to keep fields order in the original parser.json file
        test_case = [
            ('test', test_name.upper().replace('-', '_')),
            ('received', set_cookies),
            ('sent', parse_expected_file(expected_file))
        ]

        if location:
            test_case.insert(2, ('sent-to', location))

        tests.append(OrderedDict(test_case))

    return tests


def validate_options(options):
    errs = []

    if not options.data_dir or not os.path.isdir(options.data_dir):
        errs.append('Test data directory does not exists or not specified.')

    if not options.output_file:
        errs.append('Output JSON file path is not specified.')

    if len(errs) > 0:
        for err in errs:
            print err

        print 'Exiting... Run with "-h" flag for help.'
        sys.exit(-1)


def main():
    options = parse_options()
    validate_options(options)

    tests = read_data_dir(options.data_dir)
    output_dir = os.path.dirname(options.output_file)

    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)

    with open(options.output_file, 'wb') as f:
        data_json = json.dumps(tests, cls=TestDataEncoder)
        f.write(data_json)

    print 'Done'


if __name__ == '__main__':
    main()