from optparse import OptionParser
import os
import sys
import glob
import re
import json


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
            name, value = re.findall('(\S+):\s*(.*)', line)[0]

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
        test_case = {
            'test': test_name.upper(),
            'received': set_cookies,
            'sent': parse_expected_file(expected_file)
        }

        if location:
            test_case['sent-to'] = location

        tests.append(test_case)

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
        json.dump(tests, f, indent=2)

    print 'Done'


if __name__ == '__main__':
    main()