from optparse import OptionParser

from . import scanner

if __name__ == '__main__':
    import sys
    import json

    parser = OptionParser()
    parser.add_option('-p', '--port', type='int', default=22)
    options, args = parser.parse_args()
    if not args:
        args.append('localhost')
    if len(args) != 1:
        parser.error('too many arguments')

    result = scanner.scan((args[0], options.port))

    print(json.dumps(result, indent=2, sort_keys=True))
