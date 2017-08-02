import sys
import os
import logging
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        prog='fluffyd', description='Fluffy development server')
    parser.add_argument('-H', '--host', type=str, action='store', dest='host',
                        default='0.0.0.0', help='Bind host (default: %(default)s)')
    parser.add_argument('-p', '--port', type=int, action='store', dest='port',
                        default=8676, help='Listen port (default: %(default)s)')
    parser.add_argument('-c', '--config', type=str, action='store', dest='config_file',
                        default='/etc/fluffy/fluffy.yaml', help='Configuration file (default: %(default)s)')
    parser.add_argument('-l', '--log_level', type=str, action='store', dest='log_level', default=None, choices=[
                        'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the logging level (default: %(default)s)')
    opts = parser.parse_args()
    return opts


def main():
    opts = parse_args()

    os.environ['FLUFFY_CONFIG_FILE'] = opts.config_file
    if opts.log_level:
        os.environ['FLUFFY_LOGLEVEL'] = opts.log_level

    from .application import app
    app.run(host=opts.host, port=opts.port, threaded=True, use_reloader=False)


if __name__ == '__main__':
    main()
