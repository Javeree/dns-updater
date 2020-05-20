#! /bin/env python

import requests
import argparse
import json
import sys
import socket
from os.path import expanduser

# defaultcachefile caches the last IP address that was successfully uploaded to freedns
# a new update is only done when the current IP address differs from the cached one.
defaultcachefile="/var/tmp/dns_updater_cachefile"
general_defaultconfigfile='~/.config/dnsupdater.json'
defaultconfigfile=expanduser(general_defaultconfigfile)


class dynamicdnsupdater:
    protocol = None
    api = None

    def __init__(self):
        self.timeout = 2.0

    @staticmethod
    def createupdater(protocol, api):
        for subclass in dynamicdnsupdater.__subclasses__():
            if subclass._compatiblewith(subclass, protocol, api):
                return subclass._create()

    def _compatiblewith(subclass, protocol, api):
        return subclass.protocol == protocol and subclass.api == api

    def updateurl(self, key, ip):
        return None

    def update(self, dnsname, ip, key=None, username=None, password=None):
        url = self.updateurl(dnsname, ip, key, username, password)
        print(url)
        if username is None or password is None:
            auth=None
        else:
            auth = (username, password)
        return requests.get(url, timeout = self.timeout, auth = auth)


class freedns_api_1_0(dynamicdnsupdater):
    protocol = 'freedns'
    api = '1_0'

    @staticmethod
    def _create():
        return freedns_api_1_0()

    def __init__(self):
        super(freedns_api_1_0, self).__init__()
        self.update_host = 'freedns.afraid.org'

    def updateurl(self, dnsname, ip, key, username, password):
        return 'https://{}/dynamic/update.php?{}&address={}'.format(self.update_host, key, ip)

class freedns_api_2_0(dynamicdnsupdater):
    ''' Examples of configurations:
        { \
            'provider': 'freedns', \
            'api': '2_0', \
            'dnsname': 'my.freednsdns.name', \
            'key': 'CodeIGetFromFreedns' \
        }, \
        { \
            'provider': 'freedns', \
            'api': '2_0', \
            'dnsname': 'last.freedns.subdomain.com', \
            'key': 'CodeFromFreednsOfCourse' \
        },
    '''
    protocol = 'freedns'
    api = '2_0'

    @staticmethod
    def _create():
        return freedns_api_2_0()

    def __init__(self):
        super(freedns_api_2_0, self).__init__()
        self.update_host = 'sync.afraid.org'

    def updateurl(self, dnsname, ip, key, username, password):
        return 'https://{}/u/{}/'.format(self.update_host,key)

class freedns_api_2_2(dynamicdnsupdater):
    ''' Example of configuration:
       { \
            'provider': 'freedns', \
            'api': '2_2', \
            'dnsname': 'www.freedns.subdomain.com', \
            'username': 'myfreednslogin', \
            'password': 'mypassword', \
        },
    '''
    protocol = 'freedns'
    api = '2_2'

    @staticmethod
    def _create():
        return freedns_api_2_2()

    def __init__(self):
        super(freedns_api_2_2, self).__init__()
        self.update_host = 'sync.afraid.org'

    def updateurl(self, dnsname, ip, key, username, password):
        return 'https://{}/u/?h={}&ip={}'.format(self.update_host,dnsname,ip)

# the folllowing entries have been joined in freedns to require only a single update:
# "calibre.vereecke.mooo.com" "cloud.vereecke.mooo.com" "ftp.vereecke.mooo.com" "javeree.mooo.com" "vereecke.mooo.com"
# "cups.vereecke.mooo.com" "delindekring.vereecke.mooo.com" "imap.vereecke.mooo.com" "smtp.vereecke.mooo.com" "www.vereecke.mooo.com"
# "webmail.vereecke.mooo.com"

# API 2_0 is supported, but does not support external ip, so I need to take a version with encrypted http to send the password.
entries = None

def get_current_external_ip():
    """ Get the ip address of this PC/NATted network as visible from the internet """
    url = "http://Hermes/whatismyip"
    try:
        response = requests.get(url)

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        ip = soup.pre.string.rstrip()
        return ip
    except AttributeError:
        print(f'Error: Unexpected content received from {url}: {soup}', file=sys.stderr)
    except requests.ConnectionError as e:
        print(f'Error: Could not reach {url}', file=sys.stderr)
        print(e, file=sys.stderr)
        quit()


def get_cached_ip(cachefile = defaultcachefile):
    try:
        with open(cachefile, 'r')  as cf:
            ip = cf.read()
    except:
        ip = None
    return ip

def write_ip_to_cache(ip, cachefile=defaultcachefile):
    with open(cachefile,'w') as cf:
        cf.write(ip)


def update_freedns(key, ip, api = 1):
    """Updates the IP address in FreeDNS using API provided
    key The domain key
    ip The IP address to set
    api The api to use
    """
    timeout = 1.0

    if (api == 1):
        # See http://freedns.afraid.org/dynamic/ for API information.
        # and https://freedns.afraid.org/api/ for the URL and API key info
        url = 'http://freedns.afraid.org/dynamic/update.php?{}&address={}'.format(key, ip)
        response = requests.get(url, timeout = timeout)
    elif (api == 2):
        # See https://freedns.afraid.org/dynamic/v2/ to create the API and keys to update your version
        # this api does not allow to set the ip yourself!
        url = 'http://sync.afraid.org/u/{}/'.format(key)
        response = requests.get(url, timeout = timeout )
    else:
        response = None
    return response

def update_ips(entries, ip, verbose):
    """ Update al entries with the given ip
    entries: a list of json-based dns entries to be updated and the username/pass to authenticate
    ip: the ip address to set
    verbose: True to provide verbose output on the console
    returns: a list with results for each entry update (response status code (and text on error) from the server or False on timeout)
    """
    result = []
    for entry in entries:
        if verbose:
            print('update: {}'.format(entry['dnsname']))
        updater = dynamicdnsupdater.createupdater(entry['provider'], entry['api'])
        try:
            self.update_host = entry['update_host']
        except KeyError:
            pass
        try:
            response = updater.update(entry.get('dnsname'), ip=ip, key=entry.get('key'), username=entry.get('username'), password=entry.get('password'))
            result.append(response.status_code == 200)
            if (response.status_code != 200 or verbose):
                print(response.text)
        except requests.exceptions.Timeout as e:
                result.append(False)
                print('Timeout: {}'.format(str(e)))
    return result

def main():
    parser = argparse.ArgumentParser(description='Update freedns dynamic ip address')
    parser.add_argument('-c', '--config', dest='configfile', action='store', default=defaultconfigfile, \
        help=f'file containing the configurations to update.\n(default: {general_defaultconfigfile})')
    parser.add_argument('-i', '--ip', dest='ip', action='store', default=None, \
        help='provide the ip address to use instead of using autodetection')
    parser.add_argument('-f', '--force', dest='force', action='store_const', const=True, default=False, \
        help='send an update request without checking the IP cache')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_const', const=True, default=False, \
        help='provide verbose feedback')
    args = parser.parse_args()

    try:
        with open(args.configfile, 'r') as infile:
            entries = json.load(infile)
    except IOError as e:
        print('Error: could not open file {}'.format(args.configfile))
        parser.print_usage()
        quit(1)

    try:
        socket.inet_aton(str(args.ip)) # test the validity of the string as an ip address
        current_ip = args.ip
    except socket.error:
        current_ip = get_current_external_ip()

    if args.verbose:
        print('current ip: {}'.format(current_ip))
    old_ip = get_cached_ip()
    if args.verbose:
        print('cached ip: {}'.format(old_ip))
    if current_ip != old_ip or args.force:
        result = update_ips(entries, current_ip, args.verbose)
        if all(result):
            write_ip_to_cache(current_ip)
 
if __name__ == "__main__":
    main()
