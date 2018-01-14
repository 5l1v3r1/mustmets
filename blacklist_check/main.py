from gglsbl import SafeBrowsingList
import requests
from pathlib import Path
import hashlib
from datetime import datetime, timedelta
import json
import sys
import re

sys.path.append('..')
from collector import database_access

config = json.load(open('blacklist_check.json'))


class Bunch(object):
  def __init__(self, adict):
    self.__dict__.update(adict)

config = Bunch(config)

update = False

sbl = SafeBrowsingList(api_key=config.GOOGLE_API_KEY, db_path='gsb_v4.db')

if update:
    print('Updating safe browsing database...')
    sbl.update_hash_prefix_cache()
    print('Safe browsing database updated')

    print('Updating DNSBL-s...')
    for list in config.DNSBL_URL_LIST:
        resp = requests.get(list)
        if resp.status_code == 200:
            f = Path(config.DNSBL_DIRECTORY, hashlib.md5(list.encode('utf-8')).hexdigest())
            f.write_bytes(resp.content)
    print('DNSBL update completed')

print('Getting domain data from MySQL...')
db = database_access.MysqlDB()
now = datetime.now()
newest = now - timedelta(days=0)
oldest = now - timedelta(days=9)
domains = db.get_domains(newest=newest, oldest=oldest)

# our first item is the rowcount
domaincount = next(domains)

iteration = 0

bl_files = Path(config.DNSBL_DIRECTORY).glob('**/*')

dnsbl = dict()

# https://gist.github.com/neu5ron/66078f804f16f9bda828
domain_regex = r'(?:(?:[\da-zA-Z])(?:[_\w-]{,62})\.){,127}(?:(?:[\da-zA-Z])[_\w-]{,61})?(?:[\da-zA-Z]\.(?:(?:xn\-\-[a-zA-Z\d]+)|(?:[a-zA-Z\d]{2,})))'
valid_domain_name_regex = re.compile(domain_regex, re.IGNORECASE)

print('Loading DNSBL data...')
for file in bl_files:
    text = file.read_text(encoding='utf-8', errors='ignore')
    domains_bl = valid_domain_name_regex.finditer(text)
    for domain in domains_bl:
        if domain.group(0) in dnsbl:
            dnsbl[domain.group(0)] += 1
        else:
            dnsbl[domain.group(0)] = 1

print('Checking {} domains against blacklists...'.format(domaincount))
for domain in domains:
    iteration += 1
    if iteration % 101 == 0:
        print('\rProgress: {:05.3f}%'.format(iteration/int(domaincount)), end='')
    domain_name = domain['name'].replace('*.', '')
    blacklists = 0
    # print('Safebrowsing check started for {} ({})'.format(domain_name, str(blacklists)))
    th = sbl.lookup_url('https://' + domain_name + '/')
    if th is not None:
        blacklists += 1
    th = sbl.lookup_url('http://' + domain_name + '/')
    if th is not None:
        blacklists += 1
    # print('DNSBL check started for {} ({})'.format(domain_name, str(blacklists)))
    if domain_name in dnsbl:
        blacklists += dnsbl[domain_name]
    if blacklists > 0:
        print('\nDomain {} found in {} blacklists - updating database.'.format(domain_name, str(blacklists)))
        db.update_blacklists(domain=domain['name'], count=blacklists)
print('Blacklist data update complete!')
