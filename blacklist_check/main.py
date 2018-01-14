from gglsbl import SafeBrowsingList
import requests
from pathlib import Path
import hashlib
from datetime import datetime, timedelta
import json
import sys
import subprocess

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

print('Checking {} domains against blacklists...'.format(domaincount))

iteration = 0

bl_files = Path(config.DNSBL_DIRECTORY).glob('**/*')

for domain in domains:
    iteration += 1
    print('\rProgress: {0:.3g}%'.format(iteration/int(domaincount)), end='')
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
    for f in bl_files:
        if f.is_file():
            rc = subprocess.call(['grep', domain_name, str(f)])
            if rc != 1:
                blacklists += 1
    if blacklists > 0:
        print('Domain {} found in {} blacklists - updating database.'.format(domain_name, str(blacklists)))
        db.update_blacklists(domain=domain['name'], count=blacklists)
print('Blacklist data update complete!')
