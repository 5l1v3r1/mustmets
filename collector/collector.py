"""
Must Mets - Real-time DNSBL from CT log mining
Copyright (C) 2018 Silver Saks

Collector module - gathers data from certstream and routes it for further processing.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import certstream
from database_access import MysqlDB
import ujson
import asn1crypto.x509
import base64
from datetime import datetime


def parse_cert(data):
    streamdata = ujson.loads(data)
    if 'data' in streamdata:
        cert = base64.b64decode(streamdata['data']['leaf_cert']['as_der'].encode('utf-8'))
        cert = asn1crypto.x509.Certificate.load(cert)
        if cert is not None and cert.key_usage_value is not None:
            db.insert_cert(domain_names=streamdata['data']['leaf_cert']['all_domains'],
                           cert_issuer=cert.issuer.human_friendly,
                           cert_notbefore=datetime.fromtimestamp(streamdata['data']['leaf_cert']['not_before']),
                           cert_notafter=datetime.fromtimestamp(streamdata['data']['leaf_cert']['not_after']),
                           cert_seen=datetime.fromtimestamp(streamdata['data']['seen']),
                           cert_source=streamdata['data']['source']['url'],
                           cert_serial=streamdata['data']['leaf_cert']['serial_number'],
                           cert_fingerprint=streamdata['data']['leaf_cert']['fingerprint'],
                           cert_allowed_digitalsignature=True if 'digital_signature' in cert.key_usage_value.native else False,
                           cert_allowed_nonrepudiation=True if 'non_repudiation' in cert.key_usage_value.native else False,
                           cert_allowed_keyencipherment=True if 'key_encipherment' in cert.key_usage_value.native else False,
                           cert_allowed_dataencipherment=True if 'data_encipherment' in cert.key_usage_value.native else False,
                           cert_allowed_keyagreement=True if 'key_agreement' in cert.key_usage_value.native else False,
                           cert_allowed_keycertsign=True if 'key_cert_sign' in cert.key_usage_value.native else False,
                           cert_allowed_crlsign=True if 'crl_sign' in cert.key_usage_value.native else False,
                           cert_allowed_encipheronly=True if 'encipher_only' in cert.key_usage_value.native else False,
                           cert_allowed_decipheronly=True if 'decipher_only' in cert.key_usage_value.native else False,
                           cert_signaturealgorithm=cert.signature_algo,
                           cert_algorithm=cert.public_key.algorithm,
                           cert_algorthm_bit_size=cert.public_key.bit_size
                           )

db = MysqlDB()

certstream.listen_for_events(parse_cert)
