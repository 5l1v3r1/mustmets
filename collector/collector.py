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
import pymysql
import pymysql.cursors
import config
import ujson
import asn1crypto.x509
import base64


class MysqlDB:
    _conn = None

    def __init__(self):
        self._conn = self.connect()
        self.create_db()

    def query(self, sql, params):
        try:
            cur = self._conn.cursor()
            cur.execute(sql, params)
        except (AttributeError, pymysql.OperationalError):
            self._conn = self.connect()
            cur = self._conn.cursor()
            cur.execute(sql, params)
        return cur

    @staticmethod
    def connect():
        return pymysql.connect(host=config.SQL_HOST,
                               user=config.SQL_USER,
                               password=config.SQL_PASSWORD,
                               db=config.SQL_DB,
                               charset='utf8mb4',
                               cursorclass=pymysql.cursors.DictCursor)

    def create_db(self):
        sql = """
                CREATE TABLE IF NOT EXISTS `certs` (
                    `id` int(11) NOT NULL AUTO_INCREMENT,
                    `certdata` JSON NOT NULL,
                    `added` DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (`id`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
              """
        cur = self.query(sql, ())
        self._conn.commit()
        cur.close()

    def insert_cert(self, data):
        sql = """
            INSERT INTO `certs` (`certdata`) VALUES (%s);
        """
        params = (data,)
        cur = self.query(sql, params)
        self._conn.commit()
        cur.close()

    def parse_cert(self, data):
        streamdata = ujson.loads(data)
        if 'data' in streamdata:
            cert = base64.b64decode(streamdata['data']['leaf_cert']['as_der'].encode('utf-8'))
            cert = asn1crypto.x509.Certificate.load(cert)
            print(cert)


db = MysqlDB()

certstream.listen_for_events(db.parse_cert)
