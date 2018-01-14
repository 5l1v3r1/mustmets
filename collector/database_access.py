import pymysql
import pymysql.cursors
import json
from pathlib import Path

p = Path(__file__).parents[0]
p = Path(p, 'collector.json')

with p.open('r') as configfile:
    config = json.load(configfile)


class Bunch(object):
  def __init__(self, adict):
    self.__dict__.update(adict)

config = Bunch(config)


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
                               cursorclass=pymysql.cursors.DictCursor,
                               autocommit=True)

    def create_db(self):
        domain = """
CREATE TABLE IF NOT EXISTS `domain` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` VARCHAR(255) NOT NULL,
  `first_seen` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `blacklists` INT NULL,
  UNIQUE INDEX `name_UNIQUE` (`name` ASC)
  )
ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""
        cur = self.query(domain, ())
        certificate = """
CREATE TABLE IF NOT EXISTS `certificate` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `issuer` VARCHAR(1024) NULL,
  `notbefore` DATETIME NULL,
  `notafter` DATETIME NULL,
  `seen` DATETIME NULL,
  `source` VARCHAR(255) NULL,
  `serial` VARCHAR(100) NULL,
  `fingerprint` VARCHAR(100) NULL,
  `digitalSignature` TINYINT(1) NOT NULL DEFAULT 0,
  `nonRepudiation` TINYINT(1) NOT NULL DEFAULT 0,
  `keyEncipherment` TINYINT(1) NOT NULL DEFAULT 0,
  `dataEncipherment` TINYINT(1) NOT NULL DEFAULT 0,
  `keyAgreement` TINYINT(1) NOT NULL DEFAULT 0,
  `keyCertSign` TINYINT(1) NOT NULL DEFAULT 0,
  `cRLSign` TINYINT(1) NOT NULL DEFAULT 0,
  `encipherOnly` TINYINT(1) NOT NULL DEFAULT 0,
  `decipherOnly` TINYINT(1) NOT NULL DEFAULT 0,
  `signatureAlgorithm` VARCHAR(45) NOT NULL,
  `algorithm` VARCHAR(45) NOT NULL,
  `bit_size` INT NOT NULL
  )
ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""
        cur = self.query(certificate, ())
        domain_in_cert = """
CREATE TABLE IF NOT EXISTS `domain_in_certificate` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `domain_id` INT NOT NULL,
  `certificate_id` INT NOT NULL,
  INDEX `fk_domain_in_certificate_domain_idx` (`domain_id` ASC),
  INDEX `fk_domain_in_certificate_certificate1_idx` (`certificate_id` ASC),
  CONSTRAINT `fk_domain_in_certificate_domain`
    FOREIGN KEY (`domain_id`)
    REFERENCES `domain` (`id`)
    ON DELETE RESTRICT
    ON UPDATE RESTRICT,
  CONSTRAINT `fk_domain_in_certificate_certificate1`
    FOREIGN KEY (`certificate_id`)
    REFERENCES `certificate` (`id`)
    ON DELETE RESTRICT 
    ON UPDATE RESTRICT 
  )
ENGINE = InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """
        cur = self.query(domain_in_cert, ())
        self._conn.commit()
        cur.close()

    def insert_cert(self,
                    domain_names=None,
                    cert_issuer=None,
                    cert_notbefore=None,
                    cert_notafter=None,
                    cert_seen=None,
                    cert_source=None,
                    cert_serial=None,
                    cert_fingerprint=None,
                    cert_allowed_digitalsignature=False,
                    cert_allowed_nonrepudiation=False,
                    cert_allowed_keyencipherment=False,
                    cert_allowed_dataencipherment=False,
                    cert_allowed_keyagreement=False,
                    cert_allowed_keycertsign=False,
                    cert_allowed_crlsign=False,
                    cert_allowed_encipheronly=False,
                    cert_allowed_decipheronly=False,
                    cert_signaturealgorithm=None,
                    cert_algorithm=None,
                    cert_algorthm_bit_size=None):
        # insert certificate
        sql = """
INSERT INTO `certificate` (
  `issuer`, `notbefore`, `notafter`, `seen`, `source`, `serial`, `fingerprint`, `digitalSignature`, `nonRepudiation`,
  `keyEncipherment`, `dataEncipherment`, `keyAgreement`, `keyCertSign`, `cRLSign`, `encipherOnly`, `decipherOnly`, 
  `signatureAlgorithm`, `algorithm`, `bit_size`
) VALUES (
  %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s 
);
              """
        params = (cert_issuer, cert_notbefore, cert_notafter, cert_seen, cert_source, cert_serial, cert_fingerprint,
                  cert_allowed_digitalsignature, cert_allowed_nonrepudiation, cert_allowed_keyencipherment,
                  cert_allowed_dataencipherment, cert_allowed_keyagreement, cert_allowed_keycertsign, cert_allowed_crlsign,
                  cert_allowed_encipheronly, cert_allowed_decipheronly, cert_signaturealgorithm, cert_algorithm, cert_algorthm_bit_size)

        cur = self.query(sql, params)
        cert_id = cur.lastrowid
        cur.close()

        # insert all domains
        for domain_name in domain_names:
            # insert domain if not exists
            sql = 'INSERT IGNORE INTO `domain` (`name`) VALUES (%s);'
            params = (domain_name,)
            cur = self.query(sql, params)
            cur.close()

            # get the id for the domain
            cur = self.query('SELECT `id` FROM `domain` WHERE `name` = %s;', params)
            domain_id = cur.fetchone()['id']
            cur.close()

            # link domain with certificate
            sql = 'INSERT INTO `domain_in_certificate` (`domain_id`, `certificate_id`) VALUES (%s, %s);'
            cur = self.query(sql, (domain_id, cert_id))
            cur.close()

    def get_domains(self, newest=None, oldest=None):
        sql = 'SELECT `name` FROM `domain` WHERE `first_seen` > %s AND `first_seen` < %s;'
        params = (oldest, newest)
        cur = self.query(sql, params)
        yield cur.rowcount
        row = ""
        while row is not None:
            row = cur.fetchone()
            yield row
        cur.close()

    def update_blacklists(self, domain=None, count=None):
        sql = 'UPDATE `domain` SET `blacklists` = %s WHERE `name` = %s;'
        params = (count, domain)
        cur = self.query(sql, params)
        cur.close()

