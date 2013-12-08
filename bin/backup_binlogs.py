#!/usr/bin/env python

import os
from os import listdir
from os.path import isfile, join

import time
import shutil
import subprocess
import hashlib
import logging
import random
import struct
import re
import inspect
from socket import gethostname
from Crypto.Cipher import AES
from swiftclient import Connection, ClientException
from optparse import OptionParser
parser = OptionParser()

workdir = os.getcwd()
LOG = logging.getLogger(__name__)
hdlr = logging.FileHandler("%s/%s.log" % (workdir,
                           inspect.getfile(inspect.currentframe())))
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
LOG.addHandler(hdlr)
LOG.setLevel(logging.INFO)

# Settings
parser.add_option("-l", "--log",
                  dest="log_file",
                  help="Log file",
                  metavar="LOG")

parser.add_option("-c", "--container",
                  default="db_backup_binlogs",
                  dest="container",
                  help="CONTAINER",
                  metavar="CONTAINER")

parser.add_option("-u", "--os-username",
                  default=os.environ.get('OS_USERNAME', ''),
                  dest="username",
                  help="User",
                  metavar="USER")

parser.add_option("-p", "--os-password",
                  default=os.environ.get('OS_PASSWORD', ''),
                  dest="password",
                  help="Swift Password",
                  metavar="PASSWORD")


parser.add_option("-t", "--os-tenant-name",
                  default=os.environ.get('OS_TENANT_NAME', ''),
                  dest="tenant_name",
                  help="Tenant Name",
                  metavar="TENANT")

parser.add_option("-a", "--os-auth-url",
                  default=os.environ.get('OS_AUTH_URL', ''),
                  dest="auth_url",
                  help="Auth URL",
                  metavar="AUTH_URL")

parser.add_option("-b", "--backup-dir",
                  default="/var/lib/mysql-backup",
                  dest="backup_dir",
                  help="Backup directory",
                  metavar="BACKUP_DIR")

parser.add_option("-B", "--binlog-dir",
                  default="/var/lib/mysql",
                  dest="binlog_dir",
                  help="Binlog directory",
                  metavar="BINLOG_DIR")

parser.add_option("-s", "--secret-file",
                  default="/etc/mysql-backup/.backup.key",
                  dest="secret_file",
                  help="Secret file",
                  metavar="SECRET FILE")

(options, args) = parser.parse_args()

log_file = options.log_file
username = options.username
password = options.password

auth_url = options.auth_url
tenant_name = options.tenant_name
secret_file = options.secret_file

container = options.container
binlog_dir = options.binlog_dir

backup_command = '/usr/bin/innobackupex --no-timestamp'
prepare_command = '/usr/bin/innobackupex --apply-log'
backup_dir = options.backup_dir
backup_name = "%s-%s-backup" % (time.strftime("%Y-%m-%d-%H%M-%Z-%a"),
                                gethostname())
backup_file = backup_name + ".tar.gz"
backup_file_enc = backup_file + ".enc"
content_type = 'application/gzip'


def ensure_container_exists(conn, container):
    headers = {}
    try:
        conn.post_container(container, headers=headers)
    except ClientException, err:
        if err.http_status != 404:
            raise
        conn.put_container(container, headers=headers)


def upload_file_to_swift(conn,
                         container, filename,
                         file_handle, file_md5,
                         content_type, content_length):
        # you must set headers this way
        headers = {"Content-Type": content_type}

        # upload object
        try:
            conn.put_object(container,
                            filename,
                            file_handle,
                            headers=headers,
                            content_length=content_length,
                            etag=file_md5)
        except ClientException, err:
            LOG.critical('Upload failed: %s', str(err))
        else:
            LOG.info('Upload succeeded')


def get_binlogs_on_disk():
    binlogs_on_disk = {}
    binlogs = [binlog for binlog in listdir(binlog_dir)
               if isfile(join(binlog_dir, binlog)) and
               re.match(r'mysql-bin\.\d+$', binlog, re.M | re.I)]
    for binlog in binlogs:
        binlogs_on_disk[binlog] = 1

    return binlogs_on_disk


def md5_for_file(filename, block_size=2 ** 20):
    with open(filename, 'rb') as fh:
        md5 = hashlib.md5()
        while True:
            data = fh.read(block_size)
            if not data:
                break
            md5.update(data)

    return md5.hexdigest()


def get_secret():
    with open(secret_file, "r") as fh:
        key = fh.readline()

    return key.rstrip()


def upload_binlogs_on_disk_to_swift(conn, binlogs):
    for binlog in binlogs.keys():
        binlog_enc = binlog + '.enc'
        binlog_on_disk = binlog_dir + '/' + binlog
        binlog_enc_on_disk = backup_dir + '/' + binlog_enc
        # AES encrypt the file before uploading
        secret = get_secret()
        encrypt_file(secret, binlog_on_disk, binlog_enc_on_disk)
        content_type = 'application/gzip'
        content_length = os.stat(binlog_enc_on_disk).st_size
        file_md5 = md5_for_file(binlog_enc_on_disk)
        LOG.info("uploading %s to %s" % (binlog_enc_on_disk, container))
        # print "uploading %s to %s" % (binlog_enc_on_disk, container)
        try:
            with open(binlog_on_disk, 'rb') as fh:
                upload_file_to_swift(conn,
                                     container,
                                     binlog_enc,
                                     fh,
                                     file_md5,
                                     content_type,
                                     content_length)
        finally:
            LOG.info("done uploading")


def get_binlogs_in_swift(conn, container):
    binlogs_in_swift = {}
    try:
        items = \
            conn.get_container(container, '', '')[1]
        for item in items:
            binlog_encrypted = item.get('name')
            binlog = None
            m = re.match(r'(mysql-bin\.\d+).enc$',
                         binlog_encrypted, re.M | re.I)
            if m is None:
                next
            else:
                binlog = m.group(1)
            if binlog is not None:
                binlogs_in_swift[binlog[0]] = 1
    except ClientException, err:
        if err.http_status != 404:
            LOG.error('Authorization Failure. %s' % err)
            raise

    return binlogs_in_swift


def dict_diff(dicta, dictb):
    missing = {}
    if len(dictb) == 0:
        return dicta
    for key in dicta.keys():
        if (key not in dictb):
            missing[key] = 1

    return missing


def delete_binlogs_in_swift_not_on_disk(conn, missing_on_disk):
    for binlog in missing_on_disk:
        binlog_enc = binlog + '.enc'
        conn.delete_object(container, binlog_enc, query_string='')


def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    """
        http://eli.thegreenplace.net/2010/06/25/ \
        aes-encryption-of-files-in-python-with-pycrypto/

        Encrypts a file using AES (CBC mode) with the
        given key.

        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.

        in_filename:
            Name of the input file

        out_filename:
            If None, '<in_filename>.enc' will be used.

        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """

    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


if __name__ == '__main__':
    LOG.setLevel(logging.INFO)
    try:
        # establish connection
        conn = Connection(auth_url,
                          username,
                          password,
                          tenant_name=tenant_name,
                          auth_version="2.0")
    except ClientException, err:
        LOG.critical("No Swift Connection: %s", str(err))

    ensure_container_exists(conn, container)

    binlogs_on_disk = get_binlogs_on_disk()
    binlogs_in_swift = get_binlogs_in_swift(conn, container)

    # print "before:"
    # print "binlogs_on_disk"
    # print binlogs_on_disk
    # print "binlogs_in_swift"
    # print binlogs_in_swift

    missing_in_swift = dict_diff(binlogs_on_disk, binlogs_in_swift)
    upload_binlogs_on_disk_to_swift(conn, missing_in_swift)

    missing_on_disk = dict_diff(binlogs_in_swift, binlogs_on_disk)
    delete_binlogs_in_swift_not_on_disk(conn, missing_on_disk)

    binlogs_on_disk = get_binlogs_on_disk()
    binlogs_in_swift = get_binlogs_in_swift(conn, container)

    # print "after:"
    # print "binlogs_on_disk"
    # print binlogs_on_disk
    # print "binlogs_in_swift"
    # print binlogs_in_swift
