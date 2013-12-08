#!/usr/bin/env python

import os
import time
import shutil
import subprocess
import hashlib
import logging
import random
import struct

from socket import gethostname
from Crypto.Cipher import AES
from swiftclient import Connection, ClientException

from optparse import OptionParser
parser = OptionParser()

use_swift = True

parser.add_option("-l", "--log", dest="log_file",
                  help="Log file",
                  metavar="LOG")

parser.add_option("-c", "--container",
                  default="",
                  dest="container",
                  help="CONTAINER",
                  metavar="CONTAINER")

parser.add_option("-u", "--os-username",
                  default="",
                  dest="username",
                  help="User",
                  metavar="USER")

parser.add_option("-p", "--os-password",
                  default="",
                  dest="password",
                  help="Swift Password",
                  metavar="PASSWORD")


parser.add_option("-t", "--os-tenant-name",
                  default="",
                  dest="tenant_name",
                  help="Tenant Name",
                  metavar="TENANT")

parser.add_option("-a", "--os-auth-url",
                  default="",
                  dest="auth_url",
                  help="Auth URL",
                  metavar="AUTH_URL")


parser.add_option("-D", "--purge-on-disk",
                  action="store_false", dest="purge",
                  help="Purge Backup on disk",
                  metavar="PURGE")

parser.add_option("-P", "--purge-enc-on-disk",
                  action="store_false", dest="purge_enc",
                  help="Purge Backup on disk",
                  metavar="PURGE_ENC")

parser.add_option("-b", "--backup-dir",
                  default="/var/lib/mysql-backup",
                  dest="backup_dir",
                  help="Backup directory",
                  metavar="BACKUP_DIR")

parser.add_option("-s", "--secret-file",
                  default="/etc/mysql-backup/.backup.key",
                  dest="secret_file",
                  help="Secret file",
                  metavar="SECRET FILE")

(options, args) = parser.parse_args()

log_file = options.log_file


purge = options.purge
purge_enc = options.purge_enc

auth_url = options.auth_url
if auth_url == "":
    auth_url = os.environ.get('OS_AUTH_URL', '')

tenant_name = options.tenant_name
if tenant_name == "":
    tenant_name = os.environ.get('OS_TENANT_NAME', '')

password = options.password
if password == "":
    password = os.environ.get('OS_PASSWORD', '')

username = options.username
if username == "":
    username = os.environ.get('OS_USERNAME', '')

container = options.container
if container == "":
    container = os.environ.get('BACKUP_CONTAINER', 'db_backup')

backup_dir = options.backup_dir
secret_file = options.secret_file

logging.StreamHandler(stream=log_file)

logging.basicConfig(filename=log_file,
                    level=logging.INFO)

LOG = logging.getLogger(__name__)

# Settings
workdir = os.getcwd()
backup_command = '/usr/bin/innobackupex --no-timestamp'
prepare_command = '/usr/bin/innobackupex --apply-log'
backup_name = "%s-%s-backup" % (time.strftime("%Y-%m-%d-%H%M-%Z-%a"),
              gethostname())
backup_file = backup_name + ".tar.gz"
backup_file_enc = backup_file + ".enc"
content_type = 'application/gzip'


def md5_for_file(filename, block_size=2 ** 20):
    with open(filename, 'rb') as fh:
        md5 = hashlib.md5()
        while True:
            data = fh.read(block_size)
            if not data:
                break
            md5.update(data)

    return md5.hexdigest()


def backup_task(command):
    LOG.info('backup_task running: %s' % command)
    try:
        subprocess.check_call("%s" % command, shell=True)
    except subprocess.CalledProcessError:
        LOG.critical("%s failed" % command)
    else:
        LOG.info("%s succeeded" % command)


def ensure_container_exists(conn, container):
    headers = {}

    print "checking container <%s>" % container
    try:
        conn.post_container(container, headers=headers)
    except ClientException, err:
        if err.http_status != 404:
            raise
        conn.put_container(container, headers=headers)


def get_secret():
    with open(secret_file, "r") as fh:
        key = fh.readline()

    return key.rstrip()


def upload_file_to_swift(conn,
                         container,
                         filename,
                         file_handle,
                         file_md5,
                         content_type,
                         content_length):
        LOG.info('Uploading %s to swift in the container %s' %
                 (filename, container))
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


def run_backup():
    # get AES key
    secret = get_secret()

    # initial backup
    backup_task("%s %s/%s" % (backup_command, backup_dir, backup_name))

    # apply log
    backup_task("%s %s/%s" % (prepare_command, backup_dir, backup_name))

    # archive the backup
    os.chdir(backup_dir)
    backup_task("tar cvzf %s %s" % (backup_file, backup_name))

    # AES encrypt the file before uploading
    encrypt_file(secret, backup_file, backup_file_enc)

    # Get the md5 for the file
    file_md5 = md5_for_file(backup_file_enc)
    LOG.debug('Backup MD5: %s' % file_md5)

    # Get the length of the file
    content_length = os.stat(backup_file_enc).st_size
    LOG.debug('Backup Length: %s' % content_length)

    # open the file and obtain md5 for etag and upload
    try:
        if use_swift:
            conn = connect_to_swift()
            ensure_container_exists(conn, container)

            with open(backup_file_enc, 'rb') as fh:
                upload_file_to_swift(conn, container,
                                     backup_file_enc,
                                     fh,
                                     file_md5,
                                     content_type=content_type,
                                     content_length=content_length)
    finally:
        # Cleanup the backup directory and files
        LOG.info('Removing directory %s/%s' %
                 (backup_dir, backup_name))
        shutil.rmtree("%s/%s" % (backup_dir, backup_name))
        if purge:
            LOG.info('unlink(%s)' % backup_file)
            os.unlink(backup_file)
        if purge_enc:
            LOG.info('unlink(%s)' % backup_file_enc)
            os.unlink(backup_file_enc)


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


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def connect_to_swift():
    try:
        # establish connection
        conn = Connection(auth_url,
                          username,
                          password,
                          tenant_name=tenant_name,
                          auth_version="2.0")
    except ClientException, err:
        LOG.critical("No Swift Connection: %s", str(err))

    return conn


if __name__ == '__main__':
    run_backup()
