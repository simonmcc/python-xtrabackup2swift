# python-xtrabackup2swift common bits
#
# Copyright 2012 Hewlett-Packard Development Company, L.P. All Rights Reserved.
#
# Author: Simon McCartney <simon.mccartney@hp.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations

import sys
import os
import time
import shutil
import subprocess
import hashlib
import logging
import random
import struct
from pwd import getpwnam
from socket import gethostname
from Crypto.Cipher import AES
from swiftclient import Connection, ClientException
from optparse import OptionParser

LOG = logging.getLogger(__name__)


def cli_options():
    parser = OptionParser()

    parser.add_option("--use-swift",
                      action="store_false",
                      dest="use_swift",
                      default=True,
                      help="Upload backup to Swift (default)")

    parser.add_option("--no-swift",
                      action="store_false",
                      dest="use_swift",
                      default=True,
                      help="Do not upload backup to Swift")

    parser.add_option("-l", "--log",
                      dest="log_file",
                      help="Log file",
                      metavar="LOG")

    parser.add_option("-c", "--container",
                      dest="container",
                      default=os.environ.get('BACKUP_CONTAINER', 'db_backup'),
                      help="Swift Container used to store the backup objects. \
                      Defaults to env[BACKUP_CONTAINER]",
                      metavar="CONTAINER")

    parser.add_option("-b", "--backup-dir",
                      default="/var/lib/mysql-backup",
                      dest="backup_dir",
                      help="Backup directory",
                      metavar="BACKUP_DIR")

    parser.add_option("-s", "--secret-file",
                      default="/etc/mysql-backup/.backup.key",
                      dest="secret_file",
                      help="File containing the key used to encrypt/decrypt \
                      the backup",
                      metavar="SECRET_FILE")

    parser.add_option("-u", "--os-username",
                      dest="username",
                      default=os.environ.get('OS_USERNAME', ''),
                      help="OpenStack username. Defaults to env[OS_USERNAME]",
                      metavar="USER")

    parser.add_option("-p", "--os-password",
                      dest="password",
                      default=os.environ.get('OS_PASSWORD', ''),
                      help="Swift Password. Defaults to env[OS_PASSWORD]",
                      metavar="PASSWORD")

    parser.add_option("-r", "--os-region-name",
                      dest="region",
                      default=os.environ.get('OS_REGION_NAME', ''),
                      help="Swift Region. Defaults to env[OS_REGION_NAME]",
                      metavar="REGION")

    parser.add_option("-t", "--os-tenant-name",
                      dest="tenant_name",
                      default=os.environ.get('OS_TENANT_NAME', ''),
                      help="Tenant Name. Defaults to env[OS_TENANT_NAME]",
                      metavar="TENANT")

    parser.add_option("-a", "--os-auth-url",
                      dest="auth_url",
                      default=os.environ.get('OS_AUTH_URL', ''),
                      help="Auth URL", metavar="AUTH_URL")

    parser.add_option("-d", "--datadir",
                      dest="datadir", default="/var/lib/mysql",
                      help="MySQL datadir", metavar="datadir")

    parser.add_option("-D", "--purge-on-disk",
                      action="store_false",
                      dest="purge",
                      default="false",
                      help="Purge Backup on disk", metavar="PURGE")

    parser.add_option("-P", "--purge-enc-on-disk",
                      action="store_false",
                      dest="purge_enc",
                      default="false",
                      help="Purge Backup on disk", metavar="PURGE_ENC")

    parser.add_option("-w", "--work-dir",
                      dest="workdir",
                      default=os.getcwd(),
                      metavar="Work Directory",
                      help="Top level restoration directory")

    parser.add_option("-f", "--file",
                      dest="restore_file_enc",
                      default="",
                      metavar="RESTORE_FILE_ENC",
                      help="Name of file to restore from")

    return parser.parse_args()


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
    try:
        subprocess.check_call("%s" % command, shell=True)
    except subprocess.CalledProcessError:
        LOG.critical("%s failed" % command)
    else:
        LOG.info("%s succeeded" % command)


def ensure_container_exists(conn, container):
    headers = {}

    LOG.debug("Checking container <%s> exists" % container)
    try:
        meta = conn.head_container(container)
    except ClientException as err:
        if err.http_status != 404:
            raise
        conn.put_container(container, headers=headers)


def get_secret(secret_file):
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


def run_backup(options):
    # Settings
    backup_command = '/usr/bin/innobackupex --no-timestamp'
    prepare_command = '/usr/bin/innobackupex --apply-log'
    backup_name = "%s-%s-backup" % (time.strftime("%Y-%m-%d-%H%M-%Z-%a"),
                                    gethostname())
    backup_file = backup_name + ".tar.gz"
    backup_file_enc = backup_file + ".enc"
    backup_key = "/etc/mysql-backup/.backup.key"
    content_type = 'application/gzip'

    # get AES key
    backup_key = get_secret(options.secret_file)

    # initial backup
    backup_task("%s %s/%s" % (backup_command, options.backup_dir, backup_name))

    # apply log
    backup_task("%s %s/%s" % (prepare_command, options.backup_dir, backup_name))

    # archive the backup
    os.chdir(options.backup_dir)
    backup_task("tar cvzf %s %s" % (backup_file, backup_name))

    # AES encrypt the file before uploading
    encrypt_file(backup_key, backup_file, backup_file_enc)

    # Get the md5 for the file
    file_md5 = md5_for_file(backup_file_enc)
    LOG.debug('Backup MD5: %s' % file_md5)

    # Get the length of the file
    content_length = os.stat(backup_file_enc).st_size
    LOG.debug('Backup Length: %s' % content_length)

    # open the file and obtain md5 for etag and upload
    try:
        if options.use_swift:
            conn = connect_to_swift(options)
            ensure_container_exists(conn, options.container)

            with open(backup_file_enc, 'rb') as fh:
                upload_file_to_swift(conn, options.container,
                                     backup_file_enc,
                                     fh,
                                     file_md5,
                                     content_type=content_type,
                                     content_length=content_length)
    finally:
        # Cleanup the backup directory and files
        LOG.info('Removing directory %s/%s' %
                 (options.backup_dir, backup_name))
        shutil.rmtree("%s/%s" % (options.backup_dir, backup_name))
        if options.purge:
            LOG.info('unlink(%s)' % backup_file)
            os.unlink(backup_file)
        if options.purge_enc:
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


def connect_to_swift(options):
    LOG.info("attempting to connect to %s as user:%s tenant_name:%s" % (options.auth_url,
                                                                        options.username,
                                                                        options.tenant_name))

    if options.region:
        os_options = {}
        os_options['region_name'] = options.region
    else:
        os_options = None

    try:
        # establish connection
        conn = Connection(options.auth_url,
                          options.username,
                          options.password,
                          tenant_name=options.tenant_name,
                          os_options=os_options,
                          auth_version="2.0")
    except ClientException, err:
        LOG.critical("No Swift Connection: %s", str(err))

    return conn


def restore_task(command):
    try:
        subprocess.check_call("%s" % command, shell=True)
    except subprocess.CalledProcessError:
        LOG.error("%s failed" % command)
    else:
        LOG.debug("%s succeeded" % command)


def download_file_from_swift(conn, container, filename):
    LOG.info("Downloading file %s from container %s" % (filename, container))

    try:
        headers, body = conn.get_object(container,
                                        filename,
                                        resp_chunk_size=65536)
    except ClientException, err:
        LOG.critical('Download failed: %s', str(err))
    else:
        LOG.info('Download succeeded')

    s_etag = headers.get('etag')
    md5 = hashlib.md5()
    fh = open(filename, 'wb')
    read_length = 0
    for chunk in body:
        fh.write(chunk)
        read_length += len(chunk)
        LOG.debug("read_length: %d" % read_length)
        if md5:
            md5.update(chunk)
    fh.close()
    f_etag = md5.hexdigest()
    # need to figure out how to handle this
    if (s_etag != f_etag):
        LOG.error("MD5 for file from swift doesn't match that which was "
                  "downloaded!")
        LOG.error("%s != %s" % (s_etag, f_etag))


def list_backups(conn, container):
    """
       List backups for informational purposes
    """
    try:
        marker = ''
        while True:
            items = conn.get_container(container, marker=marker)[1]
            if not items:
                break
            print "Backups to restore from:"
            print "------------------------"
            for item in items:
                print "%s" % item.get('name', item.get('subdir'))
            marker = items[-1].get('name', items[-1].get('subdir'))
    except ClientException, err:
        if err.http_status != 404:
            raise

        # TODO: handle the container not being found/existing
        # print 'Container %s not found' % repr(args[0])


def run_restoration(options):
    # get AES key
    secret = get_secret(options.secret_file)

    restore_dir = options.workdir + '/' + 'restore'
    restore_conf = 'restore.cnf'
    restore_file_enc = options.restore_file_enc

    conn = connect_to_swift(options)

    # if not supplied by command line options, then get from user
    if restore_file_enc == "":
        list_backups(conn, options.container)
        LOG.info("container %s" % options.container)
        print "What file do you wish to restore from? Enter: "
        restore_file_enc = sys.stdin.readline().rstrip()

    # get name of tar.gz
    restore_file = restore_file_enc.strip('.enc')
    # get restore name
    restore_name = restore_file.strip('.tar.gz')

    if not os.path.exists(options.workdir):
        os.mkdir(options.workdir)

    os.chdir(options.workdir)

    download_file_from_swift(conn, options.container, restore_file_enc)

    # AES encrypt the file before uploading
    decrypt_file(secret, restore_file_enc, restore_file)

    restore_task("tar xvzf %s" % restore_file)
    LOG.info("Restored to %s" % options.workdir)

    # remove old link if exists
    if os.path.exists(restore_dir):
        os.unlink(restore_dir)

    # make sure this data directory is owned by mysql:mysql
    chown_r(options.workdir + '/' + restore_name,
            getpwnam('mysql').pw_uid, getpwnam('mysql').pw_gid)

    # easy link to reference
    os.symlink(restore_name, restore_dir)
    os.chown(restore_dir, getpwnam('mysql').pw_uid, getpwnam('mysql').pw_gid)

    # remove if exists
    if os.path.exists(options.workdir + '/' + restore_conf):
        os.unlink(options.workdir + '/' + restore_conf)

    r = open(options.workdir + '/' + restore_conf, 'w')
    r.write("[mysqld]\n")
    r.write("data_dir = %s" % restore_dir)
    r.close()

    # cleanup
    os.unlink(restore_file_enc)
    os.unlink(restore_file)

    LOG.info("The restoration is ready to use "
             "Now you will need to start mysql with "
             "restored data\nby copying restore_conf to /etc/mysql/conf.d "
             "and restarting mysql.\n"
             "IMPORTANT: you may have to make sure to back up existing "
             "data directory if it exists by copying it elsewhere!")


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


def chown_r(starting_dir, uid, gid):
    for root, dirs, files in os.walk(starting_dir):
        os.chown(os.path.join(starting_dir, root), uid, gid)
        for f in files:
            os.chown(os.path.join(starting_dir, root, f), uid, gid)
