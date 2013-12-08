#!/usr/bin/env python

import os
import subprocess
import hashlib
import logging
import struct
import sys
from Crypto.Cipher import AES
from swiftclient import Connection, ClientException
from optparse import OptionParser
from pwd import getpwnam

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)

parser = OptionParser()

parser.add_option("-w", "--work-dir",
                  dest="workdir",
                  default="",
                  metavar="Work Directory",
                  help="Top level restoration directory")

parser.add_option("-f", "--file",
                  dest="restore_file_enc",
                  default="",
                  metavar="RESTORE_FILE_ENC",
                  help="Name of file to restore from")

parser.add_option("-c", "--container",
                  dest="container",
                  default="",
                  metavar="CONTAINER",
                  help="Container where backups exist")

parser.add_option("-s", "--secret-file",
                  default="/etc/mysql-backup/.backup.key",
                  dest="secret_file",
                  help="Secret file",
                  metavar="SECRET FILE")

(options, args) = parser.parse_args()

secret_file = options.secret_file
container = options.container
workdir = options.workdir
if workdir == "":
    workdir = os.getcwd()

# globals, set later
restore_name = ''
restore_file = ''

# Settings

restore_dir = workdir + '/' + 'restore'
restore_conf = 'restore.cnf'

restore_file_enc = options.restore_file_enc

try:
    # establish connection
    conn = Connection(os.environ['OS_AUTH_URL'],
                      os.environ['OS_USERNAME'],
                      os.environ['OS_PASSWORD'],
                      tenant_name=os.environ['OS_TENANT_NAME'],
                      auth_version="2.0")
except ClientException, err:
    LOG.critical("No Swift Connection: %s", str(err))


def restore_task(command):
    try:
        subprocess.check_call("%s" % command, shell=True)
    except subprocess.CalledProcessError:
        LOG.error("%s failed" % command)
    else:
        LOG.debug("%s succeeded" % command)


def get_secret():
    with open(secret_file, "r") as fh:
        key = fh.readline()

    return key.rstrip()


def download_file_from_swift(container, filename):
    LOG.info("Downloading file %s from container %s" %
             (filename, container))

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


def list_backups(container):
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
        if not args:
            print 'Account not found'
        else:
            print 'Container %s not found' % repr(args[0])


def run_restoration():
    # get AES key
    secret = get_secret()

    if not os.path.exists(workdir):
        os.mkdir(workdir)

    os.chdir(workdir)

    download_file_from_swift(container, restore_file_enc)

    # AES encrypt the file before uploading
    decrypt_file(secret, restore_file_enc, restore_file)

    restore_task("tar xvzf %s" % restore_file)

    # remove old link if exists
    if os.path.exists(restore_dir):
        os.unlink(restore_dir)

    # make sure this data directory is owned by mysql:mysql
    chown_r(workdir + '/' + restore_name,
            getpwnam('mysql').pw_uid, getpwnam('mysql').pw_gid)

    # easy link to reference
    os.symlink(restore_name, restore_dir)
    os.chown(restore_dir, getpwnam('mysql').pw_uid, getpwnam('mysql').pw_gid)

    # remove if exists
    if os.path.exists(workdir + '/' + restore_conf):
        os.unlink(workdir + '/' + restore_conf)

    r = open(workdir + '/' + restore_conf, 'w')
    r.write("[mysqld]\n")
    r.write("data_dir = %s" % restore_dir)
    r.close()

    # cleanup
    os.unlink(restore_file_enc)
    os.unlink(restore_file)

    LOG.info("The restoration is ready to use"
             "Now you will need to start mysql with "
             "restored data\nby copying restore_conf to /etc/mysql/conf.d"
             " and restarting mysql.\n"
             "IMPORTANT: you may have to make sure to back up existing"
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


if __name__ == '__main__':
    # if not supplied by command line options, then get from user
    if restore_file_enc == "":
        print "container %s" % container
        list_backups(container)
        print "What file do you wish to restore from? Enter: "
        restore_file_enc = sys.stdin.readline().rstrip()
    # get name of tar.gz
    restore_file = restore_file_enc.strip('.enc')
    # get restore name
    restore_name = restore_file.strip('.tar.gz')
    # run the restoration
    run_restoration()
