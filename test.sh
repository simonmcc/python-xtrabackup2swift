#!/bin/bash
#
# backup & restore test

if [ -d /vagrant ]; then
  VENV=/tmp/.venv-$$
else
  VENV=.venv
fi

rm -rf ${VENV} ; virtualenv --system-site-packages ${VENV} ; . ${VENV}/bin/activate

pip install --upgrade setuptools
pip install python-swiftclient python-keystoneclient

python setup.py develop

# load in some swift details
. .swift-aw2

# do a backup
echo
echo
echo BACKUP STARTED
echo
sudo ./bin/xtrabackup2swift --container=xtrabackup-test --secret-file=backup.key --os-user=$OS_USERNAME --os-password=$OS_PASSWORD --os-tenant-name=$OS_TENANT_NAME --os-auth-url=$OS_AUTH_URL
echo
echo BACKUP COMPLETE
echo

# find the backup we just made
LATEST=`swift --os-user=$OS_USERNAME --os-password=$OS_PASSWORD --os-tenant-name=$OS_TENANT_NAME --os-auth-url=$OS_AUTH_URL --os-region-name=region-a.geo-1 list xtrabackup-test| tail -1`
if [ -z "$LATEST" ] ;
then
    echo "Couldn't find any backups"
    exit 2
else
    echo "Found ${LATEST} as the latest backup"
fi

# restore it
echo
echo
echo RESTORE STARTED
echo
service mysql stop
sudo ./bin/swift2xtrabackup --container=xtrabackup-test --secret-file=backup.key --os-user=$OS_USERNAME --os-password=$OS_PASSWORD --os-tenant-name=$OS_TENANT_NAME --os-auth-url=$OS_AUTH_URL --file=$LATEST --work-dir=/var/lib/mysql
echo
echo RESTORE COMPLETE
echo

deactivate
rm -rf $VENV
