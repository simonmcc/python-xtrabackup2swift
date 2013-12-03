# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # All Vagrant configuration is done here. The most common configuration
  # options are documented and commented below. For a complete reference,
  # please see the online documentation at vagrantup.com.

  # Every Vagrant virtual environment requires a box to build off of.
  config.vm.box = "precise64"

  # Install the correct version of chef
  config.vm.provision :shell do |shell|
    shell.inline = %Q{

        # add the Ubuntu Cloud Archive (for python-swiftclient)
        apt-get install python-software-properties
        add-apt-repository cloud-archive:havana

        # add the percona repo (for python-xtrabackup)
        apt-key adv --keyserver keys.gnupg.net --recv-keys 1C4CBDCDCD2EFD2A
        echo "deb http://repo.percona.com/apt precise main" > /etc/apt/sources.list.d/percona.list
        echo "deb-src http://repo.percona.com/apt precise main" >> /etc/apt/sources.list.d/percona.list

        # non-JeOS
        apt-get update
        apt-get install -y python-dev python-virtualenv git-buildpackage dh-make python-swiftclient
        DEBIAN_FRONTEND=noninteractive apt-get install -y percona-server-server-5.5 percona-xtrabackup

        # our bits
        mkdir /etc/mysql-backup /var/lib/mysql-backup
        echo abc123def456ghi7 > /etc/mysql-backup/.backup.key

    }
  end

end
