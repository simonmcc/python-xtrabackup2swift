# python-xtrabackup2swift

scripts to make running Percona's xtrabackup & storing the backups in Swift easier


## Installation

	pip install --upgrade setuptools
	python setup.py install

## Development (Linux/Ubuntu 12.04)
	
	sudo apt-get update
	sudo apt-get install python-dev python-virtualenv
	rm -rf /tmp/.venv/ ; virtualenv /tmp/.venv/ ; . /tmp/.venv/bin/activate
	pip install --upgrade setuptools
	pip install python-swiftclient
	python setup.py develop

### Building Debian/Ubuntu packages
	
	sudo apt-get update
	sudo apt-get install -y git-buildpackage build-essential cdbs dh-make python-dev python-virtualenv
	
	# build unsigned (FIXME)
	git-buildpackage -us -uc

	# TODO: move to pbr so that we can auto-generate version strings from commit SHA1

# Development (Mac/OSX)
	
	rm -rf .venv/ ; virtualenv .venv/ ; . .venv/bin/activate
	# something is broken in the python-swiftclient
	# dependency chain install via pip as setuptools borks
	pip install python-swiftclient
	python setup.py develop


# Publish to PyPi

	python setup.py sdist upload

