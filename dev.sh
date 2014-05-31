
if [ -d /vagrant ]; then
  VENV=/tmp/.venv-$$
else
  VENV=.venv
fi

rm -rf ${VENV} ; virtualenv --system-site-packages ${VENV} ; . ${VENV}/bin/activate

pip install --upgrade setuptools
pip install python-swiftclient python-keystoneclient 
python setup.py develop

bash
