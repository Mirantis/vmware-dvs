PBIN=/usr/bin
PLIB=/usr/lib/python2.7/dist-packages/

all: clean
	fpm -s python -t deb --python-install-bin $(PBIN)  --python-install-lib $(PLIB) setup.py

clean:
	rm -rf *.deb
