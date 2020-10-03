MD_PREPROCESSOR := python3 mk-appendix.py
XML_RESOURCE_ORG_PREFIX = https://xml2rfc.tools.ietf.org/public/rfc

include lib/main.mk

lib/main.mk:
ifneq (,$(shell git submodule status lib 2>/dev/null))
	git submodule sync
	git submodule update --init
else
	git clone --depth 10 -b main https://github.com/martinthomson/i-d-template.git lib
endif
