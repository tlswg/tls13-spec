MD_PREPROCESSOR := python mk-appendix.py

include lib/main.mk

lib/main.mk:
ifneq (,$(shell git submodule status lib 2>/dev/null))
	git submodule sync
	git submodule update --init
else
	git clone --depth 10 -b master https://github.com/martinthomson/i-d-template.git lib
endif
