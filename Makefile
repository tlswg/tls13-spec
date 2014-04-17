xml2rfc ?= xml2rfc
kramdown-rfc2629 ?= kramdown-rfc2629
idnits ?= idnits

draft := draft-ietf-tls-tls13
current_ver := $(shell git tag | grep "$(draft)" | tail -1 | sed -e"s/.*-//")
ifeq "${current_ver}" ""
next_ver ?= 00
else
next_ver ?= $(shell printf "%.2d" $$((1$(current_ver)-99)))
endif
next := $(draft)-$(next_ver)

.PHONY: latest submit clean

latest: $(draft).txt $(draft).html

submit: $(next).txt

idnits: $(next).txt
	$(idnits) $<

clean:
	-rm -f $(draft).txt $(draft).html
	-rm -f $(next).txt $(next).html
	-rm -f $(draft)-[0-9][0-9].xml

$(next).md: $(draft).md
	sed -e"s/$(basename $<)-latest/$(basename $@)/" $< > $@

%.xml: %.md
	$(kramdown-rfc2629) $< > $@

%.txt: %.xml
	$(xml2rfc) $< $@

%.html: %.xml
	$(xml2rfc) $< $@
