
draft-ietf-tls-tls13-18.xml: draft-ietf-tls-tls13.xml
	sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-18/' $< > $@
diff-draft-ietf-tls-tls13.html: draft-ietf-tls-tls13-17.txt draft-ietf-tls-tls13.txt
	-$(rfcdiff) --html --stdout $^ > $@
.INTERMEDIATE: draft-ietf-tls-tls13.md
draft-ietf-tls-tls13.md:
	 git show draft-ietf-tls-tls13:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-00.md
draft-ietf-tls-tls13-00.md:
	 git show draft-ietf-tls-tls13-00:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-00/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-01.md
draft-ietf-tls-tls13-01.md:
	 git show draft-ietf-tls-tls13-01:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-01/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-02.md
draft-ietf-tls-tls13-02.md:
	 git show draft-ietf-tls-tls13-02:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-02/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-03.md
draft-ietf-tls-tls13-03.md:
	 git show draft-ietf-tls-tls13-03:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-03/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-04.md
draft-ietf-tls-tls13-04.md:
	 git show draft-ietf-tls-tls13-04:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-04/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-05.md
draft-ietf-tls-tls13-05.md:
	 git show draft-ietf-tls-tls13-05:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-05/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-06.md
draft-ietf-tls-tls13-06.md:
	 git show draft-ietf-tls-tls13-06:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-06/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-07.md
draft-ietf-tls-tls13-07.md:
	 git show draft-ietf-tls-tls13-07:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-07/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-08.md
draft-ietf-tls-tls13-08.md:
	 git show draft-ietf-tls-tls13-08:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-08/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-09.md
draft-ietf-tls-tls13-09.md:
	 git show draft-ietf-tls-tls13-09:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-09/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-10.md
draft-ietf-tls-tls13-10.md:
	 git show draft-ietf-tls-tls13-10:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-10/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-11.md
draft-ietf-tls-tls13-11.md:
	 git show draft-ietf-tls-tls13-11:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-11/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-12.md
draft-ietf-tls-tls13-12.md:
	 git show draft-ietf-tls-tls13-12:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-12/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-13.md
draft-ietf-tls-tls13-13.md:
	 git show draft-ietf-tls-tls13-13:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-13/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-14.md
draft-ietf-tls-tls13-14.md:
	 git show draft-ietf-tls-tls13-14:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-14/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-15.md
draft-ietf-tls-tls13-15.md:
	 git show draft-ietf-tls-tls13-15:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-15/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-16.md
draft-ietf-tls-tls13-16.md:
	 git show draft-ietf-tls-tls13-16:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-16/' > $@
.INTERMEDIATE: draft-ietf-tls-tls13-17.md
draft-ietf-tls-tls13-17.md:
	 git show draft-ietf-tls-tls13-17:draft-ietf-tls-tls13.md | sed -e 's/draft-ietf-tls-tls13-latest/draft-ietf-tls-tls13-17/' > $@
