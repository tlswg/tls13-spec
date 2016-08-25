#!/usr/bin/env python
from __future__ import print_function
import re
import sys

APPENDICES = {}
IN_APPENDIX = None
CURRENT = ""

def print_syntax(val):
    vl = val.split("\n")
    last_empty = False

    for v in vl:
        if v == "":
            if not last_empty:
                print()
            last_empty = True
        else:
            last_empty = False
            print(v)
    print()


for l in sys.stdin:
    if not IN_APPENDIX:
        m = re.match('%%% (.*)$', l)
        if m is not None:
            IN_APPENDIX = m.group(1)
        else:
            m = re.match('%%(#+|!) (.*)$', l)
            if m is not None:
                if m.group(1) != '!':
                    print("%s %s" % (m.group(1), m.group(2)))
                print_syntax(APPENDICES[m.group(2)])
                del APPENDICES[m.group(2)]
                print()
            else:
                print(l, end='')
    else:
        # Strip out everything marked as RESERVED
        if l.find("RESERVED") == -1:
            print(l, end='')
        m = re.match("\S", l)
        if m is None:
            CURRENT += l
        else:
            CURRENT += "\n"
            if not IN_APPENDIX in APPENDICES:
                APPENDICES[IN_APPENDIX] = ""
            APPENDICES[IN_APPENDIX] += CURRENT
            CURRENT = ""
            IN_APPENDIX = None

if len(APPENDICES) > 0:
    sys.stderr.write("Unused figures: " + str(list(APPENDICES.keys())) + "\n")
    sys.exit(1)
