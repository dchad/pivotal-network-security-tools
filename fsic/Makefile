# FSIC - File System Integrity Checker
# Derek Chadwick 18910502
# ICT539 Project

CC=gcc
CFLAGS=-c -Wall -ansi
LDFLAGS=-static
LIBS=-lmhash
SOURCES=fsic.c password.c update.c check.c self.c log.c hmac.c util.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=fsic
UNITEXE=unit
UNITSOURCES=unit.c password.c update.c check.c self.c log.c hmac.c util.c
UNITOBJECTS=$(UNITSOURCES:.c=.o)
CIK1 := $(shell date +%s | md5sum) 
CIK2 := $(shell date +%s | sha256sum) 
CIK3 := $(shell od -N4 -An -i /dev/random | md5sum)
CIK4 := $(shell od -N4 -An -i /dev/random | sha256sum)

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(CFLAGS) -DKEY1="\"$(CIK4)\"" $< -o $@

strip:
	strip fsic

clean: 
	rm *.o fsic

test: $(UNITSOURCES) $(UNITEXE)

$(UNITEXE): $(UNITOBJECTS)
	$(CC) $(LDFLAGS) $(UNITOBJECTS) $(LIBS) -o $@

cleanunit:
	rm *.o unit

