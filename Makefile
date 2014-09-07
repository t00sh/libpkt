.PHONY: clean

VERSION = 1.0.0
PACKAGE = libpkt

CC = gcc
AR = ar
CFLAGS = -O2 -Wall -Wextra -Wwrite-strings -Wstrict-prototypes -Wuninitialized
CFLAGS += -Wunreachable-code -g -fstack-protector-all
CFLAGS += -I include/
CFLAGS += -DVERSION="\"$(VERSION)\"" -DPACKAGE="\"$(PACKAGE)\""

SRC  = $(wildcard src/*.c)
OBJ  = $(SRC:%.c=%.o)

TEST_SRC  = $(wildcard test/*.c)
TEST_OBJ  = $(TEST_SRC:%.c=%.o)

LIBRARY = $(PACKAGE).a
TEST = test.bin

all: $(LIBRARY) $(TEST)

$(TEST): $(TEST_OBJ) $(LIBRARY)
	@echo " LINK $(TEST)" ;
	@$(CC) $(CFLAGS) $(TEST_OBJ) $(LIBRARY) -o $(TEST)

$(LIBRARY): $(OBJ)
	@echo " AR $(LIBRARY)" ;
	@$(AR) rcs $(LIBRARY) $(OBJ) ;

%.o:%.c
	@echo " CC $@" ;
	@$(CC) $(CFLAGS) -c $< -o $@ ;

clean:
	rm $(LIBRARY) $(OBJ) $(TEST_OBJ) $(TEST)
	find . -name "*~" -delete
