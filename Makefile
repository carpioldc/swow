##						 ##
#	MAIN MAKEFILE #
##             ##

CC= gcc
CFLAGS= -Wall # -pedantic -ansi
LIBS = -lpcap
OBJECTS= wake_on_wan.o loadenv.o rc_funcs.o
SRC_DIR= ./src
OBJ_DIR= ./objects
HDR_DIR= ./include
INSTALL_DIR = /usr/local/bin
OBJS = $(patsubst %,$(OBJ_DIR)/%,$(OBJECTS))


all: mkdir wow

objects: $(OBJECTS)

wow: $(OBJECTS)
	$(CC) $(LIBS) $(OBJS) -o $@

mkdir:
	mkdir -p $(OBJ_DIR)

%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I $(HDR_DIR) -c $< -o $(OBJ_DIR)/$@

clean: 
	rm -rf $(OBJ_DIR)

install: wow
	install -m 0755 $< $(INSTALL_DIR)
