# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=c99 -g
CFLAGS_DISK := -Wall -Wextra -std=c99 -g 
AR := ar
ARFLAGS := rcs

# Source files
SRC := fs.c disk.c
OBJ := fs.o disk.o
LIB := libfs.a

all: $(LIB)

fs.o: fs.c
	$(CC) $(CFLAGS) -c $< -o $@

disk.o: disk.c
	$(CC) $(CFLAGS_DISK) -c $< -o $@

$(LIB): $(OBJ)
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f $(OBJ) $(LIB)