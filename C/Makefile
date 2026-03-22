CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcrypto -lsqlite3 -lm

# Source files
SRC = totp_auth.c base32.c totp.c storage.c

# Object files
OBJ = $(SRC:.c=.o)

# Output
TARGET = totp_auth

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c totp_auth.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
