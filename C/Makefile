CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcrypto -lsqlite3 -lm

TARGET = totp_auth

all: $(TARGET)

$(TARGET): totp_auth.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)
