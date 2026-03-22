# Makefile for TOTP Authenticator (C Version)
# Requires: OpenSSL, SQLite3

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcrypto -lsqlite3

# Target
TARGET = totp_auth

# Source files
SOURCES = totp_auth.c
HEADERS = 

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

clean:
	rm -f $(TARGET) auth.db

test: $(TARGET)
	@echo "=== TOTP Authenticator Test ==="
	@echo ""
	@echo "1. Initializing database..."
	./$(TARGET) --init --db test_auth.db
	@echo ""
	@echo "2. Adding test sites..."
	./$(TARGET) --add "GitHub" "JBSWY3DPEHPK3PXP" --issuer "GitHub" --db test_auth.db
	./$(TARGET) --add "Google" "HS3DOMN2EBV233CC" --issuer "Google" --db test_auth.db
	@echo ""
	@echo "3. Listing sites..."
	./$(TARGET) --list --db test_auth.db
	@echo ""
	@echo "4. Showing current codes..."
	./$(TARGET) --codes --db test_auth.db
	@echo ""
	@echo "=== Test complete ==="

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(TARGET)"

# Android NDK build (for APK integration)
android:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Static build
static: LDFLAGS += -static
static: $(TARGET)
