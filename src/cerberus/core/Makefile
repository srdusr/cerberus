# Compiler and flags
CC = gcc
CFLAGS = -fPIC -O2 -Wall -Wextra
LDFLAGS = -shared -fPIC -lssl -lcrypto -luuid
TARGET = libcerberus.so
SOURCES = cerberus.c
OBJECTS = $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJECTS)

install: $(TARGET)
	cp $(TARGET) /usr/local/lib/
	ldconfig

uninstall:
	rm -f /usr/local/lib/$(TARGET)
	ldconfig

test: $(TARGET)
	python3 -m pytest tests/
