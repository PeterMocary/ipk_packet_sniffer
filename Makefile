LOGIN=xmocar00
TARGET=ipk-sniffer
CC=gcc
CFLAGS= -lpcap -Wall -g

build: clean ipk-sniffer.c
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET)

package:
	tar cvzf $(LOGIN).tar Makefile $(TARGET).c manual.pdf README.md

clean:
	rm -f $(TARGET)