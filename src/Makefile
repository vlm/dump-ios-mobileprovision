
CFLAGS += -I.

all: dump-ios-mobileprovision

dump-ios-mobileprovision: dump-ios-mobileprovision.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o dump-ios-mobileprovision *.c

clean:
	rm -f *.o dump-ios-mobileprovision
