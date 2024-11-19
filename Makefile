CC = gcc
CFLAGS =
objects = friend
all: $(objects)

$(objects): %: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f ${objects}	
