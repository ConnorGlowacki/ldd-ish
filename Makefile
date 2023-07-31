CC := gcc
CFLAGS := -Wall -Wextra -std=c11
LDFLAGS :=

SOURCES := graph.c ldd-ish.c
OBJECTS := $(SOURCES:.c=.o)
EXECUTABLE := ldd-ish

.PHONY: all clean

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
