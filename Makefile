CC := gcc
CFLAGS := -ldl -Wall -Wextra

SRC := ldd-ish.c
OUT := ldd-ish

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC)

debug: CFLAGS += -gcc
debug: $(OUT)

clean:
	rm -f $(OUT)