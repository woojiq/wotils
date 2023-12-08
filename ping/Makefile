TARGET = ping
BUILD_DIR = build
SRC_DIR = src
INCLUDES = $(wildcard include/*.h)
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))

CC = gcc
CFLAGS = -Wall

all: $(BUILD_DIR) $(BUILD_DIR)/$(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDES)
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD_DIR)/$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD_DIR)

# Kills `ping` process with SIGINT to emulate packete loss.
# Run this script with `sudo` since `ping` runs with sudo too.
.SILENT: sigint
sigint:
	while true; do
	  p=$$(pidof "ping")
	  if [ "$$p" ]; then
	    kill -INT "$$p"
	    break
	  fi
	done

.ONESHELL:

.PHONY: all clean $(BUILD_DIR) sigint
