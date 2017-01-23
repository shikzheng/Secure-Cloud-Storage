# build an executable for the C program
CC=gcc
# compiler flags
CFLAGS = -Wall -std=gnu99 -lssl -lcrypto -I client/
#includes
INCLUDES = client/tinyfiledialogs.c
# the build target executable:
SERVER = Lee-Zheng-server
CLIENT = Lee-Zheng-client

all: $(SERVER) $(CLIENT)

server: $(SERVER)

client: $(CLIENT)

$(SERVER): $(SERVER).c
	$(CC) $(CFLAGS) -o "$(SERVER)" "$(SERVER).c"

$(CLIENT): $(CLIENT).c $(INCLUDES)
	$(CC) $(CFLAGS) -o "$(CLIENT)" "$(CLIENT).c" "$(INCLUDES)"

