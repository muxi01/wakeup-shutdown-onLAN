CFLAGS = -Wall -O2
LDFLAGS = -static -lpthread -Wl,--no-as-needed

SRC = wol-server.c
TARGET = wol.server
TARGET2 = shutdown.worker

all:
	gcc $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)
	go build -o $(TARGET2) shutdown_worker.go
	GOOS=windows GOARCH=amd64 go build -o $(TARGET2).exe shutdown-worker.go

armv7:
	$(CROSS_COMPILE)gcc $(CFLAGS) -march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)   $(TARGET2)  $(TARGET2).exe
