CC = gcc
CFLAGS = -Wall -ggdb -D_GNU_SOURCE
CFLAGS += $(shell pkg-config --cflags dbus-1)
LDFLAGS = $(shell pkg-config --libs dbus-1 libnih libnih-dbus)

all: cgmanager client movepid getpidcgroup chowncgroup

clean:
	rm -f \
		org.linuxcontainers.cgmanager.h org.linuxcontainers.cgmanager.c \
		cgmanager-client.c cgmanager-client.h \
		cgmanager-client.o getpidcgroup \
		cgmanager \
		movepid cgmanager chowncgroup

org.linuxcontainers.cgmanager.h:
	nih-dbus-tool --package=cgmanager --mode=object --prefix=cgmanager --default-interface=org.linuxcontainers.cgmanager0_0 org.linuxcontainers.cgmanager.xml

cgmanager: org.linuxcontainers.cgmanager.h fs.h fs.c cgmanager.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE org.linuxcontainers.cgmanager.c cgmanager.c fs.c $(LDFLAGS) -o cgmanager

getpidcgroup: getpidcgroup.c
	$(CC) $(CFLAGS) getpidcgroup.c $(LDFLAGS) -o getpidcgroup

chowncgroup: chowncgroup.c
	$(CC) $(CFLAGS) chowncgroup.c $(LDFLAGS) -o chowncgroup

movepid: movepid.c
	$(CC) $(CFLAGS) movepid.c $(LDFLAGS) -o movepid

client: cgmanager-client.o

cgmanager-client.o: cgmanager-client.h cgmanager-client.c
		$(CC) $(CFLAGS) -c -I. cgmanager-client.c $(LDFLAGS)

cgmanager-client.h:
	nih-dbus-tool \
    --package=cgmanager \
    --mode=proxy --prefix=cgmanager \
    --default-interface=org.linuxcontainers.cgmanager0_0 \
    --output=cgmanager-client.c \
	org.linuxcontainers.cgmanager.xml

run-server: cgmanager
	./cgmanager --debug

run-client:
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'' string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getMyCgroup string:'memory'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"serge/b"
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"serge/b" string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"../serge/b" string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"b"
