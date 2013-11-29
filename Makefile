all: cgmanager movepid

clean:
	rm -f org.linuxcontainers.cgmanager.h org.linuxcontainers.cgmanager.c cgmanager

org.linuxcontainers.cgmanager.h:
	nih-dbus-tool --package=cgmanager --mode=object --prefix=cgmanager --default-interface=org.linuxcontainers.cgmanager0_0 org.linuxcontainers.cgmanager.xml

cgmanager: org.linuxcontainers.cgmanager.h fs.h fs.c cgmanager.c
	gcc -D_GNU_SOURCE $(shell pkg-config --cflags dbus-1) org.linuxcontainers.cgmanager.c cgmanager.c fs.c -ldbus-1 -lnih -lnih-dbus -o cgmanager

movepid: movepid.c
	gcc -g -D_GNU_SOURCE $(shell pkg-config --cflags dbus-1) movepid.c -ldbus-1 -lnih -lnih-dbus -o movepid

run-server: cgmanager
	./cgmanager --debug

run-client:
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:'' string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getMyCgroup string:'memory'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"serge/b"
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"serge/b" string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.getValue string:'memory' string:"../serge/b" string:'memory.usage_in_bytes'
	dbus-send --print-reply --address=unix:path=/tmp/cgmanager --type=method_call /org/linuxcontainers/cgmanager org.linuxcontainers.cgmanager0_0.Create string:'memory' string:"b"
