all: webexec

webexec: *.go
	go build -o webexec *.go

install: webexec
	mkdir -p ${DESTDIR}/usr/bin
	mkdir -p ${DESTDIR}/etc

	cp config.xml ${DESTDIR}/etc/webexec.xml
	mv webexec ${DESTDIR}/usr/bin/

clean:
	rm -f webexec
	dh_clean
