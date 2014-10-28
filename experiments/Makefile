all:
	cc -g -o st scantest.c -lbluetooth -lcurses -ltinfo
	cc -g -o at advertisetest.c -lbluetooth -lcurses
	cc -g -o ibeacon ibeacon.c -lbluetooth

clean:
	rm -f st at ibeacon
