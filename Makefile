arp_spoof: arp_spoof.c arp_spoof.h
	gcc -o arp_spoof arp_spoof.c -lpcap

clean:
	rm arp_spoof

