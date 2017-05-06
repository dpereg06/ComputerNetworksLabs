/*****
 Receive HELLO WORLD from Ethertype 0x07ff, use a pcap filter
 
 *****/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

unsigned char * echoFrame;
unsigned int length;


/*
 * EtherType
 * Frame bytes ( 12 and 13 )
 */
void printEthertype(u_char *frame) {

    printf("Ethertype: HEX: %02x%02x, ", frame[12], frame[13]);
    printf("Decimal: %hu\n", ntohs(*(uint16_t *) (&(frame[12]))));

    fflush(stdout);

}

/*
 * Print the MAC addresses
 */
void printMac(u_char *frame) {

    int i;

    printf("Destination MAC:\t");

    /*
     * First six bytes of frame ( 0 - 5 )
     * DESTINATION MAC ADDRESS
     */
    for (i = 0; i < 6; i++) {
        printf("%02x:", frame[i]);
    }

    printf("\nSource MAC:\t");

    /*
     * Ensuing six bytes of frame ( 6 - 11 )
     * SOURCE MAC ADDRESS
     */
    for (; i < 12; i++) {
        if (i != 11)
            printf("%02x:", frame[i]);
        else
            printf("%02x", frame[i]);
    }

    printf("\n");
    fflush(stdout);
}

/*
 * pcap_pkthdr: Generic per-packet information, as supplied by libpcap:
 *      packet lengths and the packet timestamp
 *
 * u_char* frame: Bytes of data from the frame itself with all
 *                the wire bits stripped
 */
void printFrameHeader(u_char* frame, unsigned frameLength) {

    printf("\n\n");
    printf("---------------------------------------\n");
    printf("Off-wire frame length: %u\n", frameLength);
    printMac(frame);
    printEthertype(frame);
    printf("---------------------------------------\n");

}

void printPayload(char *payload, int frameLength) {

    //                                 DST MAC(6) + SRC MAC(6) + Ethertype(2)
    unsigned payLength = frameLength - (6 + 6 + 2);

    int i;
    
    printf("Payload:\n");
    
    for(i = 0; i < payLength; i++){
        printf("%c", payload[i]);
    }
    
    printf("\n\n");
    fflush(stdout);
}

/*
 * Callback function specified into  pcap_loop(...)
 * This callback will capture 1 frame whose header is available in frameHeader
 * The frame itself is stored into frame
 */
void getNewFrame(u_char *dummy, const struct pcap_pkthdr *frameHeader, u_char *frame) {
    
    /****
     From pcap.h:
     
     struct pcap_pkthdr {
        struct timeval ts;	// time stamp
        bpf_u_int32 caplen;     // length of portion present
        bpf_u_int32 len;	// length this packet (off wire)
     };
     
     ****/

    /********
    unsigned int frameLength = frameHeader->len; //Off-wire length of this frame
    unsigned int caplen = frameHeader->caplen;
    
    //Ethertype sought for is: 0x07ff
    if (frame[12] == 0x07 && frame[13] == 0xff) {

        frameCount++; //Counts only frames of Ethertype = 0x07ff
        
        printf("---> frameHeader->caplen = %u\n", frameHeader->caplen);
   
        printFrameHeader(frame, frameLength);
        printPayload(&frame[14], frameLength);

    }

    */
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_t  *pcapStatus;
    pcapStatus = pcap_open_live("wlan0", BUFSIZ, 0, 10, errbuf);
    
        printf("---> frameHeader->caplen = %u\n", frameHeader->caplen);
   
        printFrameHeader(frame, frameHeader->caplen);
        printPayload(&frame[14], frameHeader->caplen);
        

    fflush(stdout);
    
    printf("\nReceived\n");
    
    unsigned char aux;
    
    int i;
    
    for(i=0;i<6;i++){
    		aux = frame[i];
    		frame[i] = frame[i+6];
    		frame[i+6] = aux;
    }
    
    printMac(frame);
    
    //The pcap error string buffer
        
    if (pcapStatus == (pcap_t *) NULL) {
        printf("Call to pcap_open_live() returned error: %s\n", errbuf);
        exit(4);
    }
    
    printf("\n\nSending frame:\n");
    fflush(stdout);
    
    if (pcap_inject(pcapStatus, frame, frameHeader->caplen) == -1) {
        printf("Inject error\n");
        pcap_perror(pcapStatus, 0);
        pcap_close(pcapStatus);
        exit(1);
    }

}

/*
 * printIPandMask(char *defaultDev)
 *
 * Prints the IP address and the Network mask configured into the network
 * device whose p_cap name is into defatultDevice
 *
 */
void printIPandMask(char *defaultDev) {
    bpf_u_int32 netAddress;
    bpf_u_int32 netMask;
    struct in_addr inAddress;
    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Network device name = %s\n", defaultDev);

    /*
     * pcap_lookupnet() returns the IP and the netmask of the passed device
     * Actual parameters netAddress and netMask are passed by reference since
     * we want them to hold the IP and the netmask, they are therefore output
     * parameters
     */
    if (pcap_lookupnet(defaultDev, &netAddress, &netMask, errbuf) == -1) {
        printf("%s\n", errbuf);
        exit(3);
    }

    /*
     * inet_ntoa() turns a "binary network address into an ascii string"
     */
    inAddress.s_addr = netAddress;
    char *ip;

    if ((ip = inet_ntoa(inAddress)) == NULL) {
        perror("inet_ntoa");
        exit(4);
    }

    printf("IP address = %s\n", ip);

    inAddress.s_addr = netMask;
    char *mask = inet_ntoa(inAddress);

    if (mask == NULL) {
        perror("inet_ntoa");
        exit(5);
    }

    printf("Network mask = %s\n", mask);
    fflush(stdout);
}

unsigned int performCapture(char* netDevice, unsigned int nFramesToCapture) {

    char errbuf[PCAP_ERRBUF_SIZE]; //The pcap error string buffer

    /*
     * Printout of IP address + Net mask
     */
    printIPandMask(netDevice);

    /*
     * Open network device for capturing frames not-in-promiscuous mode:
     *
     * pcap_t *pcap_open_live(
     * const char *device,
     * int snaplen,
     * int promisc,
     * int timeout_ms,
     * char *errbuf);
     *
     * On OS-X timeout_ms must be > 0 ms
     * 
     */
    pcap_t* pcapStatus;
    pcapStatus = pcap_open_live(netDevice, BUFSIZ, 0, 1, errbuf);


    if (pcapStatus == (pcap_t *) NULL) {
        printf("Call to pcap_open_live() returned error: %s\n", errbuf);
        exit(4);
    }

    printf("\n\nCapturing %u frames:\n", nFramesToCapture);
    fflush(stdout);
    
    struct bpf_program fp;      /* hold compiled program */
    char filterDefinition[] = "ether proto 0x07ff";

    
    if(pcap_compile(pcapStatus, &fp, filterDefinition, 0, 0xffffff00) == -1){ 
      fprintf(stderr,"Error calling pcap_compile\n");
      exit(1);
    }

    /* set the compiled program as the filter */
    if(pcap_setfilter(pcapStatus, &fp) == -1)
    { fprintf(stderr,"Error setting filter\n"); exit(1); }
    

    /*
     * int pcap_loop(
     * pcap_t *status,
     * int number_of_frames_to_capture,
     * pcap_handler callback_function,
     * u_char *user
     * )
     *
     */
    pcap_loop(pcapStatus, nFramesToCapture, (pcap_handler) getNewFrame, (u_char *) NULL);

    return nFramesToCapture;
}

int main(int argc, char *args[]) {
    /*
     * Process command line arguments:
     * get the number of frames to capture
     */
    if (argc != 3) {
        printf("%s <net device> <n_frames_to_capture> \n", args[0]);
        exit(-1);
    }

    performCapture(args[1], 1);
    
    printf("\nFinished\n");

}
