// gcc Wiresushi.c -o Wiresushi.exe -I"./npcap-sdk-1.16/Include" -L"./npcap-sdk-1.16/Lib/x64" -lwpcap

#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#define MAX_LIST_ELEMENTS 10

typedef struct {
    int ipAddress[4];
    int totalPackets;
    int status;
    time_t last_check_time;
} Wiresushi_Table;

Wiresushi_Table Wiresushi_Table_List[MAX_LIST_ELEMENTS];

static int table_full = 0;

const char* check_status(time_t last_check_time) {
    time_t now = time(NULL);
    if (difftime(now, last_check_time) < 3) {
        return ">> LIVE";
    }
    return "-- IDLE";
}

void display() {
    system("cls");
    printf("============================================================================\n");
    printf("                     :WireSushi: Simple Network Logger \n");
    printf("============================================================================\n");
    printf(" [ID]  [Status]   %-20s   %-15s   [Last Seen] \n", "[Remote IP]", "[Total Data]");
    printf("----------------------------------------------------------------------------\n");
    for (int i = 0; i < MAX_LIST_ELEMENTS; i++) {
        if (Wiresushi_Table_List[i].status == 1) {
            struct tm* t = localtime(&Wiresushi_Table_List[i].last_check_time);

            char ipStr[20];
            sprintf(ipStr, "%d.%d.%d.%d",
                Wiresushi_Table_List[i].ipAddress[0],
                Wiresushi_Table_List[i].ipAddress[1],
                Wiresushi_Table_List[i].ipAddress[2],
                Wiresushi_Table_List[i].ipAddress[3]);

            printf("  %02d   %-8s   %-20s   %10d bytes     %02d:%02d:%02d\n",
                i + 1,
                check_status(Wiresushi_Table_List[i].last_check_time),
                ipStr,
                Wiresushi_Table_List[i].totalPackets,
                t->tm_hour, t->tm_min, t->tm_sec);
        } else {
            printf("  %02d   %-8s   %-20s   %10s           --:--:--\n", i + 1, "EMPTY", "---.---.---.---", "0 bytes");
        }
    }
    printf("============================================================================\n");

    if (table_full) {
        printf("IP table is full (%d/%d). New IPs are being ignored.\n", MAX_LIST_ELEMENTS, MAX_LIST_ELEMENTS);
    }
}

void sushi_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (pkt_data[12] != 0x08 || pkt_data[13] != 0x00) {
        return;
    }

    int Departure_ip[4] = { pkt_data[26], pkt_data[27], pkt_data[28], pkt_data[29] };
    int found = -1;

    for (int i = 0; i < MAX_LIST_ELEMENTS; i++) {
        if (Wiresushi_Table_List[i].status == 1 &&
            Wiresushi_Table_List[i].ipAddress[0] == Departure_ip[0] &&
            Wiresushi_Table_List[i].ipAddress[1] == Departure_ip[1] &&
            Wiresushi_Table_List[i].ipAddress[2] == Departure_ip[2] &&
            Wiresushi_Table_List[i].ipAddress[3] == Departure_ip[3]) {
            found = i;
            break;
        }
    }

    if (found != -1) {
        Wiresushi_Table_List[found].totalPackets += header->len;
        Wiresushi_Table_List[found].last_check_time = time(NULL);
    } else {
        int inserted = 0;
        for (int i = 0; i < MAX_LIST_ELEMENTS; i++) {
            if (Wiresushi_Table_List[i].status == 0) {
                Wiresushi_Table_List[i].ipAddress[0] = Departure_ip[0];
                Wiresushi_Table_List[i].ipAddress[1] = Departure_ip[1];
                Wiresushi_Table_List[i].ipAddress[2] = Departure_ip[2];
                Wiresushi_Table_List[i].ipAddress[3] = Departure_ip[3];
                Wiresushi_Table_List[i].totalPackets = header->len;
                Wiresushi_Table_List[i].status = 1;
                Wiresushi_Table_List[i].last_check_time = time(NULL);
                table_full = 0;
                inserted = 1;
                break;
            }
        }
        if (!inserted) {
            table_full = 1;
        }
    }
    display();
}

int main() {
    pcap_if_t* existDevices, * eD;
    pcap_t* addressHandle;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    int i = 0;
    int num;

    memset(Wiresushi_Table_List, 0, sizeof(Wiresushi_Table_List));

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &existDevices, errorBuffer) == -1) {
        fprintf(stderr, "Error in finding devices: %s\n", errorBuffer);
        return -1;
    }

    for (eD = existDevices; eD; eD = eD->next) {
        printf("%d. %s", ++i, eD->name);
        if (eD->description) {
            printf(" (%s)\n", eD->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    if (i == 0) {
        fprintf(stderr, "No devices found.\n");
        pcap_freealldevs(existDevices);
        return -1;
    }

    printf("Enter a specific device number to connect: ");
    if (scanf("%d", &num) != 1 || num < 1 || num > i) {
        fprintf(stderr, "Invalid input. Please enter a number between 1 and %d.\n", i);
        pcap_freealldevs(existDevices);
        return -1;
    }

    for (eD = existDevices, i = 1; i < num; eD = eD->next, i++);

    if ((addressHandle = pcap_open_live(eD->name, 65535, 1, 1000, errorBuffer)) == NULL) {
        fprintf(stderr, "Unable to open the adapter. %s is not available.\n", eD->name);
        pcap_freealldevs(existDevices);
        return -1;
    }

    printf("\nStarting to make sushi on %s...\n", eD->description ? eD->description : eD->name);
    pcap_loop(addressHandle, 0, sushi_handler, NULL);
    pcap_freealldevs(existDevices);
    return 0;
}