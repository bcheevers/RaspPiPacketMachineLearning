#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
/*Imports the time library*/
#include <time.h> 
/*Checks the version of windows. If using Windows 32 bit version*/
#ifdef WIN32
/*If using Windows 32 bit version, import tchar.
tchar is a string library which allows Srings to be of unicode or ascii
needed due to WIndos 32 being older than Unicode standardisation.*/
#include <tchar.h>

/*Function which loads the dynamic link library of NPCap
If failure occurs returns false*/
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	/*Scan in input from user, inputted value is inum.*/
	scanf_s("%d", &inum);
	/*Range check*/
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,			// name of the device
		65536,			// portion of the packet to capture
					  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
		1000,				// read timeout
		NULL,				// authentication on the remote machine
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
/*This function recieves the packet data.*/
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	/*Declare variables we want to return to the user.*/
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused variables
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}