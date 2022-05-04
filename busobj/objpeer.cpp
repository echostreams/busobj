#include <assert.h>
#include <systemd/sd-bus.h>
#ifdef WIN32
#include <WinSock2.h>
#endif

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif
	//#include "bus-internal.h"
	//#include "log.h"
	//#include "macro.h"
	//#include "memory-util.h"
	//#include "string-util.h"
#ifdef __cplusplus
}
#endif	


#define assert_se assert

int client(char * socketpath) {
    //_cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL, * reply = NULL;
    //_cleanup_(sd_bus_unrefp) sd_bus* bus = NULL;
    //_cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
    int r;
	sd_bus* bus = NULL;
	boost::asio::io_context io;

#ifdef WIN32

	//----------------------
	// Initialize Winsock.
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %ld\n", iResult);
		return 1;
	}

	struct sockaddr_in address; /* server address                      */
	memset(&address, 0, sizeof(address));

	address.sin_family = AF_INET;
	char server[NI_MAXHOST];
	memset(server, 0, sizeof(address));
	int port;
	const char* ptr = strrchr(socketpath, ':');
	if (ptr == NULL)
	{
		printf("Invalid address: %s\n", (socketpath));
		return -1;
	}
	size_t n = (ptr - socketpath);
	strncpy(server, socketpath, n);
	port = atoi(ptr + 1);
	struct hostent* hostnm;    /* server host name information        */
	hostnm = gethostbyname(server);
	if (hostnm == (struct hostent*)0)
	{
		printf("Gethostbyname failed: %s\n", (socketpath));
		return -1;
	}
	address.sin_port = htons(port);
	address.sin_addr.s_addr = *((unsigned long*)hostnm->h_addr);

#else

	sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, sizeof(address.sun_path), "%s", socketpath);

#endif

	
#ifdef WIN32
	int fd = socket(AF_INET, SOCK_STREAM, 0/*IPPROTO_TCP*/);
#else
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
#endif

	if (fd < 0) {
		printf("Could not open socket: %s\n", (socketpath));
	}

	if (connect(fd, (sockaddr*)(&address), sizeof(address)) < 0) {
		printf("Could not connect to socket: %s\n", (socketpath));
	}

#ifdef WIN32
	u_long iMode = 1; // non-blocking mode is enabled
	iResult = ioctlsocket(fd, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		printf("Could not set socket non-blocking: %s\n", (socketpath));
	}
#endif

    assert_se(sd_bus_new(&bus) >= 0);
    assert_se(sd_bus_set_description(bus, "client") >= 0);
    assert_se(sd_bus_set_fd(bus, fd, fd) >= 0);
    assert_se(sd_bus_negotiate_fds(bus, false) >= 0);
    assert_se(sd_bus_set_anonymous(bus, true) >= 0);
    assert_se(sd_bus_start(bus) >= 0);

    std::shared_ptr<sdbusplus::asio::connection> system_bus =
        std::make_shared<sdbusplus::asio::connection>(io, bus);

	system_bus->async_method_call(
		[](boost::system::error_code ec, std::string &introspect) {
			if (ec)
			{
				std::cerr << "Introspect returned error with "
					"async_method_call (ec = "
					<< ec << ")\n";
				return;
			}
			std::cout << "Introspect return \n" << introspect << "\n";
		},
		"xyz.openbmc_project.ObjectMapper", "/xyz/openbmc_project/object_mapper",
			"org.freedesktop.DBus.Introspectable", "Introspect");

	system_bus->async_method_call(
		[](
			const boost::system::error_code ec,
			const std::vector<std::pair<std::string, std::vector<std::string>>> &objectNames) 
		{
			if (ec)
			{
				std::cout 
					<< "ObjectMapper::GetObject call failed: "
					<< ec;			
				return;
			}

			std::string service = objectNames.begin()->first;
			std::cout << "GetObjectType: " << service;

		},
		"xyz.openbmc_project.ObjectMapper",
		"/xyz/openbmc_project/object_mapper",
		"xyz.openbmc_project.ObjectMapper", "GetObject", "/",
		std::array<std::string, 0>());

	io.run();
	return 0;
}


int main(int argc, char** argv)
{
	int ret = client(argv[1]);

	return ret;
}