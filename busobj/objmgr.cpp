#ifdef WIN32
#undef interface
#endif

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <boost/asio/signal_set.hpp>
#include <sdbusplus/asio/object_server.hpp>
//#include <xyz/openbmc_project/ObjectMapper/server.hpp>

//#include <xyz/openbmc_project/Common/error.hpp>

#include <iostream>
#include <string_view>

#include <systemd/sd-bus.h>

#include "objmgr-types.hpp"
//#include "bus-internal.h"
//#include "log.h"
//#include "macro.h"

#ifdef WIN32
#include <WinSock2.h>
extern "C" int socketpair(int domain, int type, int protocol, int sv[2]);

#endif

AssociationMaps associationMaps;
/** @brief Define white list and black list data structure */
using WhiteBlackList = boost::container::flat_set<std::string>;
static WhiteBlackList service_whitelist;
static WhiteBlackList service_blacklist;

// TODO(ed) replace with std::set_intersection once c++17 is available
template <class InputIt1, class InputIt2>
bool intersect(InputIt1 first1, InputIt1 last1, InputIt2 first2, InputIt2 last2)
{
	while (first1 != last1 && first2 != last2)
	{
		if (*first1 < *first2)
		{
			++first1;
			continue;
		}
		if (*first2 < *first1)
		{
			++first2;
			continue;
		}
		return true;
	}
	return false;
}

void doListNames(
	boost::asio::io_context& io, interface_map_type& interface_map,
	sdbusplus::asio::connection* system_bus,
	boost::container::flat_map<std::string, std::string>& name_owners,
	AssociationMaps& assocMaps, sdbusplus::asio::object_server& objectServer)
{
	system_bus->async_method_call(
		[&io, &interface_map, &name_owners, &objectServer, system_bus,
		&assocMaps](const boost::system::error_code ec,
			std::vector<std::string> process_names) {
				if (ec)
				{
					std::cerr << "Error getting names: " << ec << "\n";
					std::exit(EXIT_FAILURE);
					return;
				}
				// Try to make startup consistent
				std::sort(process_names.begin(), process_names.end());
#ifdef DEBUG
				std::shared_ptr<std::chrono::time_point<std::chrono::steady_clock>>
					global_start_time = std::make_shared<
					std::chrono::time_point<std::chrono::steady_clock>>(
						std::chrono::steady_clock::now());
#endif
				for (const std::string& process_name : process_names)
				{
					std::cout << "process_name: " << process_name.c_str() << std::endl;
					/*
					if (needToIntrospect(process_name, service_whitelist,
						service_blacklist))
					{
						start_new_introspect(system_bus, io, interface_map,
							process_name, assocMaps,
#ifdef DEBUG
							global_start_time,
#endif
							objectServer);
						update_owners(system_bus, name_owners, process_name);
					}
					*/
				}
		},
		"org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
			"ListNames");
}

namespace sdbusplus {
	namespace xyz {
		namespace openbmc_project {
			namespace Common {
				namespace Error {
					struct ResourceNotFound final : public sdbusplus::exception::generated_exception
					{
						static constexpr auto errName = "xyz.openbmc_project.Common.Error.ResourceNotFound";
						static constexpr auto errDesc = "The resource is not found.";
						static constexpr auto errWhat = "xyz.openbmc_project.Common.Error.ResourceNotFound: The resource is not found.";

						const char* name() const noexcept override;
						const char* description() const noexcept override;
						const char* what() const noexcept override;
					};

					const char* ResourceNotFound::name() const noexcept
					{
						return errName;
					}
					const char* ResourceNotFound::description() const noexcept
					{
						return errDesc;
					}
					const char* ResourceNotFound::what() const noexcept
					{
						return errWhat;
					}
				}
			}
		}
	}
}

boost::container::flat_map<std::string, boost::container::flat_set<std::string>>
getObject(const interface_map_type& interface_map, const std::string& path,
	std::vector<std::string>& interfaces)
{
	boost::container::flat_map<std::string,
		boost::container::flat_set<std::string>>
		results;

	//try {
		// Interfaces need to be sorted for intersect to function
		std::sort(interfaces.begin(), interfaces.end());
		auto path_ref = interface_map.find(path);
		if (path_ref == interface_map.end())
		{
			throw sdbusplus::xyz::openbmc_project::Common::Error::ResourceNotFound();
		}
		if (interfaces.empty())
		{
			return path_ref->second;
		}
		for (auto& interface_map : path_ref->second)
		{
			if (intersect(interfaces.begin(), interfaces.end(),
				interface_map.second.begin(), interface_map.second.end()))
			{
				results.emplace(interface_map.first, interface_map.second);
			}
		}

		if (results.empty())
		{
			throw sdbusplus::xyz::openbmc_project::Common::Error::ResourceNotFound();
		}
	//}
	//catch (std::exception& e)
	//{
	//	printf("Exception: %s\n", e.what());
	//}

	return results;
}

///////
//char fake_unique_name[] = "1:0";

//int sd_bus_list_names(sd_bus* bus, char*** acquired, char*** activatable)
//{
//	return 0;
//}

//int sd_bus_request_name(sd_bus* bus, const char* name,
//	uint64_t flags) {
//	return 0;
//}

//int sd_bus_get_unique_name(sd_bus* bus, const char** unique) {
//	*unique = fake_unique_name;
//	return 0;
//}

//sd_event* sd_bus_get_event(sd_bus* bus) { return NULL; }
//int sd_bus_attach_event(sd_bus* bus, sd_event* e, int priority) { return 0; }
//int sd_bus_detach_event(sd_bus* bus) { return 0; }
//sd_bus* sd_bus_flush_close_unref(sd_bus* bus) { return NULL; }
//int sd_bus_flush(sd_bus* bus) { return 0; }
//int sd_bus_wait(sd_bus* bus, uint64_t timeout_usec) { return 0; }
//int sd_bus_get_fd(sd_bus* bus) { return 100; }
//int sd_bus_process(sd_bus* bus, sd_bus_message** r) { return 0; }
//void sd_bus_close(sd_bus* bus) {}
//int sd_bus_default(sd_bus** ret) {
//	sd_bus_new(ret);
//	return 0;
//}
//////

extern "C" int bus_process_object(sd_bus * bus, sd_bus_message * m);
extern "C" void bus_set_state(sd_bus * bus, /*enum bus_state*/int state);
extern "C" void bus_message_set_sender_local(sd_bus * bus, sd_bus_message * m);
extern "C" void bus_iteration_counter_increase(sd_bus * bus);
extern "C" void log_set_max_level(int);
extern "C" int bus_ensure_running(sd_bus * bus);

#define assert_se assert

int peer_server(int fd)
{
	boost::asio::io_context io;
	log_set_max_level(7);

	sd_bus* bus = NULL;
	sd_id128_t id;

	assert_se(sd_id128_randomize(&id) >= 0);

	assert_se(sd_bus_new(&bus) >= 0);
	assert_se(sd_bus_set_description(bus, "server") >= 0);

	assert_se(sd_bus_set_fd(bus, fd, fd) >= 0);

	assert_se(sd_bus_set_server(bus, 1, id) >= 0);
	assert_se(sd_bus_set_anonymous(bus, true) >= 0);
#ifdef WIN32
	assert_se(sd_bus_negotiate_fds(bus, false) >= 0);
#else
	assert_se(sd_bus_negotiate_fds(bus, true) >= 0);
#endif
	assert_se(sd_bus_start(bus) >= 0);

	assert_se(bus_ensure_running(bus) >= 0);

	std::shared_ptr<sdbusplus::asio::connection> system_bus =
		std::make_shared<sdbusplus::asio::connection>(io, bus);

	sdbusplus::asio::object_server server(system_bus);

	// Construct a signal set registered for process termination.
#if 0
	boost::asio::signal_set signals(io, SIGINT, SIGTERM);
	signals.async_wait(
		[&system_bus, &io](const boost::system::error_code&, int) {

			std::cout << "io stop..." << std::endl;

			io.stop();
			
		});
#endif

	interface_map_type interface_map;
	boost::container::flat_map<std::string, std::string> name_owners;

	std::shared_ptr<sdbusplus::asio::dbus_interface> iface =
		server.add_interface("/xyz/openbmc_project/object_mapper",
			"xyz.openbmc_project.ObjectMapper");

	iface->register_method(
		"GetObject", [&interface_map](const std::string& path,
			std::vector<std::string>& interfaces) {
				return getObject(interface_map, path, interfaces);
		});


	iface->initialize();
	
	//io.post([&]() {
	//	doListNames(io, interface_map, system_bus.get(), name_owners,
	//		associationMaps, server);
	//	});
	
	//system_bus->request_name("xyz.openbmc_project.ObjectMapper");

#if 0
	
	// manually test
	sdbusplus::bus::busp_t bus = system_bus->get_bus();
	bus_set_state(bus, /*BUS_OPENING*/2);

	sdbusplus::message_t m = system_bus.get()->new_method_call(
		"xyz.openbmc_project.ObjectMapper",
		"/xyz/openbmc_project/object_mapper",
		"xyz.openbmc_project.ObjectMapper", "GetObject");
	
	m.append("/", std::array<std::string, 0>());
	
	bus_iteration_counter_increase(bus);
	bus_message_set_sender_local(bus, m.get());
	sd_bus_message_seal(m.get(), 0xFFFFFFFFULL, 0);
	bus_set_state(bus, /*BUS_RUNNING*/5);
	
	bus_process_object(bus, m.get());
	
	m = system_bus.get()->new_method_call("xyz.openbmc_project.ObjectMapper",
		"/", "org.freedesktop.DBus.Introspectable", "Introspect");

	bus_iteration_counter_increase(bus);
	bus_message_set_sender_local(bus, m.get());
	sd_bus_message_seal(m.get(), 0xFFFFFFFFULL, 0);
	bus_set_state(bus, /*BUS_RUNNING*/5);

	bus_process_object(bus, m.get());
#endif

	io.run();

	printf("..>>..>>..>>..\n");

	return 0;
}

void* get_in_addr(struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
	{
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

#ifdef WIN32
#define SOCKET_ADDR	"tcp:host=localhost,port=8888"
#else
#define SOCKET_ADDR "unix:/tmp/_mysocket"
#endif

int main(int argc, char** argv)
{
#ifdef _WIN32
	//----------------------
	// Initialize Winsock.
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		wprintf(L"WSAStartup failed with error: %ld\n", iResult);
		return 1;
	}
#endif

	//1. Getting the address data structure.
	//2. Openning a new socket.
	//3. Bind to the socket.
	//4. Listen to the socket.
	//5. Accept Connection.
	//6. Pass new connection to peer_server.

	int status;
	int listner;

#ifdef WIN32
	struct addrinfo hints, *res;
	// Before using hint you have to make sure that the data structure is empty 
	memset(&hints, 0, sizeof(hints));
	// Set the attribute for hint
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM; // TCP Socket SOCK_DGRAM 
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Fill the res data structure and make sure that the results make sense. 
	status = getaddrinfo(NULL, "8888", &hints, &res);
	if (status != 0)
	{
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
		WSACleanup();
		return 1;
	}
#else
	struct sockaddr_un local;
	int loclen = 0;
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, "/tmp/_mysocket");
	unlink(local.sun_path);
	loclen = strlen(local.sun_path) + sizeof(local.sun_family);
#endif

	// Create Socket and check if error occured afterwards
#ifdef WIN32
	listner = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#else
	listner = ::socket(AF_UNIX, SOCK_STREAM, 0);
#endif
	if (listner < 0)
	{
		fprintf(stderr, "socket error: %s\n", gai_strerror(status));
#ifdef WIN32
		freeaddrinfo(res);
		WSACleanup();
#endif
		return 1;
	}

	// Bind the socket to the address of my local machine and port number 
#ifdef WIN32
	status = ::bind(listner, res->ai_addr, (int)res->ai_addrlen);
#else
	status = ::bind(listner, (struct sockaddr*)&local, loclen);
#endif
	if (status < 0)
	{
		fprintf(stderr, "bind: %s\n", gai_strerror(status));
#ifdef WIN32
		freeaddrinfo(res);
		WSACleanup();
#endif
		return 1;
	}

#ifdef WIN32
	// Free the res linked list after we are done with it	
	freeaddrinfo(res);
#endif

	status = ::listen(listner, SOMAXCONN);
	if (status < 0)
	{
		fprintf(stderr, "listen: %s\n", gai_strerror(status));
#ifdef WIN32
		closesocket(listner);
		WSACleanup();
#endif
		return 1;
	}	

	// We should wait now for a connection to accept
	int new_conn_fd;
	struct sockaddr_storage client_addr = {};
	socklen_t addr_size;
	char s[INET6_ADDRSTRLEN]; // an empty string 

	// Calculate the size of the data structure	
	addr_size = sizeof(client_addr);

	printf("I am now accepting connections ...\n");

	while (1) {
		// Accept a new connection and return back the socket desciptor 
#ifdef WIN32
		new_conn_fd = ::accept(listner, (struct sockaddr*)&client_addr, &addr_size);
#else
		new_conn_fd = ::accept4(listner, NULL, NULL, /*SOCK_NONBLOCK | */ SOCK_CLOEXEC);
#endif
		if (new_conn_fd < 0)
		{
			fprintf(stderr, "accept: %s\n", gai_strerror(new_conn_fd));
			continue;
		}

#ifdef WIN32
		inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), s, sizeof(s));
		printf("I am now connected to %s\n", s);
#else
		struct sockaddr_storage ss;
		socklen_t sslen = sizeof(struct sockaddr_storage);
		if (getsockname(new_conn_fd, (struct sockaddr*)&ss, &sslen) == 0) {
			struct sockaddr_un* un = (struct sockaddr_un*)&ss;
			printf("I am now connected to %s\n", un->sun_path);
		}
#endif
		
		
		peer_server(new_conn_fd);
		
#ifdef _WIN32
		closesocket(new_conn_fd);
#else
		close(new_conn_fd);
#endif
	}

#ifdef WIN32
	WSACleanup();
#endif

	return 0;
}