#ifdef WIN32
#undef interface
#endif

#include "objmgr-types.hpp"

#include <boost/asio/io_context.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <boost/asio/signal_set.hpp>
#include <sdbusplus/asio/object_server.hpp>
//#include <xyz/openbmc_project/ObjectMapper/server.hpp>

//#include <xyz/openbmc_project/Common/error.hpp>

#include <iostream>
#include <string_view>

#include <systemd/sd-bus.h>


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

int main(int argc, char** argv)
{
	boost::asio::io_context io;
	log_set_max_level(7);
	std::shared_ptr<sdbusplus::asio::connection> system_bus =
		std::make_shared<sdbusplus::asio::connection>(io);

	sdbusplus::asio::object_server server(system_bus);

	// Construct a signal set registered for process termination.
	boost::asio::signal_set signals(io, SIGINT, SIGTERM);
	signals.async_wait(
		[&system_bus, &io](const boost::system::error_code&, int) {

			std::cout << "io stop..." << std::endl;
			
			system_bus.get()->CloseSocket();
			io.stop();
			
		});

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
	
	io.post([&]() {
		doListNames(io, interface_map, system_bus.get(), name_owners,
			associationMaps, server);
		});
	
	system_bus->request_name("xyz.openbmc_project.ObjectMapper");

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

	return 0;
}