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

boost::container::flat_map<std::string, boost::container::flat_set<std::string>>
getObject(const interface_map_type& interface_map, const std::string& path,
    std::vector<std::string>& interfaces)
{
    boost::container::flat_map<std::string,
        boost::container::flat_set<std::string>>
        results;

    // Interfaces need to be sorted for intersect to function
    std::sort(interfaces.begin(), interfaces.end());
    auto path_ref = interface_map.find(path);
    if (path_ref == interface_map.end())
    {
        throw std::exception("Resource Not Found");
        // sdbusplus::xyz::openbmc_project::Common::Error::ResourceNotFound();
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
        //throw sdbusplus::xyz::openbmc_project::Common::Error::ResourceNotFound();
        throw std::exception("Resource Not Found");
    }

    return results;
}



int main(int argc, char** argv)
{
    boost::asio::io_context io;
    
    std::shared_ptr<sdbusplus::asio::connection> system_bus =
        std::make_shared<sdbusplus::asio::connection>(io);

    sdbusplus::asio::object_server server(system_bus);

    // Construct a signal set registered for process termination.
    boost::asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait(
        [&io](const boost::system::error_code&, int) {

            std::cout << "io stop..." << std::endl;

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

    io.run();

    return 0;
}