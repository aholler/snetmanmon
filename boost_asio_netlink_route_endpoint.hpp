#ifndef BOOST_ASIO_NETLINK_ROUTE_ENDPOINT_HPP
#define BOOST_ASIO_NETLINK_ROUTE_ENDPOINT_HPP
//
// A simple header for netlink route endpoints
//
// (C) 2015 Alexander Holler
//

#include <sys/types.h>
#include <unistd.h>

#include <boost/asio.hpp>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

namespace boost {
namespace asio {
namespace netlink {

template<typename netlink_route_protocol>
class netlink_route_endpoint {
public:
	/// The protocol type associated with the endpoint.
	typedef netlink_route_protocol protocol_type;

	/// The type of the endpoint structure. This type is dependent on the
	/// underlying implementation of the socket layer.
	typedef boost::asio::detail::socket_addr_type address_type;

	/// Default constructor.
	netlink_route_endpoint()
        : _address()
	{
		std::memset(&_address, 0, sizeof(_address));
		_address.nl_family = AF_NETLINK;
		_address.nl_pid = getpid();
	}

	netlink_route_endpoint(uint32_t groups)
        : netlink_route_endpoint()
	{
		_address.nl_groups = groups;
	}

	/// Copy constructor.
	netlink_route_endpoint(const netlink_route_endpoint& other) :
		_address(other._address) {
	}

	/// Assign from another endpoint.
	netlink_route_endpoint& operator=(const netlink_route_endpoint& other) {
		_address = other._address;
		return *this;
	}

	/// The protocol associated with the endpoint.
	protocol_type protocol() const {
		return protocol_type::get();
	}

	uint32_t pid() const {
		return _address.nl_pid;
	}

	uint32_t groups() const {
		return _address.nl_groups;
	}

	/// Get the underlying endpoint in the native type.
	address_type* data() {
		return reinterpret_cast<boost::asio::detail::socket_addr_type*>(&_address);
	}

	/// Get the underlying endpoint in the native type.
	const address_type* data() const {
		return reinterpret_cast<const boost::asio::detail::socket_addr_type*>(&_address);
	}

	/// Get the underlying size of the endpoint in the native type.
	std::size_t size() const {
		return sizeof(_address);
	}

	/// Set the underlying size of the endpoint in the native type.
	void resize(std::size_t size) {
		if ( size > sizeof(sockaddr_nl) ) {
			boost::system::system_error e(boost::asio::error::invalid_argument);
			boost::throw_exception(e);
		}
	}

	/// Get the capacity of the endpoint in the native type.
	std::size_t capacity() const {
		return sizeof(_address);
	}

	/// Compare two endpoints for inequality.
	friend bool operator!=(const netlink_route_endpoint& e1,
			const netlink_route_endpoint& e2) {
		return e1._address == &e2._address;
	}

	/// Compare endpoints for ordering.
	friend bool operator<(const netlink_route_endpoint<netlink_route_protocol>& e1,
			const netlink_route_endpoint<netlink_route_protocol>& e2) {
		if (e1._address.nl_pid != e2._address.nl_pid)
			return e1._address.nl_pid < e2._address.nl_pid;
		return e1._address.nl_groups < e2._address.nl_groups;
	}

private:
	struct sockaddr_nl _address;
};

template<typename Elem, typename Traits, typename netlink_route_protocol>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& os,
                                             const netlink_route_endpoint<netlink_route_protocol>& endpoint)
{
    boost::system::error_code ec;
    std::string s = endpoint.to_string(ec);
    if (ec) {
        if (os.exceptions() & std::basic_ostream<Elem, Traits>::failbit) {
            boost::asio::detail::throw_error(ec);
        } else {
            os.setstate(std::basic_ostream<Elem, Traits>::failbit);
        }
    } else {
        for (std::string::iterator i = s.begin(); i != s.end(); ++i) {
            os << os.widen(*i);
        }
    }
    return os;
}

}}} // namespace boost::asio::netlink

#endif // BOOST_ASIO_NETLINK_ROUTE_ENDPOINT_HPP
