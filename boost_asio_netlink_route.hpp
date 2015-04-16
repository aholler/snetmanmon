#ifndef BOOST_ASIO_NETLINK_ROUTE_HPP
#define BOOST_ASIO_NETLINK_ROUTE_HPP
//
// A simple header for netlink route sockets
//
// (C) 2015 Alexander Holler
//

#include "boost_asio_netlink_route_endpoint.hpp"

namespace boost {
namespace asio {
namespace netlink {

class route {
public:
	/// The type of endpoint.
	typedef netlink_route_endpoint<route> endpoint;

	/// Get an Instance.
	static route get() {
		return route();
	}

	/// Obtain an identifier for the type of the protocol.
	int type() const {
		return SOCK_DGRAM;
	}

	/// Obtain an identifier for the protocol.
	int protocol() const {
		return NETLINK_ROUTE;
	}

	/// Obtain an identifier for the protocol family.
	int family() const {
		return PF_NETLINK;
	}

	/// The socket type.
	typedef basic_datagram_socket<route> socket;

	/// The acceptor type.
	typedef basic_socket_acceptor<route> acceptor;
};

}}} // namespace boost::asio::netlink

#endif // BOOST_ASIO_NETLINK_ROUTE_HPP
