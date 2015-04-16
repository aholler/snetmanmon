// snetmanmon
//
// A simple network manager and monitor for Linux
//
// (C) 2015 Alexander Holler
//

#include <iostream>
#include <array>

#include "boost_asio_netlink_route.hpp"
#include "version.h"

static std::string nlmsg_type_as_string(uint16_t type)
{
	switch (type) {
	case NLMSG_NOOP:
		return "NOOP";
	case NLMSG_ERROR:
		return "ERROR";
	case NLMSG_DONE:
		return "DONE";
	case NLMSG_OVERRUN:
		return "OVERRUN";
	case RTM_GETLINK:
		return "GETLINK";
	case RTM_NEWLINK:
		return "NEWLINK";
	case RTM_DELLINK:
		return "DELLINK";
	case RTM_GETADDR:
		return "GETADDR";
	case RTM_NEWADDR:
		return "NEWADDR";
	case RTM_DELADDR:
		return "DELADDR";
	case RTM_GETROUTE:
		return "GETROUTE";
	case RTM_NEWROUTE:
		return "NEWROUTE";
	case RTM_DELROUTE:
		return "DELROUTE";
	case RTM_NEWNDUSEROPT:
		return "NEWNDUSEROPT";
	default:
		return "UNKNOWN";
	}
}

int main(void)
{
	std::cout << "\nsnetmanmon V" VERSION << '\n';
	std::cout << "\n(C) 2015 Alexander Holler\n\n";

	boost::asio::io_service io_service;
	boost::system::error_code ec;
	boost::asio::netlink::route::socket socket(io_service);
	boost::asio::netlink::route::endpoint endpoint(
		RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
		RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE |
		(1<<(RTNLGRP_ND_USEROPT-1)));
	socket.open();
	socket.bind(endpoint);
	std::array<char, 4096> recv_buf;
	for(;;) {
		boost::asio::netlink::route::endpoint endpoint_rcv;
		size_t len = socket.receive_from(boost::asio::buffer(recv_buf), endpoint_rcv);
		std::cout << "len:" << len << '\n';
		std::cout << "pid: 0x" << std::hex << endpoint_rcv.pid() <<
			" groups: 0x" << endpoint.groups() << std::dec << '\n';

		struct nlmsghdr *hdr = (struct nlmsghdr *)&recv_buf[0];

		if (NLMSG_OK(hdr, len)) {
			std::cout << nlmsg_type_as_string(hdr->nlmsg_type) <<
				" (" << (unsigned)hdr->nlmsg_type << ')' <<
				" len " << hdr->nlmsg_len <<
				" flags 0x" << std::hex << hdr->nlmsg_flags << std::dec <<
				" seq " << hdr->nlmsg_seq <<
				" pid " << hdr->nlmsg_pid <<
				'\n';
			std::cout << '\n';
		}
	}
	return 0;
}
