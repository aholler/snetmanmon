// send_rpc_ra
//
// (C) 2015 Alexander Holler
//

#include <cstring>
#include <iostream>

#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <unistd.h> // close
#include <net/if.h> // if_nametoindex
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h> // inet_pton

static bool is_link_local(const in6_addr& addr)
{
	static const in6_addr addr6_linklocal =  { { {
		0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	} } };
	return !(std::memcmp(&addr6_linklocal, &addr, 8));
}

static int set_src_addr(const std::string& if_name, in6_addr& src)
{
	ifaddrs* ifaddr;
	if (::getifaddrs(&ifaddr) == -1) {
		std::cerr << "Error from getifaddrs ( " << strerror(errno) << ")!\n";
		return 1;
	}
	int rc = 2;
	for (ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (!ifa->ifa_name)
			continue;
		if (if_name == ifa->ifa_name) {
			if (!is_link_local(reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr)->sin6_addr))
				continue;
			src = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;
			rc = 0;
			break;
		}
	}
	::freeifaddrs(ifaddr);
	return rc;
}

static int check_prefix(const std::string if_name, const in6_addr& prefix)
{
	ifaddrs* ifaddr;
	if (::getifaddrs(&ifaddr) == -1) {
		std::cerr << "Error from getifaddrs ( " << strerror(errno) << ")!\n";
		return 1;
	}
	for (ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (!ifa->ifa_name)
			continue;
		if (if_name == ifa->ifa_name) {
			if (!std::memcmp(&prefix, &reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr)->sin6_addr, 8)) {
				::freeifaddrs(ifaddr);
				return 2;
			}
		}
	}
	::freeifaddrs(ifaddr);
	return 0;
}

int main(int argc, char** argv)
{
        std::cout << "\nsend_rpc_ra\n";
        std::cout << "\n(C) 2015 Alexander Holler\n\n";

	if (argc != 4) {
		std::cout << "Usage: " <<
			"send_rpc_ra interface destination_ipv6 prefix_ipv6\n" <<
			"Example: " <<
			"send_ra eth0 ff02::1 fecd::\n\n";
		return 1;
	}

	std::string interface(argv[1]);
	std::string destination(argv[2]);
	std::string prefix(argv[3]);

	struct {
		nd_router_advert nra;
		nd_opt_prefix_info opt_prefix_info;
	} my_ra;

	std::memset(&my_ra, 0, sizeof(my_ra));

	my_ra.nra.nd_ra_type = ND_ROUTER_ADVERT;

	msghdr msghdr;
	std::memset(&msghdr, 0, sizeof(msghdr));

	// destination address
	sockaddr_in6 dst;
	std::memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	dst.sin6_port = htons(IPPROTO_ICMPV6);

	if (inet_pton(AF_INET6, destination.c_str(), &dst.sin6_addr) != 1) {
		std::cerr << "Error setting destination '" << destination << "'\n";
		return 2;
	}

	msghdr.msg_name = &dst;
	msghdr.msg_namelen = sizeof(dst);

	iovec iov[2];
	std::memset(&iov, 0, sizeof(iov));
	iov[0].iov_base = &my_ra;
	iov[0].iov_len = sizeof(my_ra);
	msghdr.msg_iov = (struct iovec *) &iov;
	msghdr.msg_iovlen = sizeof(iov) / sizeof(struct iovec);

	in6_pktinfo* ipi;
	cmsghdr* cmsg_hdr;
	uint8_t cmsgbuf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(*ipi))];
	std::memset(&cmsgbuf, 0, sizeof(cmsgbuf));

	msghdr.msg_control = &cmsgbuf;
	msghdr.msg_controllen = sizeof(cmsgbuf);

	// hop limit
	cmsg_hdr = CMSG_FIRSTHDR(&msghdr);
	cmsg_hdr->cmsg_level = IPPROTO_IPV6;
	cmsg_hdr->cmsg_type = IPV6_HOPLIMIT;
	cmsg_hdr->cmsg_len = CMSG_LEN(sizeof(int));
	cmsgbuf[sizeof(*cmsg_hdr)] = 255; // using CMSG_DATA throws a warning

	// packet info
	cmsg_hdr = CMSG_NXTHDR(&msghdr, cmsg_hdr);
	cmsg_hdr->cmsg_level = IPPROTO_IPV6;
	cmsg_hdr->cmsg_type = IPV6_PKTINFO;
	cmsg_hdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	ipi = (struct in6_pktinfo *) CMSG_DATA(cmsg_hdr);

	ipi->ipi6_ifindex = if_nametoindex(interface.c_str());
	if (!ipi->ipi6_ifindex) {
		std::cerr << "Interface '" << interface << "' not found!\n";
		return 3;
	}

	in6_addr s_addr;
	std::memset(&s_addr, 0, sizeof(s_addr));

	if (set_src_addr(interface, s_addr)) {
		std::cerr << "Error finding link-local address of interface '" << interface << "'!\n";
		return 4;
	}

	std::memcpy(&ipi->ipi6_addr, &s_addr, sizeof(ipi->ipi6_addr));
	msghdr.msg_iovlen = 1;

	my_ra.opt_prefix_info.nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	my_ra.opt_prefix_info.nd_opt_pi_len = 4;
	if (inet_pton(AF_INET6, prefix.c_str(), &my_ra.opt_prefix_info.nd_opt_pi_prefix) != 1) {
		std::cerr << "Error converting prefix '" << prefix << "'!\n";
		return 5;
	}
	my_ra.opt_prefix_info.nd_opt_pi_prefix_len = 64;


	if (check_prefix(interface, my_ra.opt_prefix_info.nd_opt_pi_prefix)) {
		std::cerr << "Prefix " << prefix << " seems to be in use!\n";
		return 6;
	}
	my_ra.opt_prefix_info.nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_AUTO;
	my_ra.opt_prefix_info.nd_opt_pi_flags_reserved |= ND_OPT_PI_FLAG_RADDR;

	// Setting both lifetimes to 1 means the kernel will only delete the
	// link-local address without creating it before.
	my_ra.opt_prefix_info.nd_opt_pi_valid_time = htonl(1);
	my_ra.opt_prefix_info.nd_opt_pi_preferred_time = htonl(1);

	int sock = ::socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (sock < 0) {
		std::cerr << "Error opening raw socket, are you root?\n";
		return 7;
	}
	if (::sendmsg(sock, &msghdr, 0) < 0) {
		::close(sock);
		std::cerr << "Error sending RA ( " << strerror(errno) << ")!\n";
		return 8;
	}
	::close(sock);

	std::cout << "Sent a Router Advertisment with prefix " <<
		prefix << " to " << destination << "\n";

	return 0;
}
