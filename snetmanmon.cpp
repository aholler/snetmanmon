// snetmanmon
//
// A simple network manager and monitor for Linux
//
// (C) 2015 Alexander Holler
//

#include <iostream>
#include <array>
#include <vector>
#include <map>
#include <set>
#include <cassert>
#include <thread>
#include <cstdlib> // std::system

#include <boost/property_tree/json_parser.hpp>
#include <boost/regex.hpp>

#include <netinet/ether.h> // ether_addr
#include <ifaddrs.h>

#include "SafeQueue.hpp"
#include "boost_asio_netlink_route.hpp"
#include "version.h"

typedef std::set<boost::asio::ip::address> SetIps;
typedef std::map<unsigned, SetIps> Map_idx_addrs;

class Link
{
	public:
		Link(std::string&& i, std::string&& s, std::string&& a)
			: ifname(std::move(i))
			, state(std::move(s))
			, address(std::move(a))
		{}
		Link(const std::string& i, const std::string& s, const std::string& a)
			: ifname(i)
			, state(s)
			, address(a)
		{}
		std::string ifname;
		std::string state;
		std::string address; // MAC
};

typedef std::map<unsigned, Link> Map_idx_if;

static Map_idx_addrs map_idx_addrs;
static Map_idx_if map_idx_if;

static void print_ifs(void)
{
	auto end = map_idx_if.cend();
	for (auto i = map_idx_if.cbegin(); i != end; ++i)
		std::cout << "idx " << i->first <<
			" if '" << i->second.ifname <<
			"' state '" << i->second.state <<
			"' MAC " << i->second.address << "\n";
	auto end_ifs = map_idx_addrs.cend();
	for (auto i = map_idx_addrs.cbegin(); i != end_ifs; ++i) {
		std::cout << "idx " << i->first << "\n";
		auto end_addrs = i->second.cend();
		for (auto j = i->second.cbegin(); j != end_addrs; ++j)
			std::cout << "\taddr " << j->to_string() << '\n';
	}
}

static boost::asio::ip::address in_addr_to_address(const in6_addr& ina6)
{
	boost::asio::ip::address_v6::bytes_type ipv6;
	static_assert((sizeof(ina6.s6_addr) == 16), "");
	assert(ipv6.size() == 16);
	std::memcpy(ipv6.data(), ina6.s6_addr, 16);
	return boost::asio::ip::address_v6(std::move(ipv6));
}

static boost::asio::ip::address in_addr_to_address(const sockaddr_in6 &s)
{
	return in_addr_to_address(s.sin6_addr);
}

static boost::asio::ip::address in_addr_to_address(const in_addr& ina)
{
	boost::asio::ip::address_v4::bytes_type ipv4;
	static_assert((sizeof(ina.s_addr) == 4), "");
	assert(ipv4.size() == 4);
	std::memcpy(ipv4.data(), &ina.s_addr, 4);
	return boost::asio::ip::address_v4(std::move(ipv4));
}

static boost::asio::ip::address in_addr_to_address(const sockaddr_in &s)
{
	return in_addr_to_address(s.sin_addr);
}

class Event
{
	public:
		std::string ifname;
		std::string address;
};

class EventLink : public Event
{
	public:
		std::string state; // up, down or unknown
		std::string ifname_old;
		std::string state_old;
		std::string address_old;
};

class EventAddr : public Event
{
	public:
		std::string broadcast;
		bool type_v6; // ipv6?
};

struct Action
{
	enum Type {
		Type_stdout,
		Type_exec,
		Type_exec_seq,
	} type;
	std::string str;
};
typedef std::vector<Action> Actions;

class Filter
{
	public:
		boost::regex ifname;
		boost::regex address;
		Actions actions;
};

class FilterLink: public Filter
{
	public:
		boost::regex ifname_old;
		boost::regex state;
		boost::regex state_old;
		boost::regex address_old;
};
typedef std::vector<FilterLink> FiltersLink;

class FilterAddress: public Filter
{
	public:
		boost::regex broadcast;
		std::string type;
};
typedef std::vector<FilterAddress> FiltersAddress;

class Settings {
	public:
		Actions actions_link_new;
		Actions actions_link_del;
		Actions actions_addr_new;
		Actions actions_addr_del;
		FiltersLink filters_link_new;
		FiltersLink filters_link_del;
		FiltersAddress filters_addr_new;
		FiltersAddress filters_addr_del;
		bool link_new_for_existing_links;
		bool addr_new_for_existing_addresses;
		std::string pid_file;
		void load(const std::string& path);
};

static void add_actions_type(const boost::property_tree::ptree& pt,
	Actions& actions, std::string&& type_name, Action::Type type)
{
	auto found = pt.equal_range(std::move(type_name));
	for (auto it = found.first; it != found.second; ++it ) {
		Action action;
		action.type = type;
		action.str = it->second.data();
		actions.push_back(std::move(action));
	}
}

static void add_actions(const boost::property_tree::ptree& pt, Actions& actions)
{
	auto found_actions = pt.equal_range("actions");
	for (auto it = found_actions.first; it != found_actions.second; ++it ) {
		add_actions_type(it->second, actions, "stdout", Action::Type_stdout);
		add_actions_type(it->second, actions, "exec", Action::Type_exec);
		add_actions_type(it->second, actions, "exec_seq", Action::Type_exec_seq);
	}
}

static void add_regex(const boost::property_tree::ptree::const_assoc_iterator& it, std::string&& s, boost::regex& r)
{
	std::string str(it->second.get<std::string>(std::move(s), ""));
	if (str.empty())
		return;
	r = boost::regex(std::move(str), boost::regex::perl);
}

static void add_link_events(const boost::property_tree::ptree& pt, std::string&& ltype, Actions& actions, FiltersLink& filters_link)
{
	auto events = pt.equal_range(std::move(ltype));
	for (auto it = events.first; it != events.second; ++it ) {
		add_actions(it->second, actions);
		auto filters = it->second.equal_range("filter");
		for (auto itf = filters.first; itf != filters.second; ++itf ) {
			FilterLink filter;
			add_regex(itf, "ifname", filter.ifname);
			add_regex(itf, "address", filter.address);
			add_regex(itf, "state", filter.state);
			add_regex(itf, "ifname_old", filter.ifname_old);
			add_regex(itf, "state_old", filter.state_old);
			add_regex(itf, "address_old", filter.address_old);
			add_actions(itf->second, filter.actions);
			filters_link.push_back(std::move(filter));
		}
	}
}

static void add_address_events(const boost::property_tree::ptree& pt, std::string&& atype, Actions& actions, FiltersAddress& filters_address)
{
	auto events = pt.equal_range(std::move(atype));
	for (auto it = events.first; it != events.second; ++it ) {
		add_actions(it->second, actions);
		auto filters = it->second.equal_range("filter");
		for (auto itf = filters.first; itf != filters.second; ++itf ) {
			FilterAddress filter;
			add_regex(itf, "ifname", filter.ifname);
			add_regex(itf, "address", filter.address);
			add_regex(itf, "broadcast", filter.broadcast);
			filter.type = itf->second.get<std::string>("type", "");
			add_actions(itf->second, filter.actions);
			filters_address.push_back(std::move(filter));
		}
	}
}

void Settings::load(const std::string& path)
{
	boost::property_tree::ptree pt;
	read_json(path, pt);

	link_new_for_existing_links = pt.get<bool>("link_new_for_existing_links", false);
	addr_new_for_existing_addresses = pt.get<bool>("addr_new_for_existing_addresses", false);
	pid_file = pt.get<std::string>("pid_file", "");
	boost::property_tree::ptree& events(pt.get_child("events"));
	add_link_events(events, "link_new", actions_link_new, filters_link_new);
	add_link_events(events, "link_del", actions_link_del, filters_link_del);
	add_address_events(events, "addr_new", actions_addr_new, filters_addr_new);
	add_address_events(events, "addr_del", actions_addr_del, filters_addr_del);
}

static Settings settings;

static void stringReplace(std::string& str, std::string&& what, const std::string& with)
{
	for (size_t pos = str.rfind(what); pos != std::string::npos; pos = str.rfind(what, pos - 1)) {
		str.replace(pos, what.size(), with);
		if (!pos)
			break;
	}
}

static std::string mac2str(const unsigned char* mac)
{
	std::ostringstream os;
	os << std::setfill('0') << std::hex <<
		std::setw(2) << (unsigned)mac[0] << ':' << std::setw(2) << (unsigned)mac[1] << ':' <<
		std::setw(2) << (unsigned)mac[2] << ':' << std::setw(2) << (unsigned)mac[3] << ':' <<
		std::setw(2) << (unsigned)mac[4] << ':' << std::setw(2) << (unsigned)mac[5];
        return os.str();
}
static std::string mac2str(const ether_addr* mac)
{
	return mac2str(mac->ether_addr_octet);
}

static std::string ether2str(const rtattr* attr)
{
	int len = (int) RTA_PAYLOAD(attr);
	if (len != ETH_ALEN)
		return "";
	return mac2str(static_cast<const ether_addr*>(RTA_DATA(attr)));
}

static std::string inet2str(const rtattr* attr, unsigned char family)
{
	int len = (int) RTA_PAYLOAD(attr);

	if (family == AF_INET && len == sizeof(in_addr))
		return in_addr_to_address(*static_cast<const in_addr*>(RTA_DATA(attr))).to_string();
	else if (family == AF_INET6 && len == sizeof(in6_addr))
		return in_addr_to_address(*static_cast<const in6_addr*>(RTA_DATA(attr))).to_string();
	return "";
}

static void parse_link(const nlmsghdr* hdr, EventLink& evt)
{
	const ifinfomsg* msg = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr));
	int bytes = IFLA_PAYLOAD(hdr);

	for (const rtattr* attr = IFLA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			evt.address = ether2str(attr);
			break;
		case IFLA_IFNAME:
			if (RTA_PAYLOAD(attr))
				evt.ifname = (char*) RTA_DATA(attr);
			break;
		case IFLA_OPERSTATE:
			{
			static const std::vector<std::string> states {
				"unknown",
				"notpresent",
				"down",
				"lowerlayerdown",
				"testing",
				"dormant",
				"up",
			};
			if (RTA_PAYLOAD(attr)) {
				uint8_t state_idx = *static_cast<const uint8_t*>(RTA_DATA(attr));
				if (state_idx < states.size())
					evt.state = states[state_idx];
			}
			}
			break;
		default:
			break;
		}
	}
}

typedef SafeQueue<std::string> QueueStrings;
static QueueStrings queue_execs;
static std::thread exec_thread;

static void do_action(const Action& action, std::string&& str)
{
	assert(!str.empty());
	if (action.type == Action::Type_exec) {
		std::thread t([](std::string&& s){
			int unused __attribute__((unused));
			unused = std::system(s.c_str());
		}, std::move(str));
		t.detach();
	} else if (action.type == Action::Type_exec_seq) {
		queue_execs.enqueue(std::move(str));
		if (!exec_thread.joinable()) {
			exec_thread = std::thread([](){
				for (;;) {
					std::string s(queue_execs.dequeue());
					if (s.empty())
						return;
					int unused __attribute__((unused));
					unused = std::system(s.c_str());
				}
			});
		}
	} else // if (action.type == Action::Type_stdout)
		std::cout << std::move(str) << '\n';
}

static std::string build_string(const EventLink& evt, const std::string& s, const std::string& etype)
{
	std::string result(s);
	stringReplace(result, "%a", evt.address);
	stringReplace(result, "%A", evt.address_old);
	stringReplace(result, "%e", etype);
	stringReplace(result, "%i", evt.ifname);
	stringReplace(result, "%I", evt.ifname_old);
	stringReplace(result, "%s", evt.state);
	stringReplace(result, "%S", evt.state_old);
	return result;
}

static std::string build_string(const EventAddr& evt, const std::string& s, const std::string& etype)
{
	std::string result(s);
	stringReplace(result, "%a", evt.address);
	stringReplace(result, "%b", evt.broadcast);
	stringReplace(result, "%e", etype);
	stringReplace(result, "%i", evt.ifname);
	stringReplace(result, "%t", (evt.type_v6 ? "v6" : "v4"));
	return result;
}

template <class E>
static void do_actions(const E& evt, const std::string& etype, const Actions& actions)
{
	auto end = actions.cend();
	for (auto i = actions.cbegin(); i != end; ++i) {
		if (i->str.empty())
			continue;
		std::string str(build_string(evt, i->str, etype));
		do_action(*i, std::move(str));
	}
}

static bool is_empty_or_matches(const boost::regex& e, const std::string& s)
{
	if (e.empty())
		return true;
	return regex_match(s, e);
}

static bool filter_matches(const EventLink& evt, const FilterLink& filter)
{
	if (!is_empty_or_matches(filter.address, evt.address))
		return false;
	if (!is_empty_or_matches(filter.address_old, evt.address_old))
		return false;
	if (!is_empty_or_matches(filter.ifname, evt.ifname))
		return false;
	if (!is_empty_or_matches(filter.ifname_old, evt.ifname_old))
		return false;
	if (!is_empty_or_matches(filter.state, evt.state))
		return false;
	if (!is_empty_or_matches(filter.state_old, evt.state_old))
		return false;
	return true;
}

static bool filter_matches(const EventAddr& evt, const FilterAddress& filter)
{
	if (!is_empty_or_matches(filter.ifname, evt.ifname))
		return false;
	if (!is_empty_or_matches(filter.address, evt.address))
		return false;
	if (!is_empty_or_matches(filter.broadcast, evt.broadcast))
		return false;
	if (!filter.type.empty() && filter.type != (evt.type_v6 ? "v6" : "v4"))
		return false;
	return true;
}

template <class E, class F>
static void do_filters(const E& evt, const std::string& etype, const F& filters)
{
	auto end = filters.cend();
	for (auto i = filters.cbegin(); i != end; ++i)
		if (filter_matches(evt, *i))
			do_actions(evt, etype, i->actions);
}

static void link_new(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);

	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	map_idx_addrs.insert(std::pair<unsigned, SetIps>(idx, SetIps()));
	Link link(evt.ifname, evt.state, evt.address);
	auto inserted = map_idx_if.insert(std::pair<unsigned, Link>(idx, link));
	if (inserted.second) {
		// New link (interface), submit the event, done.
		do_actions(evt, "link_new", settings.actions_link_new);
		do_filters(evt, "link_new", settings.filters_link_new);
		return;
	}
	// Link (interface) already exists.
	if (evt.state.empty() && !inserted.first->second.state.empty()) {
		// Use the old state if the netlink msg didn't contain a state
		evt.state = inserted.first->second.state;
		link.state = evt.state;
	}
	if (evt.address.empty() && !inserted.first->second.address.empty()) {
		// Use the old address if the netlink msg didn't contain an address
		evt.address = inserted.first->second.address;
		link.address = evt.address;
	}
	if (evt.ifname == inserted.first->second.ifname &&
			evt.state == inserted.first->second.state &&
			evt.address == inserted.first->second.address)
		// Nothing (we care for) has changed
		return;

	EventLink evt_old(evt);
	evt_old.ifname = inserted.first->second.ifname;
	evt_old.address = inserted.first->second.address;
	evt_old.state = inserted.first->second.state;
	// Now generate one event for every change, even if we
	// received several changes with one event.
	if (evt.ifname != inserted.first->second.ifname) {
		// if got renamed
		evt_old.ifname = evt.ifname;
		evt_old.ifname_old = inserted.first->second.ifname;
		inserted.first->second.ifname = evt.ifname;
		do_actions(evt_old, "link_new", settings.actions_link_new);
		do_filters(evt_old, "link_new", settings.filters_link_new);
		evt_old.ifname_old.clear();
	}
	if (evt.state != inserted.first->second.state) {
		// State changed
		evt_old.state = evt.state;
		evt_old.state_old = inserted.first->second.state;
		inserted.first->second.state = evt.state;
		do_actions(evt_old, "link_new", settings.actions_link_new);
		do_filters(evt_old, "link_new", settings.filters_link_new);
		//evt_old.state_old.clear();
	}
	if (evt.address != inserted.first->second.address) {
		// MAC changed
		evt.address_old = inserted.first->second.address;
		inserted.first->second.address = evt.address;
		do_actions(evt, "link_new", settings.actions_link_new);
		do_filters(evt, "link_new", settings.filters_link_new);
	}
}

static void link_del(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);
	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	// Make sure to send addr_del events for any addresses we
	// might not have received such an event.
	auto found = map_idx_addrs.find(idx);
	if (found != map_idx_addrs.cend())
		for (auto addr = found->second.cbegin(); addr != found->second.cend(); ++addr) {
			EventAddr evt_addr;
			evt_addr.ifname = evt.ifname;
			evt_addr.address = addr->to_string();
			evt_addr.type_v6 = addr->is_v6();
			do_actions(evt_addr, "addr_del", settings.actions_addr_del);
			do_filters(evt_addr, "addr_del", settings.filters_addr_del);
		}
	map_idx_addrs.erase(idx);
	map_idx_if.erase(idx);
	do_actions(evt, "link_del", settings.actions_link_del);
	do_filters(evt, "link_del", settings.filters_link_del);
}

static std::string ifname(unsigned int idx)
{
	char name[IFNAMSIZ];
	if (!if_indextoname(idx, name))
		return "";
	return name;
}

static void parse_addr(const nlmsghdr* hdr, EventAddr& evt)
{
	const ifaddrmsg* msg = static_cast<const ifaddrmsg*>(NLMSG_DATA(hdr));
	int bytes = IFA_PAYLOAD(hdr);
	evt.ifname = ifname(msg->ifa_index);
	if (evt.ifname.empty()) {
		auto found = map_idx_if.find(msg->ifa_index);
		if (found != map_idx_if.end())
			evt.ifname = found->second.ifname;
	}
	for (const rtattr* attr = IFA_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case IFA_ADDRESS:
			evt.address = inet2str(attr, msg->ifa_family);
			evt.type_v6 = (msg->ifa_family == AF_INET6);
			break;
		case IFA_LABEL:
			if (RTA_PAYLOAD(attr))
				evt.ifname = (char*) RTA_DATA(attr);
			break;
		case IFA_BROADCAST:
			evt.broadcast = inet2str(attr, msg->ifa_family);
			break;
		default:
			break;
		}
	}
}

static void addr_new(const nlmsghdr* hdr)
{
	EventAddr evt;
	parse_addr(hdr, evt);
	unsigned idx = static_cast<const ifaddrmsg*>(NLMSG_DATA(hdr))->ifa_index;
	auto found = map_idx_addrs.find(idx);
	if (found != map_idx_addrs.cend()) {
		auto inserted = found->second.insert(boost::asio::ip::address::from_string(evt.address));
		if (inserted.second) {
			do_actions(evt, "addr_new", settings.actions_addr_new);
			do_filters(evt, "addr_new", settings.filters_addr_new);
		}
	}
}

static void addr_del(const nlmsghdr* hdr)
{
	EventAddr evt;
	parse_addr(hdr, evt);
	unsigned idx = static_cast<const ifaddrmsg*>(NLMSG_DATA(hdr))->ifa_index;
	auto found = map_idx_addrs.find(idx);
	if (found != map_idx_addrs.cend()) {
		found->second.erase(boost::asio::ip::address::from_string(evt.address));
		do_actions(evt, "addr_del", settings.actions_addr_del);
		do_filters(evt, "addr_del", settings.filters_addr_del);
	}
}

static std::string get_eth_addr(ifaddrs* ifa)
{
	size_t len = ::strlen(ifa->ifa_name);
	ifreq ifr;
	if (len > sizeof(ifr.ifr_name) - 1)
		return "";
	std::memcpy(ifr.ifr_name, ifa->ifa_name, len+1);
	int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd == -1)
		return "";
	int rc = ::ioctl(fd, SIOCGIFHWADDR, &ifr);
	::close(fd);
	if (rc == -1)
		return "";
	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return "";
	return mac2str(reinterpret_cast<const unsigned char*>(ifr.ifr_hwaddr.sa_data));
}

static void generate_evt_link(const Link& link)
{
	EventLink evt;
	evt.ifname = link.ifname;
	evt.address = link.address;
	evt.state = link.state;
	do_actions(evt, "link_new", settings.actions_link_new);
	do_filters(evt, "link_new", settings.filters_link_new);
}

static void generate_evt_addr(const std::string& ifname, const boost::asio::ip::address&& addr, std::string&& broadcast)
{
	EventAddr evt;
	evt.ifname = ifname;
	evt.address = addr.to_string();
	evt.broadcast = std::move(broadcast);
	evt.type_v6 = addr.is_v6();
	do_actions(evt, "addr_new", settings.actions_addr_new);
	do_filters(evt, "addr_new", settings.filters_addr_new);
}

static void populate_ifs(void)
{
	ifaddrs* ifaddr;

	if (getifaddrs(&ifaddr) == -1) {
		std::cerr << strerror(errno) << '\n';
		return;
	}

	for (ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
		if (ifa->ifa_name == nullptr)
			continue;
		unsigned idx = if_nametoindex(ifa->ifa_name);
		if (!idx)
			continue;
		std::string state("up");
		if (!(ifa->ifa_flags & IFF_UP))
			state = "down";
		Link link(ifa->ifa_name, std::move(state), get_eth_addr(ifa));
		auto if_inserted = map_idx_if.insert(std::pair<unsigned, Link>(idx, link));
		if (if_inserted.second && settings.link_new_for_existing_links)
			generate_evt_link(link);
		if (ifa->ifa_addr == nullptr)
			continue;
		int family = ifa->ifa_addr->sa_family;
		if (family == AF_INET || family == AF_INET6) {
			auto inserted = map_idx_addrs.insert(std::pair<unsigned, SetIps>(idx, SetIps()));
			if (inserted.first != map_idx_addrs.end()) {
				boost::asio::ip::address addr;
				if (family == AF_INET)
					addr = in_addr_to_address(*reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr));
				else
					addr = in_addr_to_address(*reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr));
				auto addr_inserted = inserted.first->second.insert(addr);
				if (addr_inserted.second && settings.addr_new_for_existing_addresses) {
					std::string broadcast;
					if (ifa->ifa_flags & IFF_BROADCAST && ifa->ifa_broadaddr && ifa->ifa_broadaddr->sa_family == AF_INET)
						broadcast = in_addr_to_address(*reinterpret_cast<const sockaddr_in*>(ifa->ifa_broadaddr)).to_string();
					generate_evt_addr(ifa->ifa_name, std::move(addr), std::move(broadcast));
				}
			}
		}
	}
	freeifaddrs(ifaddr);
}

class netlink_route_client
{
private:
	void receive(void) {
		socket_.async_receive_from(
			boost::asio::buffer(data_, max_length), sender_endpoint_,
				boost::bind(&netlink_route_client::handle_receive_from, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
	}
	boost::asio::netlink::route::socket socket_;
	boost::asio::netlink::route::endpoint sender_endpoint_;
	enum { max_length = 4096 };
	char data_[max_length];

public:
	netlink_route_client(boost::asio::io_service& io_service)
		: socket_(io_service, boost::asio::netlink::route::endpoint(
			RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR))
	{
		// It would be better to use SOCK_CLOEXEC when opening the
		// socket, but as we are still single threaded here, it
		// should be ok.
		if (::fcntl(socket_.native_handle(), F_SETFD, FD_CLOEXEC))
			std::cerr << strerror(errno) << '\n';
		receive();
		populate_ifs();
	}

	void handle_receive_from(const boost::system::error_code& error, size_t bytes_recvd) {
		const nlmsghdr* hdr = reinterpret_cast<const nlmsghdr*>(data_);
		if (!error && bytes_recvd && !sender_endpoint_.pid())
			for(; NLMSG_OK(hdr, bytes_recvd); hdr = NLMSG_NEXT(hdr, bytes_recvd))
				switch (hdr->nlmsg_type) {
				case RTM_NEWLINK:
					link_new(hdr);
					break;
				case RTM_DELLINK:
					link_del(hdr);
					break;
				case RTM_NEWADDR:
					addr_new(hdr);
					break;
				case RTM_DELADDR:
					addr_del(hdr);
					break;
				default:
					break;
				}
		receive();
	}
};

static void del_pid_file(void)
{
	if (!settings.pid_file.empty())
		if (::unlink(settings.pid_file.c_str()))
			std::cerr << "Error deleting pid file '" << settings.pid_file << "'\n";
}

static boost::asio::signal_set* signal_usr1_p;
static void sigusr1(const boost::system::error_code&, int)
{
	print_ifs();
	signal_usr1_p->async_wait(sigusr1);
}

static std::string config;

static boost::asio::signal_set* signal_hup_p;
static void sighup(const boost::system::error_code&, int)
{
	signal_hup_p->async_wait(sighup);
	Settings new_settings;
	try {
		new_settings.load(config);
	} catch(const std::exception& e) {
		std::cerr << "Error reading config '" << config << "': " << e.what() <<  ", nothing changed!\n";
		return;
	}
	if (!settings.pid_file.empty() && settings.pid_file != new_settings.pid_file)
		std::cerr << "Warning: pid_file changed to '" << new_settings.pid_file <<
			"', the old one ('" << settings.pid_file <<
			"') will not be deleted at program termination.\n";
	std::swap(settings, new_settings);
	std::cout << "Configuration reloaded.\n";
}

int main(int argc, char* argv[])
{
	std::cout << "\nsnetmanmon V" VERSION << '\n';
	std::cout << "\n(C) 2015 Alexander Holler\n\n";

	if ((argc != 2 && argc != 3) || (argc == 3 && std::string(argv[1]) != "-t")) {
		std::cerr << "Usage: snetmanmon [-t] config\n\n";
		return 1;
	}

	config = argv[argc == 3 ? 2 : 1];

	try {
		settings.load(config);
	} catch(const std::exception& e) {
		std::cerr << "Error reading config '" << config << "': " << e.what() <<  "!\n";
		return 2;
	}

	if (argc == 3)
		return 0;

	if (!settings.pid_file.empty()) {
		std::ofstream pid;
		pid.exceptions( std::ofstream::failbit | std::ofstream::badbit );
		try {
			pid.open(settings.pid_file);
			pid << ::getpid() << std::endl;
			pid.close();
		} catch(const std::exception& e) {
			std::cerr << "Error writing pid file '" << settings.pid_file << "'!\n";
			return 3;
		}
	}

	boost::asio::io_service io_service;

	boost::asio::signal_set signals_term(io_service, SIGTERM, SIGINT, SIGQUIT);
	signals_term.async_wait(boost::bind(&boost::asio::io_service::stop, &io_service));
	boost::asio::signal_set signal_hup(io_service, SIGHUP);
	signal_hup_p = &signal_hup;
	signal_hup.async_wait(sighup);
	boost::asio::signal_set signal_usr1(io_service, SIGUSR1);
	signal_usr1_p = &signal_usr1;
	signal_usr1.async_wait(sigusr1);

	netlink_route_client nrc(io_service);

	try {
		io_service.run();
	} catch(const std::exception& e) {
		std::cerr << "Exception: " << e.what() << "\n";
		del_pid_file();
		return 4;
	}

	if (exec_thread.joinable()) {
		queue_execs.enqueue(std::string());
		exec_thread.join();
	}

	del_pid_file();

	return 0;
}
