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

#include <netinet/ether.h> // ether_ntoa
#include <ifaddrs.h>

#include "boost_asio_netlink_route.hpp"
#include "version.h"

typedef std::set<boost::asio::ip::address> SetIps;
typedef std::map<unsigned, SetIps> Map_idx_addrs;
typedef std::map<unsigned, std::string> Map_idx_if;

static Map_idx_addrs map_idx_addrs;
static Map_idx_if map_idx_if;

static void print_ifs(void)
{
	auto end = map_idx_if.cend();
	for (auto i = map_idx_if.cbegin(); i != end; ++i)
		std::cout << "idx " << i->first << " if '" << i->second << "'\n";
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
	}
}

static void add_regex(const boost::property_tree::ptree::const_assoc_iterator& it, std::string&& s, boost::regex& r)
{
	std::string str(it->second.get<std::string>(std::move(s), ""));
	if (str.empty())
		return;
	r = boost::regex(std::move(str), boost::regex::extended);
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

static std::string ether2str(const rtattr* attr)
{
	int len = (int) RTA_PAYLOAD(attr);
	if (len != ETH_ALEN)
		return "";
	return ether_ntoa(static_cast<const ether_addr*>(RTA_DATA(attr)));
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
			if (RTA_PAYLOAD(attr))
				evt.state = states.at(*(uint8_t*)RTA_DATA(attr));
			}
			break;
		default:
			break;
		}
	}
}

std::string build_link_string(const EventLink& evt, const std::string& s, const std::string& etype)
{
	std::string result(s);
	stringReplace(result, "%a", evt.address);
	stringReplace(result, "%e", etype);
	stringReplace(result, "%i", evt.ifname);
	stringReplace(result, "%o", evt.ifname_old);
	stringReplace(result, "%s", evt.state);
	return result;
}

static void do_action(const Action& action, std::string&& str)
{
	if (action.type == Action::Type_exec) {
		// TODO: We (currently) don't care about what happens with the thread.
		// That bears the problem that these threads aren't serialized.
		// E.g. if we start a thread for a link_new event and a thread for
		// an addr_new event, the second thread might actually run before
		// the first.
		std::thread t([](std::string&& s){
			int unused __attribute__((unused));
			unused = std::system(s.c_str());
		}, std::move(str));
		t.detach();
	} else // if (action.type == Action::Type_stdout)
		std::cout << std::move(str) << '\n';
}

static void do_link_actions(const EventLink& evt, const std::string& etype, const Actions& actions)
{
	auto end = actions.cend();
	for (auto i = actions.cbegin(); i != end; ++i) {
		if (i->str.empty())
			continue;
		std::string str(build_link_string(evt, i->str, etype));
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
	if (!is_empty_or_matches(filter.ifname, evt.ifname))
		return false;
	if (!is_empty_or_matches(filter.address, evt.address))
		return false;
	if (!is_empty_or_matches(filter.ifname_old, evt.ifname_old))
		return false;
	if (!is_empty_or_matches(filter.state, evt.state))
		return false;
	return true;
}

static void do_link_filters(const EventLink& evt, const std::string& etype, const FiltersLink& filters)
{
	auto end = filters.cend();
	for (auto i = filters.cbegin(); i != end; ++i)
		if (filter_matches(evt, *i))
			do_link_actions(evt, etype, i->actions);
}

static void link_new(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);

	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	map_idx_addrs.insert(std::pair<unsigned, SetIps>(idx, SetIps()));
	auto inserted = map_idx_if.insert(std::pair<unsigned, std::string>(idx, evt.ifname));
	if (!inserted.second && inserted.first != map_idx_if.cend() && evt.ifname != inserted.first->second) {
		// if got renamed
		evt.ifname_old = inserted.first->second;
		inserted.first->second = evt.ifname;
	}
	do_link_actions(evt, "link_new", settings.actions_link_new);
	do_link_filters(evt, "link_new", settings.filters_link_new);
}

static void link_del(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);
	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	map_idx_addrs.erase(idx);
	map_idx_if.erase(idx);
	do_link_actions(evt, "link_del", settings.actions_link_del);
	do_link_filters(evt, "link_del", settings.filters_link_del);
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
			evt.ifname = found->second;
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

std::string build_addr_string(const EventAddr& evt, const std::string& s, const std::string& etype)
{
	std::string result(s);
	stringReplace(result, "%a", evt.address);
	stringReplace(result, "%b", evt.broadcast);
	stringReplace(result, "%e", etype);
	stringReplace(result, "%i", evt.ifname);
	stringReplace(result, "%t", (evt.type_v6 ? "v6" : "v4"));
	return result;
}

static void do_addr_actions(const EventAddr& evt, const std::string& etype, const Actions& actions)
{
	auto end = actions.cend();
	for (auto i = actions.cbegin(); i != end; ++i) {
		if (i->str.empty())
			continue;
		std::string str(build_addr_string(evt, i->str, etype));
		do_action(*i, std::move(str));
	}
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

static void do_addr_filters(const EventAddr& evt, const std::string& etype, const FiltersAddress& filters)
{
	auto end = filters.cend();
	for (auto i = filters.cbegin(); i != end; ++i)
		if (filter_matches(evt, *i))
			do_addr_actions(evt, etype, i->actions);
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
			do_addr_actions(evt, "addr_new", settings.actions_addr_new);
			do_addr_filters(evt, "addr_new", settings.filters_addr_new);
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
		do_addr_actions(evt, "addr_del", settings.actions_addr_del);
		do_addr_filters(evt, "addr_del", settings.filters_addr_del);
	}
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
		map_idx_if.insert(std::pair<unsigned, std::string>(idx, ifa->ifa_name));
		if (ifa->ifa_addr == nullptr)
			continue;
		int family = ifa->ifa_addr->sa_family;
		if (family == AF_INET || family == AF_INET6) {
			auto inserted = map_idx_addrs.insert(std::pair<unsigned, SetIps>(idx, SetIps()));
			if (inserted.first != map_idx_addrs.end()) {
				if (family == AF_INET)
					inserted.first->second.insert(in_addr_to_address(*reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr)));
				else
					inserted.first->second.insert(in_addr_to_address(*reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr)));
			}
		}
	}
	freeifaddrs(ifaddr);
}

static void (*old_signal_handler)(int) = nullptr;

void sig_handler(int signal)
{
	// There should be a lock here, but it's currently just a debug facility.
	print_ifs();
        if (old_signal_handler != nullptr)
                old_signal_handler(signal);
}

int main(int argc, char* argv[])
{
	std::cout << "\nsnetmanmon V" VERSION << '\n';
	std::cout << "\n(C) 2015 Alexander Holler\n\n";

	if (argc != 2) {
		std::cerr << "Usage: snetmanmon config\n\n";
		return 1;
	}

	old_signal_handler = std::signal(SIGHUP, sig_handler); // catch SIGHUP

	try {
		settings.load(argv[1]);
	} catch(const std::exception& e) {
		std::cerr << "Error reading config '" << argv[1] << "': " << e.what() <<  "!\n";
		return 2;
	}

	// TODO: we should populate the cache after we started to listen
	// for events, in order to not miss something.
	populate_ifs();

	boost::asio::io_service io_service;
	boost::system::error_code ec;
	boost::asio::netlink::route::socket socket(io_service);
	boost::asio::netlink::route::endpoint endpoint(
		RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);
	socket.open();
	socket.bind(endpoint);
	std::array<char, 4096> recv_buf;
	for (;;) {
		boost::asio::netlink::route::endpoint endpoint_rcv;
		size_t len = socket.receive_from(boost::asio::buffer(recv_buf), endpoint_rcv);
		if (endpoint_rcv.pid())
			continue; // not from kernel
		const nlmsghdr* hdr = reinterpret_cast<const nlmsghdr*>(recv_buf.data());
		if (!NLMSG_OK(hdr, len)) {
			std::cerr << "Received broken netlink msg!\n";
			continue;
		}
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
	}
	return 0;
}
