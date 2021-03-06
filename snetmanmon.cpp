// snetmanmon
//
// A simple network manager and monitor for Linux
//
// (C) 2015 - 2018 Alexander Holler
//

#include <iostream>
#include <array>
#include <vector>
#include <map>
#include <set>
#include <cassert>
#include <thread>
#include <cstdlib> // std::system
#include <chrono>
#include <fstream> // ifstream
#include <iomanip> // setfill, setw

#include <boost/bind.hpp>
#include <boost/regex.hpp>

#include <netinet/ether.h> // ether_addr

#include "SafeQueue.hpp"
#include "boost_asio_netlink_route.hpp"
#include "json11/json11.hpp"
#include "version.h"

static std::chrono::time_point<std::chrono::steady_clock> time_last_msg_exec_queue_overflow;
static std::chrono::time_point<std::chrono::steady_clock> time_last_msg_max_routes;

typedef std::set<boost::asio::ip::address> SetIps;
typedef std::map<unsigned, SetIps> Map_idx_addrs;

class Route
{
	public:
		Route(std::string&& d, std::string&& g, bool v6, uint8_t s)
			: destination(std::move(d))
			, gateway(std::move(g))
			, is_v6(v6)
			, scope(s)
		{}
		Route(const std::string& d, const std::string& g, bool v6, uint8_t s)
			: destination(d)
			, gateway(g)
			, is_v6(v6)
			, scope(s)
		{}
		std::string destination;
		std::string gateway;
		bool is_v6;
		uint8_t scope;
		bool operator==(const Route& r) const {
			return destination == r.destination && gateway == r.gateway;
		}
		bool operator<(const Route& r) const {
			if (destination == r.destination)
				return gateway < r.gateway;
			return destination < r.destination;
		}
};
typedef std::set<Route> SetRoutes;
typedef std::map<unsigned, SetRoutes> Map_idx_routes;

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
static Map_idx_routes map_idx_routes;
static Map_idx_if map_idx_if;

static void print_ifs(void)
{
	for (const auto& i : map_idx_if)
		std::cout << "idx " << i.first <<
			" if '" << i.second.ifname <<
			"' state '" << i.second.state <<
			"' MAC " << i.second.address << "\n";
	for (const auto& i : map_idx_addrs) {
		std::cout << "idx " << i.first << "\n";
		for (const auto& a : i.second)
			std::cout << "\taddr " << a.to_string() << '\n';
	}
	for (const auto& i : map_idx_routes) {
		std::cout << "idx " << i.first << "\n";
		for (const auto& r : i.second)
			std::cout << "\troute " << r.destination << " gw " << r.gateway << " scope " << std::to_string(r.scope) << '\n';
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

static boost::asio::ip::address in_addr_to_address(const in_addr& ina)
{
	boost::asio::ip::address_v4::bytes_type ipv4;
	static_assert((sizeof(ina.s_addr) == 4), "");
	assert(ipv4.size() == 4);
	std::memcpy(ipv4.data(), &ina.s_addr, 4);
	return boost::asio::ip::address_v4(std::move(ipv4));
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
		std::string state;
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

class EventRoute : public Event
{
	public:
		std::string gateway;
		bool type_v6; // ipv6?
		unsigned if_idx;
		uint8_t scope;
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

class FilterRoute: public Filter
{
	public:
		boost::regex gateway;
		std::string type;
		boost::regex scope;
};
typedef std::vector<FilterRoute> FiltersRoute;

class Settings {
	public:
		Actions actions_link_new;
		Actions actions_link_del;
		Actions actions_addr_new;
		Actions actions_addr_del;
		Actions actions_route_new;
		Actions actions_route_del;
		FiltersLink filters_link_new;
		FiltersLink filters_link_del;
		FiltersAddress filters_addr_new;
		FiltersAddress filters_addr_del;
		FiltersRoute filters_route_new;
		FiltersRoute filters_route_del;
		bool link_new_for_existing_links;
		bool addr_new_for_existing_addresses;
		bool route_new_for_existing_routes;
		std::string pid_file;
		unsigned max_exec_queue_elements;
		std::string exec_max_exec_queue_elements;
		unsigned rate_limit_seconds_exec_max_exec_queue_elements;
		unsigned max_routes_per_link;
		std::string exec_max_routes_per_link;
		unsigned rate_limit_seconds_exec_max_routes_per_link;
		void load(const std::string& path);
};

static void add_actions_type(const json11::Json::object& jo,
	Actions& actions, std::string&& type_name, Action::Type type)
{
	auto found = jo.equal_range(std::move(type_name));
	for (auto it = found.first; it != found.second; ++it ) {
		Action action;
		action.type = type;
		action.str = it->second.string_value();
		actions.push_back(std::move(action));
	}
}

static void add_actions(const json11::Json::object& jo, Actions& actions)
{
	auto found_actions = jo.equal_range("actions");
	for (auto it = found_actions.first; it != found_actions.second; ++it ) {
		add_actions_type(it->second.object_items(), actions, "stdout", Action::Type_stdout);
		add_actions_type(it->second.object_items(), actions, "exec", Action::Type_exec);
		add_actions_type(it->second.object_items(), actions, "exec_seq", Action::Type_exec_seq);
	}
}

static void add_regex(const json11::Json& j, std::string&& s, boost::regex& r)
{
	std::string str(j[std::move(s)].string_value());
	if (str.empty())
		return;
	r = boost::regex(std::move(str), boost::regex::perl);
}

static void add_link_events(const json11::Json::object& jo, std::string&& ltype, Actions& actions, FiltersLink& filters_link)
{
	auto events = jo.equal_range(std::move(ltype));
	for (auto it = events.first; it != events.second; ++it ) {
		add_actions(it->second.object_items(), actions);
		auto filters = it->second.object_items().equal_range("filter");
		for (auto itf = filters.first; itf != filters.second; ++itf ) {
			FilterLink filter;
			add_regex(itf->second, "ifname", filter.ifname);
			add_regex(itf->second, "address", filter.address);
			add_regex(itf->second, "state", filter.state);
			add_regex(itf->second, "ifname_old", filter.ifname_old);
			add_regex(itf->second, "state_old", filter.state_old);
			add_regex(itf->second, "address_old", filter.address_old);
			add_actions(itf->second.object_items(), filter.actions);
			filters_link.push_back(std::move(filter));
		}
	}
}

static void add_address_events(const json11::Json::object& jo, std::string&& atype, Actions& actions, FiltersAddress& filters_address)
{
	auto events = jo.equal_range(std::move(atype));
	for (auto it = events.first; it != events.second; ++it ) {
		add_actions(it->second.object_items(), actions);
		auto filters = it->second.object_items().equal_range("filter");
		for (auto itf = filters.first; itf != filters.second; ++itf ) {
			FilterAddress filter;
			add_regex(itf->second, "ifname", filter.ifname);
			add_regex(itf->second, "address", filter.address);
			add_regex(itf->second, "broadcast", filter.broadcast);
			filter.type = itf->second["type"].string_value();
			add_actions(itf->second.object_items(), filter.actions);
			filters_address.push_back(std::move(filter));
		}
	}
}

static void add_route_events(const json11::Json::object& jo, std::string&& atype, Actions& actions, FiltersRoute& filters_route)
{
	auto events = jo.equal_range(std::move(atype));
	for (auto it = events.first; it != events.second; ++it ) {
		add_actions(it->second.object_items(), actions);
		auto filters = it->second.object_items().equal_range("filter");
		for (auto itf = filters.first; itf != filters.second; ++itf ) {
			FilterRoute filter;
			add_regex(itf->second, "ifname", filter.ifname);
			add_regex(itf->second, "destination", filter.address);
			add_regex(itf->second, "gateway", filter.gateway);
			filter.type = itf->second["type"].string_value();
			add_regex(itf->second, "scope", filter.scope);
			add_actions(itf->second.object_items(), filter.actions);
			filters_route.push_back(std::move(filter));
		}
	}
}

void Settings::load(const std::string& path)
{
	json11::Json json;
	{
	std::ifstream t(path);
	t.seekg(0, std::ios::end);
	size_t size = t.tellg();
	std::string buffer(size, ' ');
	t.seekg(0);
	t.read(&buffer[0], size);
	std::string err;
	json = json11::Json::parse(buffer, err, json11::JsonParse::COMMENTS);
	if (!err.empty()) {
		throw std::invalid_argument("json11: '" + err + '\'');
	}
	}
	link_new_for_existing_links = json["link_new_for_existing_links"].as_bool();
	addr_new_for_existing_addresses = json["addr_new_for_existing_addresses"].as_bool();
	route_new_for_existing_routes = json["route_new_for_existing_routes"].as_bool();
	pid_file = json["pid_file"].string_value();
	max_exec_queue_elements = json["max_exec_queue_elements"].as_int(1100);
	if (!max_exec_queue_elements)
		throw std::invalid_argument("max_exec_queue_elements should never be 0");
	exec_max_exec_queue_elements = json["exec_max_exec_queue_elements"].string_value();
	rate_limit_seconds_exec_max_exec_queue_elements = json["rate_limit_seconds_exec_max_exec_queue_elements"].as_int(60);
	max_routes_per_link = json["max_routes_per_link"].as_int(1000);
	exec_max_routes_per_link = json["exec_max_routes_per_link"].string_value();
	rate_limit_seconds_exec_max_routes_per_link = json["rate_limit_seconds_exec_max_routes_per_link"].as_int(60);
	json11::Json::object events(json["events"].object_items());
	add_link_events(events, "link_new", actions_link_new, filters_link_new);
	add_link_events(events, "link_del", actions_link_del, filters_link_del);
	add_address_events(events, "addr_new", actions_addr_new, filters_addr_new);
	add_address_events(events, "addr_del", actions_addr_del, filters_addr_del);
	add_route_events(events, "route_new", actions_route_new, filters_route_new);
	add_route_events(events, "route_del", actions_route_del, filters_route_del);
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
static bool actions_disabled; // used to temporarily disable actions for existing links, addresses or routes

static void exec(std::string &&str)
{
	std::thread t([](std::string&& s){
		int unused __attribute__((unused));
		unused = std::system(s.c_str());
	}, std::move(str));
	t.detach();
}
static void exec(const std::string &str)
{
	exec(std::string(str));
}

static void do_action(const Action& action, std::string&& str)
{
	assert(!str.empty());
	if (action.type == Action::Type_exec)
		exec(std::move(str));
	else if (action.type == Action::Type_exec_seq) {
		if (!queue_execs.enqueue_if_below_max(std::move(str), settings.max_exec_queue_elements)) {
			if (!settings.rate_limit_seconds_exec_max_exec_queue_elements ||
				std::chrono::steady_clock::now() - time_last_msg_exec_queue_overflow > std::chrono::seconds(settings.rate_limit_seconds_exec_max_exec_queue_elements)) {
				if (settings.exec_max_exec_queue_elements.empty())
					std::cerr << "Reached maximum number of queued exec_seq actions!\n";
				else
					exec(settings.exec_max_exec_queue_elements);
				time_last_msg_exec_queue_overflow = std::chrono::steady_clock::now();
			}
			return;
		}
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

static std::string scope_as_string(uint8_t scope)
{
	switch (scope) {
	case RT_SCOPE_UNIVERSE:
		return "universe";
	case RT_SCOPE_SITE:
		return "site";
	case RT_SCOPE_LINK:
		return "link";
	case RT_SCOPE_HOST:
		return "host";
	case RT_SCOPE_NOWHERE:
		return "nowhere";
	default:
		return std::to_string(scope);
	}
}

static std::string build_string(const EventRoute& evt, const std::string& s, const std::string& etype)
{
	std::string result(s);
	stringReplace(result, "%d", evt.address);
	stringReplace(result, "%e", etype);
	stringReplace(result, "%g", evt.gateway);
	stringReplace(result, "%i", evt.ifname);
	stringReplace(result, "%t", (evt.type_v6 ? "v6" : "v4"));
	stringReplace(result, "%s", scope_as_string(evt.scope));
	return result;
}

template <class E>
static void do_actions(const E& evt, const std::string& etype, const Actions& actions)
{
	for (const auto& a : actions) {
		if (a.str.empty() || actions_disabled)
			continue;
		std::string str(build_string(evt, a.str, etype));
		do_action(a, std::move(str));
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

static bool filter_matches(const EventRoute& evt, const FilterRoute& filter)
{
	if (!is_empty_or_matches(filter.ifname, evt.ifname))
		return false;
	if (!is_empty_or_matches(filter.address, evt.address))
		return false;
	if (!is_empty_or_matches(filter.gateway, evt.gateway))
		return false;
	if (!filter.type.empty() && filter.type != (evt.type_v6 ? "v6" : "v4"))
		return false;
	if (!is_empty_or_matches(filter.scope, scope_as_string(evt.scope)))
		return false;
	return true;
}

template <class E, class F>
static void do_filters(const E& evt, std::string&& etype, const F& filters)
{
	for (const auto& f : filters)
		if (filter_matches(evt, f))
			do_actions(evt, etype, f.actions);
}

template <class E, class F>
static void do_event(const E& evt, std::string&& etype, const Actions& actions, const F& filters)
{
	do_actions(evt, etype, actions);
	do_filters(evt, std::move(etype), filters);
}

static void link_new(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);

	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	map_idx_addrs.insert(std::make_pair(idx, SetIps()));
	map_idx_routes.insert(std::make_pair(idx, SetRoutes()));
	Link link(evt.ifname, evt.state, evt.address);
	auto inserted = map_idx_if.insert(std::make_pair(idx, link));
	if (inserted.second) {
		// New link (interface), submit the event, done.
		do_event(evt, "link_new", settings.actions_link_new, settings.filters_link_new);
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
		do_event(evt_old, "link_new", settings.actions_link_new, settings.filters_link_new);
		evt_old.ifname_old.clear();
	}
	if (evt.state != inserted.first->second.state) {
		// State changed
		evt_old.state = evt.state;
		evt_old.state_old = inserted.first->second.state;
		inserted.first->second.state = evt.state;
		do_event(evt_old, "link_new", settings.actions_link_new, settings.filters_link_new);
		//evt_old.state_old.clear();
	}
	if (evt.address != inserted.first->second.address) {
		// MAC changed
		evt.address_old = inserted.first->second.address;
		inserted.first->second.address = evt.address;
		do_event(evt, "link_new", settings.actions_link_new, settings.filters_link_new);
	}
}

static void link_del(const nlmsghdr* hdr)
{
	EventLink evt;
	parse_link(hdr, evt);
	unsigned idx = static_cast<const ifinfomsg*>(NLMSG_DATA(hdr))->ifi_index;
	// Make sure to send route_del events for any routes we
	// might not have received such an event.
	auto foundr = map_idx_routes.find(idx);
	if (foundr != map_idx_routes.cend())
		for (auto route = foundr->second.cbegin(); route != foundr->second.cend(); ++route) {
			EventRoute evt_route;
			evt_route.ifname = evt.ifname;
			evt_route.address = route->destination;
			evt_route.gateway = route->gateway;
			evt_route.type_v6 = route->is_v6;
			evt_route.scope = route->scope;
			do_event(evt_route, "route_del", settings.actions_route_del, settings.filters_route_del);
		}
	map_idx_routes.erase(idx);
	// Make sure to send addr_del events for any addresses we
	// might not have received such an event.
	auto found = map_idx_addrs.find(idx);
	if (found != map_idx_addrs.cend())
		for (auto addr = found->second.cbegin(); addr != found->second.cend(); ++addr) {
			EventAddr evt_addr;
			evt_addr.ifname = evt.ifname;
			evt_addr.address = addr->to_string();
			evt_addr.type_v6 = addr->is_v6();
			do_event(evt_addr, "addr_del", settings.actions_addr_del, settings.filters_addr_del);
		}
	map_idx_addrs.erase(idx);
	map_idx_if.erase(idx);
	do_event(evt, "link_del", settings.actions_link_del, settings.filters_link_del);
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
		if (inserted.second)
			do_event(evt, "addr_new", settings.actions_addr_new, settings.filters_addr_new);
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
		do_event(evt, "addr_del", settings.actions_addr_del, settings.filters_addr_del);
	}
}

static void parse_route(const nlmsghdr& hdr, EventRoute& evt)
{
	const rtmsg* msg = static_cast<const rtmsg *>(NLMSG_DATA(&hdr));
	if (msg->rtm_type != RTN_UNICAST || msg->rtm_table != RT_TABLE_MAIN)
		return;
	if (msg->rtm_protocol != RTPROT_BOOT && msg->rtm_protocol != RTPROT_KERNEL &&
			msg->rtm_protocol != RTPROT_STATIC &&
			msg->rtm_protocol != RTPROT_RA)
		return;
	if (msg->rtm_family != AF_INET6 && msg->rtm_family != AF_INET)
		return;
	evt.if_idx = 0;
	evt.type_v6 = (msg->rtm_family == AF_INET6);
	evt.scope = msg->rtm_scope;
	int bytes = RTM_PAYLOAD(&hdr);
	for (const rtattr* attr = RTM_RTA(msg); RTA_OK(attr, bytes); attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case RTA_DST:
			evt.address = inet2str(attr, msg->rtm_family);
			break;
		case RTA_OIF:
			if (RTA_PAYLOAD(attr) == sizeof(uint32_t)) {
				evt.if_idx = *static_cast<uint32_t*>(RTA_DATA(attr));
				auto found = map_idx_if.find(evt.if_idx);
				if (found != map_idx_if.end())
					evt.ifname = found->second.ifname;
			}
			break;
		case RTA_GATEWAY:
			evt.gateway = inet2str(attr, msg->rtm_family);
			break;
		default:
			break;
		}
	}

	if (!evt.address.empty()) {
		if ((evt.type_v6 && msg->rtm_dst_len != 128) || (!evt.type_v6 && msg->rtm_dst_len != 32))
			evt.address += "/" + std::to_string(static_cast<unsigned>(msg->rtm_dst_len));
	} else if (msg->rtm_dst_len) {
		evt.address = "0/";
		evt.address += std::to_string(static_cast<unsigned>(msg->rtm_dst_len));
	}
	else
		evt.address = "default";
}

static void route_new(const nlmsghdr& hdr)
{
	EventRoute evt;
	parse_route(hdr, evt);

	if(evt.address.empty() || evt.ifname.empty())
		return;

	auto found = map_idx_routes.find(evt.if_idx);
	if (found == map_idx_routes.cend()) {
		auto if_found = map_idx_if.find(evt.if_idx);
		if (if_found == map_idx_if.cend())
			return;
		auto inserted = map_idx_routes.insert(std::make_pair(evt.if_idx, SetRoutes()));
		found = inserted.first;
	}
	if (found != map_idx_routes.cend()) {
		if (found->second.size() >= settings.max_routes_per_link) {
			if (!settings.rate_limit_seconds_exec_max_routes_per_link ||
				std::chrono::steady_clock::now() - time_last_msg_max_routes > std::chrono::seconds(settings.rate_limit_seconds_exec_max_routes_per_link)) {
				if (settings.exec_max_routes_per_link.empty())
					std::cerr << "Too many routes for '" << evt.ifname << "'!\n";
				else {
					std::string str(settings.exec_max_routes_per_link);
					stringReplace(str, "%i", evt.ifname);
					exec(std::move(str));
				}
				time_last_msg_max_routes = std::chrono::steady_clock::now();
			}
			return;
		}
		auto inserted = found->second.insert(Route(evt.address, evt.gateway, evt.type_v6, evt.scope));
		if (inserted.second)
			do_event(evt, "route_new", settings.actions_route_new, settings.filters_route_new);
	}
}

static void route_del(const nlmsghdr& hdr)
{
	EventRoute evt;
	parse_route(hdr, evt);

	if(evt.address.empty() || evt.ifname.empty())
		return;

	auto found = map_idx_routes.find(evt.if_idx);
	if (found != map_idx_routes.cend()) {
		found->second.erase(Route(evt.address, evt.gateway, false, evt.scope));
		do_event(evt, "route_del", settings.actions_route_del, settings.filters_route_del);
	}
}

class netlink_route_client
{
private:
	std::queue<std::vector<char>*> send_queue;
	void receive(void) {
		socket_.async_receive_from(
			boost::asio::buffer(data_, max_length), sender_endpoint_,
				boost::bind(&netlink_route_client::handle_receive_from, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
	}
	void handle_send(std::vector<char>* buf, const boost::system::error_code& ec, std::size_t)
	{
		delete buf;
		if (ec)
			std::cerr << "Error sending query (" << ec.message() << ")!\n";
	}
	void send(std::vector<char>* buf) {
		socket_.async_send_to(boost::asio::buffer(buf->data(), buf->size()), socket_.remote_endpoint(),
			boost::bind(&netlink_route_client::handle_send, this, buf,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));

	}
	void query_ifs(void) {
		auto buf = new std::vector<char>(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(rtgenmsg))), 0);
		nlmsghdr* nl_msg = reinterpret_cast<nlmsghdr*>(buf->data());
		nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtgenmsg));
		nl_msg->nlmsg_type = RTM_GETLINK;
		nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
		nl_msg->nlmsg_seq = ++seq;
		rtgenmsg* rt = reinterpret_cast<rtgenmsg*>(NLMSG_DATA(nl_msg));
		rt->rtgen_family = AF_PACKET;
		send(buf);
	}
	void queue_query_rtmsg(uint16_t type) {
		auto buf = new std::vector<char>(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(rtmsg))), 0);
		nlmsghdr* nl_msg = reinterpret_cast<nlmsghdr*>(buf->data());
		nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
		nl_msg->nlmsg_type = type;
		nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
		nl_msg->nlmsg_seq = ++seq;
		send_queue.push(buf);
	}

	void queue_query_addrs(void) {
		queue_query_rtmsg(RTM_GETADDR);
	}
	void queue_query_routes(void) {
		queue_query_rtmsg(RTM_GETROUTE);
	}
	boost::asio::netlink::route::socket socket_;
	boost::asio::netlink::route::endpoint sender_endpoint_;
	enum { max_length = 8192 };
	char data_[max_length];
	unsigned seq;

public:
	netlink_route_client(boost::asio::io_service& io_service)
		: socket_(io_service, boost::asio::netlink::route::endpoint(
			RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
			RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE))
		, seq(0)
	{
		// It would be better to use SOCK_CLOEXEC when opening the
		// socket, but as we are still single threaded here, it
		// should be ok.
		if (::fcntl(socket_.native_handle(), F_SETFD, FD_CLOEXEC))
			std::cerr << strerror(errno) << '\n';
		receive();
		queue_query_addrs();
		if (settings.route_new_for_existing_routes)
			queue_query_routes();
		if (!settings.link_new_for_existing_links)
			actions_disabled = true;
		query_ifs();
	}

	void handle_receive_from(const boost::system::error_code& error, size_t bytes_recvd) {
		if (error)
			std::cerr << "Error receiving netlink message (" << error.message() << ")!\n";
		const nlmsghdr* hdr = reinterpret_cast<const nlmsghdr*>(data_);
		if (!error && bytes_recvd && !sender_endpoint_.pid()) {
			if (hdr->nlmsg_flags & NLMSG_DONE && bytes_recvd == NLMSG_ALIGN(NLMSG_LENGTH(sizeof(rtgenmsg)))) {
				if (!send_queue.empty()) {
					if (send_queue.size() == 2 || (send_queue.size() == 1 && !settings.route_new_for_existing_routes))
						// next is the request to dump addresses
						actions_disabled = !settings.addr_new_for_existing_addresses;
					else
						// next is the request to dump routes
						actions_disabled = false; // == !settings.route_new_for_existing_routes;
					send(send_queue.front());
					send_queue.pop();
				} else if (actions_disabled)
					actions_disabled = false;
			}
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
				case RTM_NEWROUTE:
					if (settings.max_routes_per_link)
						route_new(*hdr);
					break;
				case RTM_DELROUTE:
					// settings.max_routes_per_link might set to 0 by reloading
					// the configuration, therefor we still (try to)
					// delete routes.
					route_del(*hdr);
					break;
				default:
					break;
				}
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
	std::cout << "\n(C) 2015 - 2018 Alexander Holler\n\n";

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

	if (argc == 3) {
		std::cout << "No errors found in config '" << config << "'.\n";
		return 0;
	}

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
