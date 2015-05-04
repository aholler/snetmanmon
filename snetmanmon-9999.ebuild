# Ebuild written by Alexander Holler
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

# cmake-utils eclass modifies CMakeLists.txt which would make the
# version dirty. Therefor it isn't used.
inherit git-r3

KEYWORDS="arm amd64 x86"

EGIT_REPO_URI="git://github.com/aholler/snetmanmon.git"
[[ ${PV} == "9999" ]] || EGIT_COMMIT="v${PV}"

DESCRIPTION="A simple network manager and monitor for Linux"
HOMEPAGE="http://github.com/aholler/snetmanmon"

LICENSE="GPL-2"
SLOT="0"
IUSE=""
RDEPEND="dev-libs/boost"
DEPEND="${RDEPEND}
	dev-util/cmake"


src_configure() {
	cd "$S"
	cmake -DCMAKE_BUILD_TYPE=release -DCMAKE_INSTALL_PREFIX=/usr || die
}

src_compile() {
	VERBOSE=1 default
}

src_install() {
	VERBOSE=1 default
	dodoc snetmanmon.conf.log_example snetmanmon.conf.klog_example snetmanmon.conf.simple_example
	insinto /etc
	newins snetmanmon.conf.full_example snetmanmon.conf
	cat > snetmanmon.init << END
#!/sbin/runscript

extra_started_commands="reload"

depend() {
	after net
}

start() {
	ebegin "Starting snetmanmon"
	/usr/bin/snetmanmon -t /etc/snetmanmon.conf >/dev/null
	local rc=\$?
	start-stop-daemon --start --background --quiet \\
		--pidfile /run/snetmanmon.pid \\
		--exec /usr/bin/snetmanmon -- /etc/snetmanmon.conf
	eend \$rc "Failed to start snetmanmon"
}

stop() {
	ebegin "Stopping snetmanmon"
	start-stop-daemon --stop --quiet \\
		--pidfile /run/snetmanmon.pid \\
		--exec /usr/bin/snetmanmon
	eend \$? "Failed to stop snetmanmon"
}

reload() {
	ebegin "Reloading snetmanmon"
	/usr/bin/snetmanmon -t /etc/snetmanmon.conf >/dev/null
	local rc=\$?
	kill -HUP \$(cat /run/snetmanmon.pid) >/dev/null 2>&1
	eend \$rc "Failed to reload snetmanmon"
}
END
	newinitd snetmanmon.init snetmanmon
}
