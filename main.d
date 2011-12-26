import std.stdio, std.cstream, deimos.ev, std.c.linux.linux, std.c.linux.socket, std.c.string, std.c.stdlib, std.file, std.getopt;

struct clientConnection {
        int fd;
        ev_io ev_write;
		ev_io ev_read;
};

enum RunMode {
	IPv4,
	IPv6
}

immutable string VERSION = "0.1";

__gshared bool isDaemon = false;
__gshared bool isVerbose = false;
__gshared bool showStats = false;

__gshared RunMode runMode = RunMode.IPv4;

__gshared string policyData = "";

__gshared ev_io ev_accept_watcher;
__gshared ev_io ev_accept_watcher6;

__gshared ulong requests = 0;
__gshared ulong recentRequests = 0;
__gshared time_t currentTime = 0;

int setnonblock(int fd) {
    int flags;

    flags = fcntl(fd, F_GETFL);
	
    if (flags < 0)
            return flags;
	
    flags |= O_NONBLOCK;
	
    if (fcntl(fd, F_SETFL, flags) < 0) 
            return -1;

    return 0;
}

//callbacks
extern(C) {
	//send the policy file back
	static void write_cb(ev_loop_t *loop, ev_io *w, int revents) {
		clientConnection *cli = cast(clientConnection*)((cast(int)w - clientConnection.ev_write.offsetof));

		if (revents & EV_WRITE){
			core.sys.posix.unistd.write(cli.fd, std.string.toStringz(policyData), policyData.length);
		}
		
		close(cli.fd);
		free(cli);
		
		ev_io_stop(loop, w);
		
		//stats
		if (showStats) {
			requests++;
			recentRequests++;
			
			time_t pt;
			if (currentTime != time(&pt)) {
				writefln("Requests: %s/sec", recentRequests);
				
				currentTime = time(&pt);
				recentRequests = 0;
			}
		}
 	}
	
	//read from the socket, and setup the write event so we can send the policy file back
	static void read_cb(ev_loop_t *loop, ev_io *w, int revents) {
		ulong r = 0;
		char rbuff[10240]; //10 kb buffer
		
		clientConnection *cli = cast(clientConnection*)((cast(int)w - clientConnection.ev_read.offsetof));

		if (revents & EV_READ){
			r = core.sys.posix.unistd.read(cli.fd, &rbuff, rbuff.length);
		}
			
		ev_io_stop(loop, w);
		
		ev_io_init(&cli.ev_write, &write_cb, cli.fd, EV_WRITE);
		ev_io_start(loop, &cli.ev_write);
		
	}
	
	//accept a new connection. Create a clientConnection struct where we store information about the connection. Setup the read event and connect read_cb to it.
	static void accept_cb(ev_loop_t *loop, ev_io *w, int revents) {
		int client_fd;
		
		sockaddr* clientAddrPtr = null;
		socklen_t clientLen = 0;
		
		if (runMode == RunMode.IPv4) {
			clientAddrPtr = cast(sockaddr*)new sockaddr_in();
	    	clientLen = sockaddr_in.sizeof;
		}
		else if (runMode == RunMode.IPv6) {
			clientAddrPtr = cast(sockaddr*)new sockaddr_in6();
	    	clientLen = sockaddr_in6.sizeof;
		}
		else {
			throw new Exception("Unknown runMode!");
		}
		
		clientConnection *cli;
		
		client_fd = accept(w.fd, clientAddrPtr, &clientLen);
		
        if (client_fd == -1) {
			return;
        }
		
		if (setnonblock(client_fd) < 0) {
			if (isVerbose) {
				log("Error: failed to set client socket to non-blocking");
			}
		}
	   	 
		cli = cast(clientConnection*)calloc(1, clientConnection.sizeof);
		cli.fd = client_fd;
		
		if (isVerbose) {
			char[46] ip = 0;
			ushort port;
			
			if (runMode == RunMode.IPv4) {
				inet_ntop(AF_INET, &((cast(sockaddr_in*)clientAddrPtr).sin_addr), cast(char*)&ip, INET_ADDRSTRLEN);
				
				port = ntohs(((cast(sockaddr_in*)clientAddrPtr).sin_port));
			}
			else if (runMode == RunMode.IPv6) {
				inet_ntop(AF_INET6, &((cast(sockaddr_in6*)clientAddrPtr).sin6_addr), cast(char*)&ip, INET6_ADDRSTRLEN);
				
				port = ntohs((cast(sockaddr_in6*)clientAddrPtr).sin6_port);
			}
			
			log("New request from: %s:%s", ip, port);
		}
		
		delete clientAddrPtr;
			
		ev_io_init(&cli.ev_read, &read_cb, cli.fd, EV_READ);
		ev_io_start(loop, &cli.ev_read);
	}
}

void setupIPv4PolicyServer(string listenIP, ushort listenPort) {
	int listen_fd;
    sockaddr_in listen_addr; 
    int reuseaddr_on = 1;
	
	listen_fd = socket(AF_INET, SOCK_STREAM, 0); 
	
	if (listen_fd < 0) {
		log("Error: socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, reuseaddr_on.sizeof) == -1) {
    	log("Error: setsockopt failed");
		exit(EXIT_FAILURE);
	}
	
    memset(&listen_addr, 0, listen_addr.sizeof);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = inet_addr(std.string.toStringz(listenIP));
    listen_addr.sin_port = htons(listenPort);
	
	if (bind(listen_fd, cast(const(sockaddr*))&listen_addr, listen_addr.sizeof) < 0) {
    	log("Error: bind failed, port in use?");
		exit(EXIT_FAILURE);
	}
	
	//500 backlog connections
	if (listen(listen_fd, 500) < 0) {
		log("Error: listen failed");
		exit(EXIT_FAILURE);
	}
	
	if (setnonblock(listen_fd) < 0) {
    	log("Error: failed to set server socket to non-blocking");
		exit(EXIT_FAILURE);
	}
	
	if (!isDaemon) {
		log("Policy server started on %s:%s", listenIP, listenPort);
	}
	
	ev_loop_t* loop = ev_default_loop(0);
	
	ev_io_init(&ev_accept_watcher, &accept_cb, listen_fd, EV_READ);
	ev_io_start(loop, &ev_accept_watcher);
}

void setupIPv6PolicyServer(string listenIP, ushort listenPort) {
	int listen_fd;
    sockaddr_in6 listen_addr; 
    int reuseaddr_on = 1;
	
    listen_fd = socket(AF_INET6, SOCK_STREAM, 0); 
	
	if (listen_fd < 0) {
		log("Error: socket creation failed");
		exit(EXIT_FAILURE);
	}
	
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, reuseaddr_on.sizeof) == -1) {
    	log("Error: setsockopt failed");
		exit(EXIT_FAILURE);
	}
	
    memset(&listen_addr, 0, listen_addr.sizeof);
	listen_addr.sin6_family = AF_INET6;
	listen_addr.sin6_port = htons(listenPort);
	
	inet_pton(AF_INET6, std.string.toStringz(listenIP), &listen_addr.sin6_addr);
	
	if (bind(listen_fd, cast(const(sockaddr*))&listen_addr, listen_addr.sizeof) < 0) {
    	log("Error: bind failed, port in use?");
		exit(EXIT_FAILURE);
	}
	
	//5000 backlog connections
	if (listen(listen_fd, 5000) < 0) {
		log("Error: listen failed");
		exit(EXIT_FAILURE);
	}
	
	if (setnonblock(listen_fd) < 0) {
    	log("Error: failed to set server socket to non-blocking");
		exit(EXIT_FAILURE);
	}
	
	if (!isDaemon) {
		log("Policy server started on %s:%s", listenIP, listenPort);
	}
	
	ev_loop_t* loop = ev_default_loop(0);
	
	ev_io_init(&ev_accept_watcher6, &accept_cb, listen_fd, EV_READ);
	ev_io_start(loop, &ev_accept_watcher6);
}

void startPolicyServer() {
	ev_loop_t* loop = ev_default_loop(0);
	
	signal(SIGPIPE, &signalIgnoredHandler);
	
	ev_run(loop, 0);
}

extern(C) {
	void signalIgnoredHandler(int) {
	}
}

void log(T...)(T args) {
	if (!isDaemon) {
    	std.stdio.stdout.writefln(args);
	}
	
	//TODO: logfile
}

void main(string[] args) {
	string policyfileName = "flashpolicy.xml";
	string logfileName = "flashpolicy.log";
	
	bool ipv4 = true;
	bool ipv6 = false;
	
	string bindIP = "";
	
	ushort port = 843;
	
	void helpHandler(string option) {
		writefln("FlashPolleD %s - A high performance event based Flash policy server in D", VERSION);
		writefln("Usage: %s [-46bdfhpv]", args[0]);
		writefln("");
		writefln("  -4, --v4. --ipv4\t\tUse IPv4 sockets [default]");
		writefln("  -6, --v6. --ipv6\t\tUse IPv6 sockets");
		writefln("  -b, --bind=HOST\t\tBind the socket to HOST");
		writefln("  -d, --daemon\t\t\tDaemonize the server");
		writefln("  -f. --policyfile=PATH\t\tPolicyfile to serve");
		writefln("  -h, --help\t\t\tHelp");
		writefln("  -p, --port=PORT\t\tListen on PORT");
		writefln("  -s, --stats\t\t\tShow stats");
		writefln("  -v, --verbose\t\t\tShow more debuginformation");
		
		exit(0);
	}
	
	getopt(args,
		std.getopt.config.bundling,
		std.getopt.config.caseInsensitive,
		
		"daemon|d", &isDaemon,
		"policyfile|f", &policyfileName,
		
		"ipv4|v4|4", &ipv4,
		"ipv6|v6|6", &ipv6,
		
		"bind|b", &bindIP,
		"port|p", &port,
		
		"help|h", &helpHandler,
		"verbose|v", &isVerbose,
		"stats|s", &showStats
	);
	
	if (!ipv4 && !ipv6) {
		log("No network family to bind to!");
		exit(EXIT_FAILURE);
	}
	
	//read policy file
	if (!policyfileName.isFile()) {
		log("Error: policyfile missing");
		exit(EXIT_FAILURE);
	}
	
	policyData = readText(policyfileName);
	//read policy file
	
	if (isDaemon) {
    	pid_t pid, sid;
		
        pid = fork();
        if (pid < 0) {
            exit(EXIT_FAILURE);
        }
		else if (pid > 0) {
            exit(EXIT_SUCCESS);
        }
 
        umask(0);
 
        sid = setsid();
        if (sid < 0) {
            exit(EXIT_FAILURE);
        }
 
        if ((core.sys.posix.unistd.chdir("/")) < 0) {
            exit(EXIT_FAILURE);
        }
 
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
	}
	
	if (ipv6) { //a ipv6 listener will also handle ipv4 requests
		if (bindIP.length == 0) {
			bindIP = "::0";
		}
		
		runMode = RunMode.IPv6;
		
		setupIPv6PolicyServer(bindIP, port);
	}
	else if (ipv4) {
		if (bindIP.length == 0) {
			bindIP = "0.0.0.0";
		}
		
		runMode = RunMode.IPv4;
		
		setupIPv4PolicyServer(bindIP, port);
	}
	
	startPolicyServer();
}