package main

import "core:log"
import "core:net"
import "core:os"
import "core:thread"


main :: proc() {

	context.logger = log.create_console_logger()
	address := "127.0.0.1"
	port := 10502

	local_address, ok := net.parse_ip4_address(address)
	if !ok {
		log.infof("%v is not a valid ip address", address)
		os.exit(1)
	}

	endpoint := net.Endpoint {
		address = local_address,
		port    = port,
	}

	sock, err := net.listen_tcp(endpoint)

	if err != nil {
		log.errorf("cannot start socket: %v", err)
		os.exit(1)
	}

	log.infof("Server listening on \"%v:%v\"", address, port)

	for {
		cli, from, err_accept := net.accept_tcp(sock)
		if err_accept != nil {
			log.errorf("connection refused reason: %v", err_accept)
			continue
		} else {
		    log.info("Connection accepted")
		}

		//TODO(Kay): Try create and start with data!
	}

	defer net.close(sock)
}
