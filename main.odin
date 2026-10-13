package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:os"
import "core:thread"

MBAP_Header :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

//TODO(Kay): We should write the raw data into the ringbuffer and the parser should try to extract a modbus message from it.
MessageRingBuffer :: struct {
	buffer:         [512]u8,
	read_position:  u16,
	write_position: u16,
}

parse_mbap_header :: proc(message: []u8) -> (MBAP_Header, bool) {

	if len(message) < size_of(MBAP_Header) {
		log.errorf("Expected a length of %v but got %v", size_of(MBAP_Header), message)
		return {}, false
	}

	transaction_id, transaction_ok := endian.get_u16(message[0:2], .Big)
	if !transaction_ok {
		log.errorf("cannot read transaction id from message")
		return {}, false
	}

	protocol_id, protocol_ok := endian.get_u16(message[2:4], .Big)
	if !protocol_ok {
		log.errorf("cannot read protocol id from message")
		return {}, false
	}

	if protocol_id != 0 {
		log.errorf("invalid protocol id indicated by the header")
		return {}, false
	}

	length, length_ok := endian.get_u16(message[4:6], .Big)
	if !length_ok {
		log.errorf("cannot read length from message")
		return {}, false
	}

	if length > 255 {
		log.errorf("length field has an invalid size")
		return {}, false
	}

	return MBAP_Header {
			transaction_id = transaction_id,
			protocol_id = protocol_id,
			length = length,
			unit_id = message[6],
		},
		true
}

handle_message :: proc(header: MBAP_Header, message: []u8) {
	log.infof("Header Info: %v", header)
}

handle_connection :: proc(connection: net.TCP_Socket) {
	message_buffer: [256]u8

	for {
		bytes_received, err_received := net.recv_tcp(connection, message_buffer[:])

		if err_received != nil {
			log.errorf("failed to receive data: %v", err_received)
		}

		received := message_buffer[:bytes_received]

		if len(received) == 0 {
			log.infof("client disconnected")
			break
		}

		header: MBAP_Header
		ok: bool
		header, ok = parse_mbap_header(received)


		if !ok {
			continue
		}

		handle_message(header, message_buffer[:7])


		log.infof("Server received [%d bytes]: %v", bytes_received, received)
	}
}

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
		incoming_connection, from, err_accept := net.accept_tcp(sock)
		if err_accept != nil {
			log.errorf("connection refused reason: %v", err_accept)
			continue
		} else {
			log.info("Connection accepted")
		}

		thread.create_and_start_with_poly_data(incoming_connection, handle_connection, context)
	}

	defer net.close(sock)
}
