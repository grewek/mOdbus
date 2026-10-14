package main

import "core:encoding/endian"
import "core:log"
import "core:net"
import "core:os"
import "core:testing"
import "core:thread"
import "core:time"

MBAP_Header :: struct {
	transaction_id: u16,
	protocol_id:    u16,
	length:         u16,
	unit_id:        u8,
}

parse_mbap_header :: proc(message: []u8) -> (MBAP_Header, bool) {

	if len(message) < 7 {
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

	if length > 254 {
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

handle_message :: proc(message: []u8) {
	log.infof("Raw Message: %v", message[:])
}

MBAP_HEADER_SIZE :: 7

MessageState :: enum {
	Validated,
	Incomplete,
	Invalid,
}
validate_message :: proc(raw_message: []u8) -> (int, MessageState) {
	if len(raw_message) <= MBAP_HEADER_SIZE {
		return -1, .Incomplete
	}

	header, header_valid := parse_mbap_header(raw_message[:MBAP_HEADER_SIZE])

	if !header_valid {
		return -1, .Invalid
	}

	frame_size := (MBAP_HEADER_SIZE - 1) + int(header.length)
	if len(raw_message) < frame_size {
		return -1, .Incomplete
	}


	return frame_size, .Validated
}

TcpConnection :: struct {
	connection: net.TCP_Socket,
	timeout:    int,
	buffer:     [512]u8,
	length:     int,
}
handle_connection :: proc(connection: net.TCP_Socket) {
	message_buffer: [512]u8
	message_length: int = 0
	timeout: time.Duration = 5 * time.Second

	//NOTE: Close the connection once the transaction completes
	defer net.close(connection)

	//TODO: The timeout is for recv_tcp it does not measure the time it takes to get the whole frame. This is something i should take into consideration
	net.set_option(connection, .Receive_Timeout, timeout)

	for {
		bytes_received, err_received := net.recv_tcp(connection, message_buffer[message_length:])
		message_length += bytes_received

		log.infof("Received data with length of %v", message_length)
		if err_received != .None {
			log.errorf("failed to receive data: %v", err_received)
			break
		}

		if bytes_received == 0 {
			log.info("client closed connection")
			break
		}

		for {
			frame_size, frame_valid := validate_message(message_buffer[0:message_length])

			if frame_valid == .Incomplete {
				break
			}

			if frame_valid == .Invalid {
				log.info("Received invalid frame, server is closing connection")
				return
			}

			if frame_valid == .Validated {
				log.infof(
					"Server received [%d bytes]: %v",
					bytes_received,
					message_buffer[:frame_size],
				)
				handle_message(message_buffer[:frame_size])
				copy_slice(message_buffer[0:], message_buffer[frame_size:message_length])
				message_length -= frame_size
			}
		}
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

		handle_connection(incoming_connection)
	}

	defer net.close(sock)
}
