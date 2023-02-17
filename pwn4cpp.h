#ifndef _PWN4CPP_H_
#define _PWN4CPP_H_

#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>
#include <stdexcept>
#include <arpa/inet.h>
#include <netinet/in.h>

using std::string_literals::operator""s;

namespace pwn {

// Underlying type for raw bytes
using bytes = std::vector<uint8_t>;

// conversion bytes <-> std::string
std::string bytes2str(const bytes &data) { return std::string(data.begin(), data.end()); }
bytes str2bytes(const std::string &str) { return bytes(str.begin(), str.end()); }

// printinf functions
void print_error(const std::string &str)
{
#ifdef DEBUG
	std::cerr << "\x1b[91m[-] "s + str + "\x1b[0m"s << std::endl;
#endif
}

void print_info(const std::string &str)
{
#ifdef DEBUG
	std::cerr << "[*] "s + str << std::endl;
#endif
}

void print_warning(const std::string &str)
{
#ifdef DEBUG
	std::cerr << "\x1b[94m[+] "s + str + "\x1b[0m"s << std::endl;
#endif
}

void print_success(const std::string &str)
{
#ifdef DEBUG
	std::cerr << "\x1b[92m[+] "s + str + "\x1b[0m"s << std::endl;
#endif
}

class Remote {
private:
	bool _connected = false;
	std::string _host;
	uint16_t _port;
	int _socket = -1;

	void do_close()
	{
		if (_socket != -1) {
			shutdown(_socket, SHUT_RDWR);
			close(_socket);
			_socket = -1;
		}
		// silently unset parameters anyway
		_host = "<not connected>"s;
		_port = 0;
		_connected = false;
	}
public:
	Remote(const std::string &host, uint16_t port, bool resolve_dns=true)
		: _host(host), _port(port)
	{
		_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (_socket == -1) {
			print_error("Socket error");
			do_close();
			return;
		}
		if (resolve_dns) {
			// TODO : DNS resolution
		}
		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(_port);
		if (inet_pton(AF_INET, _host.c_str(), (sockaddr *) &(sin.sin_addr)) < 1)
			throw std::runtime_error("Invalid host");
		if (connect(_socket, (sockaddr *)&sin, sizeof(sockaddr_in)) != 0) {
			print_error("Unable to connect");
			do_close();
			return;
		}
		_connected = true;
		print_success("Connected to "s + _host + " on port " + std::to_string(_port));
	}

	bytes recv(size_t buffersize=2048)
	{
		if (! _connected)
			throw std::runtime_error("Not connected");
		bytes result;
		result.resize(buffersize);
		int recv_result = ::recv(_socket, result.data(), buffersize, 0);
		if (recv_result == 0) {
			print_warning("Peer has closed the connection");
			do_close();
		} else if (recv_result < 0) {
			throw std::runtime_error("Recv error");
		}
		print_success("Received "s + std::to_string(recv_result) + " byte/s");
		result.resize(recv_result);
		return result;
	}

	std::string recvstr(size_t buffersize=2048)
	{
		return bytes2str(recv(buffersize));
	}

	int send(const bytes &data)
	{
		if (! _connected)
			throw std::runtime_error("Not connected");
		int sent = ::send(_socket, data.data(), data.size(), 0);
		if (sent == -1)
			throw std::runtime_error("Send error");
		print_success("Sent "s + std::to_string(sent) + " byte/s");
		return sent;
	}

	int send(const std::string &str)
	{
		return send(str2bytes(str));
	}

	~Remote()
	{
		do_close();
		//print_info("Closing connection.");
	}

	void interactive()
	{
		print_success("Going interactive...");
		std::thread th_recv (_interactive_recvloop, this);

		std::string r;
		while (true) {
			std::getline(std::cin, r, '\x04');
			//r += '\x0a'; // TODO
			try {
				send(r);
			} catch (...) {
				break;
			}
		}
		th_recv.join();
	}
private:
	static void _interactive_recvloop(Remote *r)
	{
		while (true) {
			std::string s;
			try {
				// TODO: use select?
				s = r->recvstr(1024);
			} catch (...) {
				break;
			}
			std::cout << s << std::flush;
		}
	}
};

class exploit {
private:
	// Avoid creation
	exploit() {};
public:
	static bytes fmtstr64(uint64_t reflection_index, uintptr_t target, uint64_t what)
	{
		bytes result;
		uint8_t char_count = 0;
		int current_index = reflection_index;
		std::vector<std::pair<uintptr_t, uint8_t>> couples;

		for (int i = 0; i < 8; ++i) {
			couples.push_back(std::make_pair(target+i, *(((uint8_t*)&what)+i)));
		}
		std::sort(couples.begin(), couples.end(), [](const auto&a, const auto&b) {return a.second < b.second;});

		/*
		 * Per ogni byte che scrivo, devo mettere in testa l'indirizzo dove riprenderlo
		 * Quindi, inizialmente scrivo 8*n#indirizzi bytes
		 */
		for (unsigned int i = 0; i < couples.size(); i++) {
			//std::cout << "Chiave: " << hex << couples[i].first << " -> " << hex << (int) couples[i].second << std::endl;
			char_count += 8;
			for (int j = 0; j < 8; j++) {
				result.push_back((couples[i].first >> (8*j)) & 0xFF);
			}
		}
		// riporto a 0 il conteggio
		bytes filler = str2bytes("%" + std::to_string(256-char_count) + "c");
		result.insert(result.end(), filler.begin(), filler.end());
		char_count = 0;

		for (unsigned int i = 0; i < couples.size(); i++) {
			bytes value = str2bytes("%" + std::to_string((uint8_t)(couples[i].second - char_count)) + "c");
			bytes address = str2bytes("%" + std::to_string(current_index++) + "$hhn");
			result.insert(result.end(), value.begin(), value.end());
			result.insert(result.end(), address.begin(), address.end());
			char_count += value.size() + address.size();
		}

		return result;
	}
};


}; // namespace pwn

#endif /* _PWN4CPP_H_ */
