#include <iostream>
using namespace std;

#include "pwn4cpp.h"

int main(int argc, char *argv[])
{
	if (argc < 3) {
		cout << "missing host and port" << endl;
		return -1;
	}
	int port = atoi(argv[2]);

	pwn::Remote r(argv[1], port);

	r.send("Hello"s);
	r.interactive();
	return 0;
}
