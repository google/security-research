#include <dns_util.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	uint8_t buf[1024] = { 0 };
	int sz = read(0, &buf, sizeof(buf));

	// Move this to a heap chunk to help ASAN out
	uint8_t *hbuf = malloc(sz);
	memcpy(hbuf, buf, sz);

	dns_reply_t *reply = dns_parse_packet((const char *)hbuf, sz);

	free(reply);
	free(hbuf);

	return 0;
}

// int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
// 	if (size < 10) return 0;
// 	dns_reply_t *reply = dns_parse_packet((const char *)data, size);
// 
// 	free(reply);
// 	return 0;
// }
