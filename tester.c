/*****************************************************************************
 *
 * tester --
 *
 * A program that leaks a lot of memory, but not too fast.
 * 10MB / sec.
 *
 * To be released under the GNU GPL v2.
 *
 *****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define kBYTES 1000 /* bytes to allocate on each cycle */
#define kSLEEP 100 /* sleep time in us between cycles */

int main(int argc, char** argv)
{
	while(1) {
		char* ptr = malloc(kBYTES);
		memset(ptr, 0xAB, kBYTES);
		usleep(kSLEEP);
	}
	return -1;
}