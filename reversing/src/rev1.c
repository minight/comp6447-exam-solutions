#include <stdio.h>

#define N 5
char move(char v, char i) {
	return (v + i) % N;
}
