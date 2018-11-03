#include <stdio.h>

#define N 5
#define YD '1'
#define XD '3'
#define PR '4'
#define XI '5'
#define YI '7'

// 0 1 2
// 3 4 5
// 6 7 8

// solution: 4545454545745454545457454545454574545454545745454545457

const int view[N][N] = {
	'f', 'o', 'h', 'a', 'i', 
	'l', 'h', 'a', 'r', 'n',
	'a', 'a', 'r', 't', 'g',
	'g', 'i', '_', 'h', 'z',
	'{', 't', 'e', 'l', '}'
};

char move(char v, char i) {
	return (v + i) % N;
}

int main(int argc, char **argv) {
	char x, y = 0;
	while (1) {
		char ch = getchar();
		switch (ch) {
			case YI:
				y = move(y, 1);
				break;
			case XD:
				x = move(x, -1);
				break;
			case PR:
				printf("%c", view[x][y]);
				break;
			case XI:
				x = move(x, 1);
				break;
			case YD:
				y = move(y, -1);
			case ' ':
			case '\r':
			case '\n':
			case '\t':
			default:
				printf("\n");
				return 0;
		}
	}
}
