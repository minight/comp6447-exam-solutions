#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

#define NUM_STOCKS (sizeof(g_stocks)/sizeof(stock_t))

typedef struct stock {
	char ticker[8];
	float opening;
	float current;
	char note[64];
} stock_t;

stock_t *stock_new(char *ticker, char *note, float price) {
	stock_t *this = malloc(sizeof(stock_t));
	snprintf(this->ticker, sizeof(this->ticker), "%s", ticker);
	snprintf(this->note, sizeof(this->note), "%s", note);
	this->opening = price;
	this->current = price;
	return this;
}

