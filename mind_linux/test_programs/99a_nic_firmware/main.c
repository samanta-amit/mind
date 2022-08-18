#include <stdlib.h>
#include <stdio.h>
#include "main.h"

DEFINE_CMD(cmd1, 0x5f, ('m')('c')('r')('a')(' ')('m')('l')('x')('5')('_')('0')(' ')('0')('x')('5')('3')('6')('1')('c')('.')('1')('2')(':')('1')(' ')('0'))
DEFINE_CMD(cmd2, 0x0a, ('m')('c')('r')('a')(' ')('m')('l')('x')('5')('_')('0')(' ')('0')('x')('5')('3')('6')('3')('c')('.')('1')('2')(':')('1')(' ')('0'))


int main(void)
{
	printf("Init test\n");
	system(Getcmd1());
	system(Getcmd2());
	return 0;
}
