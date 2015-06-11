#include <stdio.h>
#include <stdlib.h>

int oh_look_useful() {
    asm("bx sp");
}

int main() {
    char buffer[32];
    gets(buffer);
}

