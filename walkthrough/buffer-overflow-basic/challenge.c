#include <stdio.h>
#include <stdlib.h>

int oh_look_useful() {
    asm("jmp %esp");
}

int main() {
    char buffer[32];
    gets(buffer);
}

