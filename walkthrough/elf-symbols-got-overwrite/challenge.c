#include <stdio.h>
#include <stdlib.h>

int oh_look_useful() {
    system("/bin/sh");
}

int main() {
    void *infoleak = &main;

    write(1, &infoleak, sizeof(infoleak));

    while(1) {
        void **where;
        void *what;

        read(0, &where, sizeof(where));
        read(0, &what, sizeof(what));

        printf("*%p == %p\n", where, what);
        *where = what;
    }
}

