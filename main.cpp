#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        return -fprintf(stderr, "usage: %s <port> <config-path>\n", argv[0]);
    }

    return 0;
}
