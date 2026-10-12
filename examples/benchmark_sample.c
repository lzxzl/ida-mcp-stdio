/* Small deterministic input for the documented static-summary benchmark. */
#include <stdio.h>
#include <string.h>

int verify_token(const char *token) {
    return strlen(token) == 14 && strcmp(token, "ida-mcp-sample") == 0;
}

int main(int argc, char **argv) {
    int accepted = argc > 1 && verify_token(argv[1]);
    puts(accepted ? "accepted" : "denied");
    return accepted ? 0 : 1;
}
