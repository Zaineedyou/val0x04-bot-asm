#include <stdio.h>

extern char **environ;
extern int asm_service_start(char **envp);
extern int secure_transport_init(void);
extern const char *secure_transport_last_error(void);

int main(void) {
    int status = secure_transport_init();
    if (status != 0) {
        fprintf(stderr, "val0x04-asm: secure transport init failed: %s\n",
                secure_transport_last_error());
        return 1;
    }
    return asm_service_start(environ);
}
