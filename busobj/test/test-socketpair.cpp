#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <thread>

#ifdef WIN32
extern "C" int socketpair(int domain, int type, int protocol, int sv[2]);
#define ERR(e) \
        { \
        printf("%s:%s failed: %d [%s@%d]\n",__FUNCTION__,e,WSAGetLastError(),__FILE__,__LINE__); \
        }
#endif

struct pairs {
    int a{};
    int b{};
};

void fib1(int socket, struct pairs pair) {
    struct pairs fib_pair = pair;
    while (fib_pair.b < 1000) {
        int ret;
        const int temp = fib_pair.a + fib_pair.b;
        fib_pair.a = fib_pair.b;
        fib_pair.b = temp;
#ifdef WIN32
        ret = send(socket, (const char*)&fib_pair, sizeof(fib_pair), 0);
        if (ret == SOCKET_ERROR) {
            ERR("fib1 send");
        }
        ret = recv(socket, (char*)&fib_pair, sizeof(fib_pair), 0);
        if (ret == SOCKET_ERROR) {
            ERR("fib1 recv");
        }
#else
        write(socket, &fib_pair, sizeof(fib_pair));
        read(socket, &fib_pair, sizeof(fib_pair));
#endif
        printf("[%d, %d]\n", fib_pair.a, fib_pair.b);

    }
}

void fib2(int socket) {
    struct pairs fib;
    int ret;
    // TODO: this loop never ends
#ifdef WIN32
    while ((ret = recv(socket, (char*)&fib, sizeof(fib), 0)))
    {
        if (ret == SOCKET_ERROR) {
            if (ret == SOCKET_ERROR) {
                ERR("fib2 recv");
            }
        }
        const int temp = fib.a + fib.b;
        fib.a = fib.b;
        fib.b = temp;
        ret = send(socket, (const char*)&fib, sizeof(fib), 0);
        if (ret == SOCKET_ERROR) {
            if (ret == SOCKET_ERROR) {
                ERR("fib2 send");
            }
        }
        if (temp > 1000)
            break;
    }
#else
    while (read(socket, &fib, sizeof(fib))) {
        const int temp = fib.a + fib.b;
        fib.a = fib.b;
        fib.b = temp;
        write(socket, &fib, sizeof(fib));
    }
#endif
}

int main() {
    struct pairs fib_pair;
    fib_pair.a = 0;
    fib_pair.b = 1;

    int pipefd[2];
    int socket_ret = socketpair(AF_INET, SOCK_STREAM, 0, pipefd);

    std::thread thread_fib1(fib1, pipefd[0], fib_pair);
    std::thread thread_fib2(fib2, pipefd[1]);

    thread_fib1.join();
    thread_fib2.join();

    return 0;
}