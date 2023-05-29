#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    for(int i = 0; i < atoi(argv[3]); ++i)
    {
    int sockfd = 0;
    struct sockaddr_in serv_addr;

    if(argc != 4)
    {
        printf("\n Usage: %s <ip of server> <port> <connections> \n",argv[0]);
        return 1;
    }

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));

    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    }

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed [i=%d] [errno=%d]\n", i, errno);
       if(errno == 99)
               argv[1] = "127.0.0.1";
       else
               return 1;
    }
    }

    printf("Success!\n");
    return 0;
}
