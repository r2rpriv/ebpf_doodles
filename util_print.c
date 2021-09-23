#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LN_WIDTH 80

void printLine(unsigned char *line,int ln,int width){
    for(int i=0;i<width;i++){
      if(!i)
          printf("line %d:%c",ln,(isascii(*line)?*line:0x20));
      else
          printf("%c",(isascii(*(line+i))?*(line+i):0x20));
    }
    printf("\n");
    return;
}
void print_buffer(unsigned char* buffer, int len){

    //We're going to print 80 characters per line
    int lc = 0;
    int not_printed = len;
    int rc = (not_printed%LN_WIDTH);
    int no_of_lines = (rc)?(not_printed/LN_WIDTH)+1:(not_printed/LN_WIDTH);
    unsigned char *pb = buffer;

    printf("no lines %d,remaining chars %d\n",no_of_lines,rc);
    for(lc=0;lc<(no_of_lines-1);lc++)
        printLine(&pb[(lc*LN_WIDTH)],lc,LN_WIDTH);
    //just to avoid clumsy space management last line is either full width or partial
    if(rc)
        printLine(&pb[(lc*LN_WIDTH)],lc,rc);
    else
        printLine(&pb[(lc*LN_WIDTH)],lc,LN_WIDTH);

    return;
}
