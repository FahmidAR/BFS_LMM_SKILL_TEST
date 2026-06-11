#include <stdio.h>
#include <string.h>

int main() {
    char source[] = "Skill Skan Goal";
    char destination[50];

    strcpy(destination, source);

    printf("Source:      %s\n", source);
    printf("Destination: %s\n", destination);

    return 0;
}
