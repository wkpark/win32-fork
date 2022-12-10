#include <stdio.h>
#include <unistd.h>
#ifdef _WIN32
#include <process.h>
#endif

pid_t fork(void);

int main(void) {
	pid_t pid = fork();

	switch (pid) {
	case 0:
		{
			FILE *f = fopen("test.txt", "w");
			fprintf(f, "ok\n");
			fclose(f);
			printf("*** child\n");
			break;
		}
	default:
		printf("*** parent\n");
		printf("child %d\n", pid);
		while (1) { usleep(1000); }
		break;
	}

	return 0;
}
