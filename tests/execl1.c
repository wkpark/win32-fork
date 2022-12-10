#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <process.h>
#endif

pid_t fork(void);

int main(int argc, const char *argv[])
{
	int fd[2];
	int n;
#ifdef _WIN32
	int result = _pipe(fd, 4096, _O_BINARY);
#else
	int result = pipe(fd);
#endif
	pid_t pid = fork();
	char buf[255];

	switch (pid) {
	case 0:
		//dup2(fd[1], STDOUT_FILENO);
		//dup2(fd[1], STDERR_FILENO);
		fprintf(stderr, "*** child\n");

#ifdef _WIN32
		execl("C:\\windows\\notepad.exe", "C:\\windows\\notepad.exe", 0);
		//execl(getenv("COMSPEC"), getenv("COMSPEC"), "/c", "dir", 0);
#else
		execl("/bin/sh", "/bin/sh", "-c", "ls", 0);
#endif
		_exit(4);
		break;
	default:
		fprintf(stderr, "*** parent\n");
		usleep(3000);
		break;
	}
	return 0;
}
