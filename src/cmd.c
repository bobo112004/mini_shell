// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	if (!dir || dir->next_part != NULL || !dir->string)
		return false;

	if (chdir(dir->string) == -1)
		return true;
	return false;
}

/**
 * Helper pentru functiile externe care se ocupa cu stdin, stdout si stderr
 */
void std_helper(simple_command_t *s)
{
	if (s->in) {
		char *path = get_word(s->in);
		int fd = open(path, O_RDONLY);

		free(path);
		if (fd == -1)
			exit(EXIT_FAILURE);
		if (dup2(fd, STDIN_FILENO) == -1) {
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}
	char *path1 = get_word(s->out), *path2 = get_word(s->err);

	if (s->out && s->err && !(strcmp(path1, path2))) {
		int fd = -1;

		if (s->io_flags == IO_ERR_APPEND || s->io_flags == IO_OUT_APPEND)
			fd = open(path1, O_CREAT | O_WRONLY | O_APPEND, 0644);
		else
			fd = open(path1, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		if (fd == -1)
			exit(EXIT_FAILURE);
		if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1) {
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	} else {
		if (s->out) {
			char *path = get_word(s->out);
			int fd = -1;

			if (s->io_flags == IO_REGULAR)
				fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			else if (s->io_flags == IO_OUT_APPEND)
				fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
			free(path);
			if (fd == -1)
				exit(EXIT_FAILURE);
			if (dup2(fd, STDOUT_FILENO) == -1) {
				close(fd);
				exit(EXIT_FAILURE);
			}
			close(fd);
		}
		if (s->err) {
			char *path = get_word(s->err);
			int fd = -1;

			if (s->io_flags == IO_REGULAR)
				fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			else if (s->io_flags == IO_ERR_APPEND)
				fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
			free(path);
			if (fd == -1)
				exit(EXIT_FAILURE);
			if (dup2(fd, STDERR_FILENO) == -1) {
				close(fd);
				exit(EXIT_FAILURE);
			}
			close(fd);
		}
	}
	free(path1);
	free(path2);
}

/**
 * Helper pentru functia interna cd (build-in)
 */
static void std_cd_helper(simple_command_t *s)
{
	int stdout = dup(STDOUT_FILENO);
	int stderr = dup(STDERR_FILENO);

	if (stdout == -1 || stderr == -1)
		exit(EXIT_FAILURE);
	if (s->in) {
		char *path = get_word(s->in);
		int fd = open(path, O_RDONLY);

		free(path);
		if (fd == -1)
			exit(EXIT_FAILURE);
		if (dup2(fd, STDIN_FILENO) == -1) {
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}
	if (s->out) {
		char *path = get_word(s->out);
		int fd = -1;

		if (s->io_flags == IO_REGULAR)
			fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		else if (s->io_flags == IO_OUT_APPEND)
			fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
		free(path);
		if (fd == -1)
			exit(EXIT_FAILURE);
		if (dup2(fd, STDOUT_FILENO) == -1) {
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}
	if (s->err) {
		char *path = get_word(s->err);
		int fd = -1;

		if (s->io_flags == IO_REGULAR)
			fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
		else if (s->io_flags == IO_ERR_APPEND)
			fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
		free(path);
		if (fd == -1)
			exit(EXIT_FAILURE);
		if (dup2(fd, STDERR_FILENO) == -1) {
			close(fd);
			exit(EXIT_FAILURE);
		}
		close(fd);
	}
	if (dup2(stdout, STDOUT_FILENO) == -1)
		exit(EXIT_FAILURE);
	if (dup2(stderr, STDERR_FILENO) == -1)
		exit(EXIT_FAILURE);
	close(stderr);
	close(stdout);
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	return SHELL_EXIT;
}

static int shell_pwd(simple_command_t *s)
{
	int stdout = dup(STDOUT_FILENO);

	if (stdout == -1)
		return EXIT_FAILURE;
	std_helper(s);
	char cwd[2048];

	if (getcwd(cwd, sizeof(cwd))) {
		strcat(cwd, "\n");
		write(STDOUT_FILENO, cwd, strlen(cwd));
	} else {
		return EXIT_FAILURE;
	}
	if (dup2(stdout, STDOUT_FILENO) == -1)
		return EXIT_FAILURE;
	close(stdout);
	return EXIT_SUCCESS;
}



static int shell_ext_command(simple_command_t *s)
{
	pid_t pid = fork();

	if (!pid) {
		std_helper(s);
		int size;
		char **args = get_argv(s, &size);
		char *cmd = get_word(s->verb);

		if (execvp(cmd, args) == -1) {
			for (int i = 0; i < size; i++)
				free(args[i]);
			char err[1024] = "Execution failed for '";

			strcat(err, cmd);
			strcat(err, "'\n\0");
			write(STDERR_FILENO, err, strlen(err));
			free(cmd);
			exit(EXIT_FAILURE);
		}
		free(cmd);
		for (int i = 0; i < size; i++)
			free(args[i]);
		exit(EXIT_SUCCESS);
	}
	int ok;

	waitpid(pid, &ok, 0);
	return WEXITSTATUS(ok);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s || !s->verb)
		return -1;

	s->aux = get_word(s->verb);

	if (!strcmp((char *)s->aux, "cd")) {
		free(s->aux);
		std_cd_helper(s);
		return shell_cd(s->params);
	}

	if (!strcmp((char *)s->aux, "exit") || !strcmp((char *)s->aux, "quit")) {
		free(s->aux);
		return shell_exit();
	}

	if (!strcmp((char *)s->aux, "pwd")) {
		free(s->aux);
		return shell_pwd(s);
	}
	free(s->aux);

	if (s->verb->next_part && s->verb->next_part->next_part && !strcmp(s->verb->next_part->string, "=")) {
		char *value = get_word(s->verb->next_part->next_part);

		int ok = setenv(s->verb->string, value, 1);

		free(value);
		return ok;
	}
	return shell_ext_command(s);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t pid = fork();

	if (!pid)
		exit(parse_command(cmd1, level + 1, father));

	pid_t pid2 = fork();

	if (!pid2)
		exit(parse_command(cmd2, level + 1, father));

	int ok1, ok2;

	if (waitpid(pid, &ok1, 0) != pid || waitpid(pid2, &ok2, 0) != pid2)
		return false;
	return true;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pipe_fd[2];

	pipe(pipe_fd);
	pid_t pid = fork();

	if (!pid) {
		close(pipe_fd[READ]);
		if (dup2(pipe_fd[WRITE], STDOUT_FILENO) == -1)
			exit(EXIT_FAILURE);
		exit(parse_command(cmd1, level + 1, father));
	}
	pid_t pid2 = fork();

	if (!pid2) {
		close(pipe_fd[WRITE]);
		if (dup2(pipe_fd[READ], STDIN_FILENO) == -1)
			exit(EXIT_FAILURE);
		exit(parse_command(cmd2, level + 1, father));
	}
	close(pipe_fd[READ]);
	close(pipe_fd[WRITE]);
	int ok;

	waitpid(pid, &ok, 0);
	waitpid(pid2, &ok, 0);
	return WEXITSTATUS(ok);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (!c)
		return 0;

	if (c->op == OP_NONE) {
		simple_command_t *cmd = c->scmd;

		if (!strcmp(cmd->verb->string, "true")) {
			pid_t pid = fork();

			if (!pid) {
				char *const args[] = {"true", NULL};

				execvp("true", args);
			} else {
				int ok;

				waitpid(pid, &ok, 0);
				return WEXITSTATUS(ok);
			}
		}
		if (!strcmp(cmd->verb->string, "false")) {
			pid_t pid = fork();

			if (!pid) {
				char *const args[] = {"false", NULL};

				execvp("false", args);
			} else {
				int ok;

				waitpid(pid, &ok, 0);
				return WEXITSTATUS(ok);
			}
		}
		return parse_simple(c->scmd, level, father);
	}

	int ok = 0;

	switch (c->op) {
	case OP_SEQUENTIAL:
		ok += parse_command(c->cmd1, level + 1, c);
		ok += parse_command(c->cmd2, level + 1, c);
		return ok;

	case OP_PARALLEL:
		return run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

	case OP_CONDITIONAL_NZERO:
		if (parse_command(c->cmd1, level + 1, c))
			return parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		if (!parse_command(c->cmd1, level + 1, c))
			return parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, c);

	default:
		return SHELL_EXIT;
	}

	return 0;
}
