// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

// function made for commands with redirection
void perform_redirections(simple_command_t *s)
{
	// redirecting the input if needed
	if (s->in != NULL) {
		int input_fd = open(s->in->string, O_RDONLY);

		if (input_fd == -1) {
			perror("open input file");
			exit(EXIT_FAILURE);
		}
		dup2(input_fd, STDIN_FILENO);
		close(input_fd);
	}

	// redirecting output and error if needed
	if (s->out != NULL && s->err != NULL && strcmp(s->out->string, s->err->string) == 0) {
		int outputErr_fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (outputErr_fd == -1) {
			perror("open input file");
			exit(EXIT_FAILURE);
		}

		dup2(outputErr_fd, STDOUT_FILENO);
		dup2(outputErr_fd, STDERR_FILENO);
	} else {
		// redirecting only the output
		if (s->out != NULL) {
			int output_fd;

			if (s->io_flags & IO_OUT_APPEND)
				output_fd = open(s->out->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				output_fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (output_fd == -1) {
				perror("open output file");
				exit(EXIT_FAILURE);
			}

			dup2(output_fd, STDOUT_FILENO);
			close(output_fd);
		}

		// redirecting only the input
		if (s->err != NULL) {
			int error_fd;

			if (s->io_flags & IO_ERR_APPEND)
				error_fd = open(s->err->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				error_fd = open(s->err->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (error_fd == -1) {
				perror("open error file");
				exit(EXIT_FAILURE);
			}

			dup2(error_fd, STDERR_FILENO);
			close(error_fd);
		}
	}
}

// function for changing directory
static bool shell_cd(word_t *dir)
{
	if (chdir(dir->string) == 0)
		return true;
	else
		return false;
}

// function for exiting shell
static int shell_exit(void)
{
    /* TODO: Execute exit/quit. */

	return SHELL_EXIT;
}


static int parse_simple(simple_command_t *s, int level, command_t *father)
{
    /* TODO: Sanity checks. */

	if (level < 0)
		return SHELL_EXIT;
	else if (s == NULL)
		return SHELL_EXIT;


    /* TODO: If builtin command, execute the command. */
	// handle "cd" command
	if (strcmp(s->verb->string, "cd") == 0) {
		// redirecting output and error for "cd" command
		if (s->out != NULL && s->err != NULL) {
			int outputErr_fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (outputErr_fd == -1) {
				perror("open output file");
				exit(EXIT_FAILURE);
			}

			close(outputErr_fd);
		}

		// handle only output redirection for "cd" command
		if (s->out != NULL && s->err == NULL) {
			int output_fd;

			if (s->io_flags & IO_OUT_APPEND)
				output_fd = open(s->out->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				output_fd = open(s->out->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (output_fd == -1) {
				perror("open output file");
				exit(EXIT_FAILURE);
			}

			close(output_fd);
		}

		// handle only error redirection for "cd" command
		if (s->err != NULL && s->out == NULL) {
			int error_fd;

			if (s->io_flags & IO_ERR_APPEND)
				error_fd = open(s->err->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				error_fd = open(s->err->string, O_WRONLY | O_CREAT | O_TRUNC, 0644);

			if (error_fd == -1) {
				perror("open error file");
				exit(EXIT_FAILURE);
			}

			close(error_fd);
		}

		// execute "cd" command
		if (shell_cd(s->params))
			return 0;
		else
			return 1;
	}

	// executing "exit" or "quit" command
	if (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0)
		return shell_exit();

	// setting environment variables
	if (strchr(get_word(s->verb), '=') != 0) {
		int ret = setenv((char *)s->verb->string, get_word(s->verb->next_part->next_part), 1);

		return ret;
	}

	// fork a new process for the external commands
	pid_t pid = fork();
	int numArgv = 0;
	char **argv = get_argv(s, &numArgv);

	if (pid == 0) {
		// the child process performing redirections and executing the command
		perform_redirections(s);
		execvp(s->verb->string, argv);
	} else {
		// the parent process waiting for the child process to finish
		int child_status;

		waitpid(pid, &child_status, 0);
		int exitCode;

		// check if the child process finished normally
		if (WIFEXITED(child_status))
			exitCode = WEXITSTATUS(child_status);
		else
			exitCode = 1;

		return exitCode;
	}

	return 0;
}


/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	// fork a child process for the first command
	pid_t pid1, pid2;
	int status1, status2;

	pid1 = fork();

	if (pid1 == -1) {
		perror("fork");
		return false;
	}

	if (pid1 == 0) {
		// the child process of the first command executing the command
		int exit_status = parse_command(cmd1, level + 1, father);

		_exit(exit_status);
	}

	// fork a child process for the secound command
	pid2 = fork();

	if (pid2 == -1) {
		perror("fork");
		return false;
	}

	if (pid2 == 0) {
		// the child process of the secound command executing the command
		int exit_status = parse_command(cmd2, level + 1, father);

		_exit(exit_status);
	}

	// parent processes waiting for children to finish
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	// check if both children finished normally
	if (WIFEXITED(status1) && WIFEXITED(status2)) {
		if (WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0)
			return 1;
	}

	return 0;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */

static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	// comunication pipe for child processes
	int pipefd[2];

	if (pipe(pipefd) == -1) {
		perror("pipe");
		return false;
	}

	pid_t child1_pid, child2_pid;

	// fork child process for first command
	child1_pid = fork();

	if (child1_pid == -1) {
		perror("fork");
		return false;
	}

	if (child1_pid == 0) {
		close(pipefd[0]);

		// redirecting output
		dup2(pipefd[1], STDOUT_FILENO);

		close(pipefd[1]);

		// executing the first command
		int exit_status = parse_command(cmd1, level + 1, father);

		exit(exit_status);
	}

	// fork child process for secound command
	child2_pid = fork();

	if (child2_pid == -1) {
		perror("fork");
		return false;
	}

	if (child2_pid == 0) {
		close(pipefd[1]);

		// redirecting input
		dup2(pipefd[0], STDIN_FILENO);

		close(pipefd[0]);

		// executing the secound command
		int exit_status = parse_command(cmd2, level + 1, father);

		exit(exit_status);
	}


	close(pipefd[0]);
	close(pipefd[1]);

	int child1_status, child2_status;

	// waiting both children to finish
	waitpid(child1_pid, &child1_status, 0);
	waitpid(child2_pid, &child2_status, 0);

	return true;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (level < 0)
		return SHELL_EXIT;
	else if (c == NULL)
		return SHELL_EXIT;

	if (c->op == OP_NONE)
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level + 1, c);

	int ret1, ret2;

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		ret1 = parse_command(c->cmd1, level + 1, c);
		ret2 = parse_command(c->cmd2, level + 1, c);
		if (ret1 == 0 || ret2 == 0)
			return true;
		return false;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		if (!run_in_parallel(c->cmd1, c->cmd2, level + 1, c))
			return true;
		return false;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level + 1, c)) {
			if (!parse_command(c->cmd2, level + 1, c))
				return true;
			return false;
		}
		return true;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		if (!parse_command(c->cmd1, level + 1, c)) {
			if (!parse_command(c->cmd2, level + 1, c))
				return true;
			return true;
		}
		return false;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		if (!run_on_pipe(c->cmd1, c->cmd2, level + 1, c))
			return false;
		return true;

	default:
		return SHELL_EXIT;
	}

	return 0;
}
