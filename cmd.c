/**
 * Operating Systems 2013-2017 - Assignment 2
 *
 * Moisa Anca-Elena, 331CA
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Open file by type (input, output. error) and by argument -
 * append or not.
 */
static int open_by_type(int filedes, const char *filename, int do_append,
		char *type)
{
	int ret;
	int fd;

	if (strcmp(type, "input") == 0) {
		fd = open(filename, O_RDWR);
		DIE(fd < 0, "Unable to open file!");
	}

	if (strcmp(type, "else") == 0) {
		if (do_append == FALSE) {
			fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
					0644);
			DIE(fd < 0, "Unable to open file!");
		} else if (do_append == TRUE) {
			fd = open(filename, O_WRONLY | O_APPEND | O_CREAT,
					0644);
			DIE(fd < 0, "Unable to open file!");
		}
	}

	ret = dup2(fd, filedes);
	DIE(ret < 0, "Failed while redirecting!");

	close(fd);
	return 0;
}

/**
 * Redirrect file by type (input, output, error).
 */
static void redirrect_by_type(simple_command_t *s)
{
	char *type;
	int do_append = FALSE, ret;
	char *input_file, *output_file, *error_file;

	/* in out and err point to the names of the redirections for
	 * the command
	 */
	input_file = get_word(s->in);
	output_file = get_word(s->out);
	error_file = get_word(s->err);

	/*
	 * < file_name - redirrect stdin from file_name
	 */
	if (input_file != NULL) {
		type = "input";
		ret = open_by_type(STDIN_FILENO, input_file,
					do_append, type);
		DIE(ret < 0, "Unable to redirrect input!");
	}

	/*
	 * > file_name - redirrect stdout in file_name
	 * >> file_name - redirect stdout in file_name - append mode
	 */
	if (output_file != NULL) {
		type = "else";
		if (s->io_flags == IO_REGULAR) {
			do_append = FALSE;
			ret = open_by_type(STDOUT_FILENO, output_file,
						do_append, type);
			DIE(ret < 0, "Unable to redirrect regular output!");
		} else if (s->io_flags == IO_OUT_APPEND) {
			do_append = TRUE;
			ret = open_by_type(STDOUT_FILENO, output_file,
						do_append, type);
			DIE(ret < 0, "Unable to redirrect append output!");
		}
	}

	/*
	 * 2> file_name - redirrect stderr in file_name
	 * 2>> file_name - redirect stderr in file_name - append mode
	 */
	if (error_file != NULL) {
		type = "else";
		if (s->io_flags == IO_REGULAR) {
			do_append = FALSE;
			ret = open_by_type(STDERR_FILENO, error_file,
						do_append, type);
			DIE(ret < 0,
				"Unable to redirrect regular error-output!");
		} else if (s->io_flags == IO_ERR_APPEND) {
			do_append = TRUE;
			ret = open_by_type(STDERR_FILENO, error_file,
						do_append, type);
			DIE(ret < 0,
				"Unable to redirrect append error!");
		}

		/* Some string literals can be found in both the out list
		 * and the err list (those entered as "command &> out").
		 */
		if (output_file != NULL)
			if (strcmp(output_file, error_file) == 0) {
				ret = dup2(STDERR_FILENO, STDOUT_FILENO);
				DIE(ret < 0, "dup2");
			}
	}

	free(input_file);
	free(output_file);
	free(error_file);
}

/**
 * Function to set environment variables.
 */
static int set_var(const char *var, const char *value)
{
	return setenv(var, value, 1);
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(simple_command_t *s, word_t *dir)
{
	int ret, fd;
	char *directory;
	char *output_file;

	directory = get_word(dir);
	output_file = get_word(s->out);

	if (output_file != NULL) {
		if (s->io_flags == IO_REGULAR) {
			fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC,
					0644);
			DIE(fd < 0, "Unable to open file!");
			close(fd);
		} else if (s->io_flags == IO_OUT_APPEND) {
			fd = open(output_file, O_WRONLY | O_APPEND | O_CREAT,
					0644);
			DIE(fd < 0, "Unable to open file!");
			close(fd);
		}
		free(output_file);
	}

	if (directory == NULL)
		fprintf(stderr,
			"Argument expected! Usage: cd [arg1]/[arg2]/...\n");
	else {
		ret = chdir(directory);
		if (ret == -1)
			fprintf(stderr, "Unable to find file or directory!\n");
	}

	free(directory);
	return ret;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* close fd */
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	char *line;
	const char *var, *value;
	int ret, wait_ret;

	line = get_word(s->verb);
	/* sanity checks */
	if (s == NULL)
		DIE(s == NULL, "NULL! Insert command.");
	if (s->verb == NULL)
		DIE(s->verb == NULL, "exe_name or internal_comand_name NULL!");
	/* if builtin command, execute the command */
	/* check exit command */
	if (strncmp("exit", line, strlen("exit")) == 0 ||
		strncmp("quit", line, strlen("quit")) == 0) {
		free(line);
		ret = shell_exit();
		return ret;
	}

	/* check cd command */
	if (strncmp("cd", line, strlen("cd")) == 0) {
		ret = shell_cd(s, s->params);
		free(line);
		return ret;
	}
	/* if variable assignment, execute the assignment and return
	 * the exit status
	 *
	 * next_part points to the next part of a string or is NULL
	 * if there are no more parts
	 *
	 * s->verb->next_part -> "="
	 * s->verb->next_part->next_part -> value
	 * if they exist, then call setenv
	 */
	if ((s->verb->next_part != NULL) &&
		(s->verb->next_part->string != NULL) &&
		(s->verb->next_part->next_part != NULL) &&
		(s->verb->next_part->next_part->string != NULL)) {
		if (strcmp(s->verb->next_part->string, "=") == 0) {
			var = s->verb->string;
			value = s->verb->next_part->next_part->string;
			ret = set_var(var, value);
			free(line);
			return ret;
		}
		free(line);
	}

	free(line);

	/* external command */
	pid_t pid;
	int status, size;
	char **given_args, *command;

	/* fork new process */
	pid = fork();

	switch (pid) {
	case -1:
		DIE(pid == -1, "fork");

	case 0:
		/* perform redirections in child */
		redirrect_by_type(s);

		/* load executable in child */
		given_args = get_argv(s, &size);
		command = get_word(s->verb);
		execvp(command, given_args);
		fprintf(stderr, "Execution failed for '%s'\n", command);
		free(given_args);
		free(command);
		exit(EXIT_FAILURE);

	default:
		/* wait for child */
		wait_ret = waitpid(pid, &status, 0);
		DIE(wait_ret < 0, "Error: waitpid");
		if (!WIFEXITED(status))
			return EXIT_FAILURE;
		else
			return WEXITSTATUS(status);
	}
	return status; /* return exit status */
}

/**
 * Wait for the child.
 */
static int wait_pid(pid_t pid)
{
	int status, wait_ret;

	wait_ret = waitpid(pid, &status, 0);
	DIE(wait_ret < 0, "waitpid err");
	if (!WIFEXITED(status))
		return EXIT_FAILURE;
	else
		return WEXITSTATUS(status);
}

/**
 * Create child without wait.
 */
static void choose_pid(pid_t pid, command_t *cmd, int level, command_t *father)
{
	switch (pid) {
	case -1:
		DIE(pid == -1, "fork");

	case 0:
		parse_command(cmd, level, father);
		exit(EXIT_FAILURE);

	default:
		/* parent process does not wait for the child process */
		break;
	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* execute cmd1 and cmd2 simultaneously */
	pid_t pid1, pid2;

	/* start first process */
	pid1 = fork();
	choose_pid(pid1, cmd1, level, father);

	/* start second process */
	pid2 = fork();
	choose_pid(pid2, cmd2, level, father);

	/* wait process1 */
	wait_pid(pid1);

	/* wait process2 */
	wait_pid(pid2);

	return TRUE;
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */
	int pipe_fd[2], ret, wait_ret, status;
	pid_t pid1, pid2;

	ret = pipe(pipe_fd);
	DIE(ret < 0, "Error pipe!");

	/* start p1 */
	pid1 = fork();
	switch (pid1) {
	case -1:
		DIE(pid1 == -1, "Error: fork1");

	case 0:
		/* start p2 */
		pid2 = fork();
		switch (pid2) {
		case -1:
			DIE(pid2 == -1, "Error: fork2");

		case 0:
			ret = close(pipe_fd[READ]);
			DIE(ret < 0, "Unable to close file!");

			ret = dup2(pipe_fd[WRITE], STDOUT_FILENO);
			DIE(ret < 0, "dup2 err");

			ret = close(pipe_fd[WRITE]);
			DIE(ret < 0, "Unable to close file!");

			ret = parse_command(cmd1, level, father);
			DIE(ret < 0, "Unable to parse command!");

			exit(EXIT_FAILURE);

		default:
			ret = close(pipe_fd[WRITE]);
			DIE(ret < 0, "Unable to close file!");

			ret = dup2(pipe_fd[READ], STDIN_FILENO);
			DIE(ret < 0, "dup2 err");

			ret = close(pipe_fd[READ]);
			DIE(ret < 0, "Unable to close file!");

			ret = parse_command(cmd2, level, father);
			DIE(ret < 0, "Unable to parse command!");

			/* cmd2 - exit code */
			exit(ret);
			break;
		}
		break;

	default:
		ret = close(pipe_fd[STDIN_FILENO]);
		DIE(ret < 0, "Error close STDIN!");

		ret = close(pipe_fd[STDOUT_FILENO]);
		DIE(ret < 0, "Error close STDOUT!");

		/* wait p1 */
		wait_ret = waitpid(pid1, &status, 0);
		DIE(wait_ret < 0, "waitpid err");
		if (!WIFEXITED(status))
			return EXIT_FAILURE;
		else
			return WEXITSTATUS(status);
	}
	return TRUE;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int ret;

	/* sanity checks */
	if (c == NULL)
		DIE(c == NULL, "null command");

	/* execute a simple command */
	if (c->op == OP_NONE) {
		ret = parse_simple(c->scmd, level + 1, father);
		return ret;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* execute the commands one after the other */
		parse_command(c->cmd1, level + 1, father);
		parse_command(c->cmd2, level + 1, father);
		break;

	case OP_PARALLEL:
		/* execute the commands simultaneously */
		do_in_parallel(c->cmd1, c->cmd2, level + 1, father);
		break;

	case OP_CONDITIONAL_NZERO:
		/* execute the second command only if the first one
		 * returns non zero
		 */
		ret = parse_command(c->cmd1, level + 1, father);
		if (ret != 0)
			ret = parse_command(c->cmd2, level + 1, father);
		return ret;

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
		 * returns zero
		 */
		ret = parse_command(c->cmd1, level + 1, father);
		if (ret == 0)
			ret = parse_command(c->cmd2, level + 1, father);
		return ret;

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second
		 */
		ret = do_on_pipe(c->cmd1, c->cmd2, level + 1, father);
		return ret;

	default:
		return SHELL_EXIT;
	}
	return 0;
}
