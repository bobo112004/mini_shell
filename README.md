## MiniShell - A Custom Bash-like Shell

### Introduction
Developed a **custom Bash-like shell** that replicates core functionalities of a Unix shell, including **command execution, file system navigation, process management, and I/O redirection**. This project provides in-depth experience with **process creation (`fork()`), inter-process communication (`pipe()`), and file descriptor manipulation (`dup2()`)**.

### Features
- Implemented built-in commands: **`cd` (change directory) and `pwd` (print working directory)**.
- Enabled **execution of external applications** using **`fork()`** for process creation.
- Supported **environment variables**, allowing value assignment and substitution.
- Implemented **operators** for command chaining:
  - **`|`** (pipe) for redirecting output between commands.
  - **`&&` / `||`** for conditional execution.
  - **`&`** for parallel execution.
  - **`;`** for sequential execution.
- Added **I/O redirection**:
  - Input (`<`), output (`>`), error (`2>`), append (`>>`), and combined redirection (`&>`).
- **Ensured robust error handling and process management** by handling invalid commands, incorrect arguments, and missing files, managing child processes with `fork()`, `execvp()`, and `waitpid()`, implementing proper exit codes for command success/failure, validating input and edge cases for directory navigation, variable expansion, and I/O redirections, and ensuring safe execution of chained operations (`&&`, `||`, `;`, `&`) through return code checks.
