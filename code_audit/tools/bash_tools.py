"""Shell command execution tools for agents."""

import subprocess


def run_command(command: str, timeout: int = 120) -> str:
    """Execute a shell command and return combined stdout and stderr.

    Used primarily by pecker_scanner for running external analysis tools.

    Args:
        command: Shell command string to execute.
        timeout: Maximum execution time in seconds (default 120).

    Returns:
        Combined stdout and stderr output. Output longer than 50000
        characters is truncated. Non-zero exit codes are appended as
        "[exit code: N]".
    """
    max_output = 50000

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr

        if len(output) > max_output:
            output = output[:max_output] + "\n... (output truncated)"

        if result.returncode != 0:
            output += f"\n[exit code: {result.returncode}]"

        return output.strip()

    except subprocess.TimeoutExpired:
        return f"Error: command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error executing command: {e}"
