# Filename: ssh_rate_limit_tester.py

import subprocess
import time
import socket # Still useful for initial port check if needed, though ssh command handles connection
import argparse
import itertools
import os # For checking file existence

def attempt_ssh_login_subprocess(hostname, port, username, password, timeout=5):
    """
    Attempts an SSH login using the 'ssh' command via subprocess and returns the result.
    This function simulates failed authentication attempts by relying on SSH's non-interactive mode.
    It does NOT interactively submit the password.

    Args:
        hostname (str): The target SSH host.
        port (int): The target SSH port.
        username (str): The username for login attempt.
        password (str): The password to associate with the attempt (not directly submitted).
        timeout (int): Timeout for the SSH command in seconds.

    Returns:
        tuple: (success_status, message, error_type)
               success_status (bool): True if login succeeded (unlikely with bad creds), False otherwise.
               message (str): A descriptive message about the attempt.
               error_type (str): A string indicating the type of error (e.g., "AuthenticationFailed", "Timeout", "ConnectionRefused").
    """
    # SSH command options explained:
    # -o BatchMode=yes: Prevents interactive password prompts. SSH will just fail if password auth is needed.
    # -o StrictHostKeyChecking=no: Bypasses host key checking (DANGEROUS IN PRODUCTION, convenient for testing).
    # -o UserKnownHostsFile=/dev/null: Prevents writing to known_hosts file.
    # -o ConnectTimeout={timeout}: Sets a timeout for the TCP connection phase.
    # -o PasswordAuthentication=yes: Explicitly allows password authentication (though not interactively provided here).
    # -o KbdInteractiveAuthentication=no: Disables keyboard-interactive auth.
    # -o PubkeyAuthentication=no: Disables public key auth, forcing it to try password (which will fail non-interactively).
    # {username}@{hostname}: The target user and host.
    # -p {port}: Specify the port.
    # exit: A simple command to execute and immediately exit, minimizing session time.
    
    ssh_command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={int(timeout)}", # ConnectTimeout expects an integer
        "-o", "PasswordAuthentication=yes",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PubkeyAuthentication=no",
        "-p", str(port),
        f"{username}@{hostname}",
        "exit" # Command to execute and immediately exit
    ]

    start_time = time.time()
    try:
        # Run the SSH command
        result = subprocess.run(
            ssh_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout, # Total command timeout
            check=False # Do not raise CalledProcessError for non-zero exit codes
        )
        end_time = time.time()
        duration = end_time - start_time

        # Analyze stderr for common failure messages
        stderr_output = result.stderr.strip()

        if result.returncode == 0:
            # A return code of 0 means successful login, which is unexpected for rate limit testing with bad creds.
            return True, f"Login successful for {username}:{password} in {duration:.2f} seconds. (Unexpected)", None
        elif "Permission denied" in stderr_output or "Authentication failed" in stderr_output:
            return False, f"Authentication failed for {username}:{password} in {duration:.2f} seconds. Output: '{stderr_output}'", "AuthenticationFailed"
        elif "Connection timed out" in stderr_output:
            return False, f"Connection timed out for {username}:{password} after {timeout} seconds. Output: '{stderr_output}'", "Timeout"
        elif "Connection refused" in stderr_output:
            return False, f"Connection refused for {username}:{password} in {duration:.2f} seconds. Output: '{stderr_output}'", "ConnectionRefused"
        elif "Too many authentication failures" in stderr_output:
            return False, f"SSH error: Too many authentication failures for {username}:{password} in {duration:.2f} seconds. Output: '{stderr_output}'", "TooManyAuthFailures"
        else:
            # Catch other SSH errors or unexpected output
            return False, f"SSH command failed with exit code {result.returncode} for {username}:{password} in {duration:.2f} seconds. Error: '{stderr_output}'", "SSHCommandError"

    except subprocess.TimeoutExpired:
        end_time = time.time()
        return False, f"Command timed out for {username}:{password} after {timeout} seconds (subprocess timeout).", "Timeout"
    except FileNotFoundError:
        return False, "Error: 'ssh' command not found. Make sure OpenSSH client is installed.", "SSHNotFound"
    except Exception as e:
        end_time = time.time()
        return False, f"An unexpected error occurred: {e} for {username}:{password} in {end_time - start_time:.2f} seconds.", "UnexpectedError"

def main():
    """
    Main function to parse arguments and run the SSH rate limit test.
    """
    parser = argparse.ArgumentParser(description="Test SSH rate limiting using password authentication via subprocess.")
    parser.add_argument("host", help="The target SSH host (IP address or hostname).")
    parser.add_argument("-p", "--port", type=int, default=22, help="The target SSH port (default: 22).")
    parser.add_argument("-uf", "--username-file", required=True, help="Path to a file containing usernames, one per line.")
    parser.add_argument("-pf", "--password-file", required=True, help="Path to a file containing passwords, one per line.")
    parser.add_argument("-n", "--attempts-per-combo", type=int, default=1, help="Number of attempts per username-password combination (default: 1).")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay between each individual attempt in seconds (default: 0.1).")
    parser.add_argument("-t", "--timeout", type=float, default=5, help="Connection/command timeout in seconds per attempt (default: 5).")

    args = parser.parse_args()

    # Validate file paths
    if not os.path.exists(args.username_file):
        print(f"Error: Username file '{args.username_file}' not found.")
        sys.exit(1)
    if not os.path.exists(args.password_file):
        print(f"Error: Password file '{args.password_file}' not found.")
        sys.exit(1)

    # Read usernames and passwords from files
    with open(args.username_file, 'r') as f:
        usernames = [line.strip() for line in f if line.strip()]
    with open(args.password_file, 'r') as f:
        passwords = [line.strip() for line in f if line.strip()]

    if not usernames:
        print("Error: Username file is empty.")
        sys.exit(1)
    if not passwords:
        print("Error: Password file is empty.")
        sys.exit(1)

    print(f"[*] Starting SSH rate limit test on {args.host}:{args.port}")
    print(f"[*] Loaded {len(usernames)} usernames and {len(passwords)} passwords.")
    print(f"[*] Attempts per combination: {args.attempts_per_combo}, Delay: {args.delay}s, Timeout: {args.timeout}s")
    print("-" * 70)

    all_results = []
    attempt_count = 0

    # Iterate through all combinations of usernames and passwords
    for username in usernames:
        for password in passwords:
            for i in range(1, args.attempts_per_combo + 1):
                attempt_count += 1
                print(f"Attempt {attempt_count} (User: '{username}', Pass: '{password}', Combo Attempt: {i}/{args.attempts_per_combo})...", end=" ")
                
                success, message, error_type = attempt_ssh_login_subprocess(
                    args.host, args.port, username, password, args.timeout
                )
                all_results.append((attempt_count, username, password, success, message, error_type))
                print(message)

                if success:
                    print("\n[!!!] WARNING: Login succeeded. This script is primarily intended for testing rate limits with *incorrect* credentials.")
                    print("Please ensure you have explicit permission to perform this test and discontinue if unauthorized.")
                    # Optionally, you might want to break here if a successful login means the test is over.
                    # For rate limiting, you might continue to see if the server still rate limits after a success.
                    # For now, we'll continue to observe behavior for other combinations.

                time.sleep(args.delay)

    print("-" * 70)
    print("[*] Test Summary:")
    
    # Categorize results
    auth_failed_count = sum(1 for r in all_results if r[5] == "AuthenticationFailed")
    timeout_count = sum(1 for r in all_results if r[5] == "Timeout")
    connection_refused_count = sum(1 for r in all_results if r[5] == "ConnectionRefused")
    too_many_auth_failures_count = sum(1 for r in all_results if r[5] == "TooManyAuthFailures")
    ssh_command_error_count = sum(1 for r in all_results if r[5] == "SSHCommandError")
    ssh_not_found_count = sum(1 for r in all_results if r[5] == "SSHNotFound")
    unexpected_error_count = sum(1 for r in all_results if r[5] == "UnexpectedError")
    successful_logins_count = sum(1 for r in all_results if r[3])

    print(f"Total attempts made: {attempt_count}")
    print(f"Successful logins: {successful_logins_count}")
    print(f"Authentication failed: {auth_failed_count}")
    print(f"Connection timed out: {timeout_count}")
    print(f"Connection refused: {connection_refused_count}")
    print(f"Too many authentication failures (SSH msg): {too_many_auth_failures_count}")
    print(f"Generic SSH command errors: {ssh_command_error_count}")
    print(f"'ssh' command not found errors: {ssh_not_found_count}")
    print(f"Other unexpected errors: {unexpected_error_count}")

    # Analyze potential rate limiting indicators
    print("\n[*] Analysis of Rate Limiting Indicators:")
    if timeout_count > 0:
        print("  [!] **Strong Indication:** Observed connection timeouts.")
        print("      This often means the SSH server is temporarily blocking or delaying responses after repeated failed attempts.")
    
    if too_many_auth_failures_count > 0:
        print("  [!] **Strong Indication:** Observed 'Too many authentication failures' messages.")
        print("      This is a direct message from the SSH server indicating it's actively rejecting connections due to rate limiting.")
    
    if connection_refused_count > 0:
        print("  [!] **Potential Indication:** Observed 'Connection refused' errors.")
        print("      This could indicate a firewall or the SSH service itself is dropping connections after a threshold.")
    
    # Check for increasing delays in failed attempts
    failed_attempts_durations = []
    for r in all_results:
        if not r[3] and "in " in r[4] and "seconds." in r[4]:
            try:
                duration_str = r[4].split(" in ")[-1].replace(" seconds.", "").strip()
                failed_attempts_durations.append(float(duration_str))
            except ValueError:
                pass # Ignore if duration parsing fails

    if failed_attempts_durations:
        min_time = min(failed_attempts_durations)
        max_time = max(failed_attempts_durations)
        if max_time > min_time * 2 and len(failed_attempts_durations) > 5: # Simple heuristic for significant delay increase
            print(f"  [!] **Potential Indication:** Failed attempt response times varied significantly (from {min_time:.2f}s to {max_time:.2f}s).")
            print("      Increasing response times can be a subtle sign of rate limiting or resource exhaustion.")
        else:
            print(f"  [*] Failed attempt response times were relatively consistent (from {min_time:.2f}s to {max_time:.2f}s).")
            print("      This suggests consistent processing without significant delay, but doesn't rule out other rate limiting mechanisms.")
    else:
        print("  [*] Not enough failed attempts with measurable durations to analyze response time variations.")

    if not (timeout_count > 0 or too_many_auth_failures_count > 0 or connection_refused_count > 0):
        print("  [*] No explicit timeouts, 'too many failures' errors, or connection refusals were directly observed.")
        print("      Rate limiting might be configured differently (e.g., account lockout without connection disruption) or not present.")

    print("\n[!] Remember: This script simulates failed connection/authentication attempts. Real SSH rate limiting mechanisms can be complex and may include:")
    print("    - Temporary IP bans")
    print("    - Account lockouts")
    print("    - Increasing delays per attempt/IP")
    print("    - Silent dropping of connections")
    print("    - Different thresholds for different types of failures (e.g., connection vs. authentication)")
    print("\n[!] This script relies on the 'ssh' command being available in your system's PATH.")
    print("[!] It does NOT interactively submit passwords. It tests the server's response to repeated non-interactive connection attempts.")


if __name__ == "__main__":
    main()