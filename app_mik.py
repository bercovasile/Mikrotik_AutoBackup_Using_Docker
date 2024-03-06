import paramiko
import os
import re
import argparse
from cryptography.fernet import Fernet
import time
from github import Github

# Create argument parser with program description
parser = argparse.ArgumentParser(description='The purpose of this program is to generate backups for a series of MikroTik devices.')
parser.add_argument(
    '-g_u',
    '--github_username',
    type=str,
    help='Set GitHub username '
)
parser.add_argument(
    '-g_t',
    '--github_token',
    type=str,
    help='Set path to file containing encrypt GitHub token'
)
parser.add_argument(
    '-g_r',
    '--repository_name',
    type=str,
    help='Set repository name on GitHub'
)
parser.add_argument(
    '-m_u',
    '--mikrotik_username',
    type=str,
    help='Set path to file containing encrypt MikroTik username'
)
parser.add_argument(
    '-m_p',
    '--mikrotik_password',
    type=str,
    help='Set path to file containing encrypt MikroTik password'
)
parser.add_argument(
    '-m_ip',
    '--mikrotik_ip_file',
    type=str,
    default='./mikrotik_ip.txt',
    help='Set path to file containing MikroTik IPs'
)
parser.add_argument(
    '-m_key',
    '--key_filename',
    type=str,
    help='Set path to file containing encrypt MikroTik private key '
)
parser.add_argument(
    '-d_key',
    '--key_decrypte',
    type=str,
    help='Set key decrypt'
)
args = parser.parse_args()

#---------------------Key-Decrypy-----------------------------------

with open(args.key_decrypte, 'rb') as file_key_decrypte:
    key_decrypte=file_key_decrypte.read()

f = Fernet(key_decrypte.decode())

#-------------------------------------------------------------------


#f = Fernet(str(args.key_decrypte))

#-----------------------USERNAME------------------------------------

with open(args.mikrotik_username, 'rb') as file_mikrotik_user_enc:
    mikrotik_user_enc=file_mikrotik_user_enc.read()

mikrotik_username = f.decrypt(mikrotik_user_enc)
mikrotik_username = mikrotik_username.decode()

#-------------------------------------------------------------------
#-----------------------PASSWORD------------------------------------

with open(args.mikrotik_password, 'rb') as file_mikrotik_pass_enc:
    mikrotik_pass_enc=file_mikrotik_pass_enc.read()

mikrotik_password = f.decrypt(mikrotik_pass_enc)
mikrotik_password = mikrotik_password.decode()

#-------------------------------------------------------------------

#----------------------PRIVATE-KEY----------------------------------

with open(args.key_filename, 'rb') as file_mikrotik_key_enc:
    mikrotik_key_enc=file_mikrotik_key_enc.read()

with open('./id_rsa', 'wb') as fill_private_key:
    fill_private_key.write(f.decrypt(mikrotik_key_enc))

key_filename = './id_rsa'

#-------------------------------------------------------------------

#-----------------------Git-Token-----------------------------------

with open(args.github_token , 'rb') as file_git_token_enc:
    git_token_enc=file_git_token_enc.read()

github_token = f.decrypt(git_token_enc)
github_token = github_token.decode()

#-------------------------------------------------------------------

mikrotik_ip_file = args.mikrotik_ip_file
github_username = args.github_username
repository_name = args.repository_name


# Function to create an SSH connection to MikroTik device
def create_ssh_connection(hostname, username, key_filename, password=None):
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        pkey = paramiko.RSAKey.from_private_key_file(key_filename)
        ssh_client.connect(
            hostname,
            username=username,
            pkey=pkey,
            look_for_keys=False,
            allow_agent=False,
            disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
            timeout=50
        )
    except paramiko.AuthenticationException as e:
        print(f"Failed to authenticate using the provided private key: {str(e)}")
        if password:
            try:
                ssh_client.connect(
                    hostname,
                    username=username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False,
                    disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                    timeout=50
                )
            except paramiko.AuthenticationException as e:
                print(f"Failed to authenticate using password: {str(e)}")
                # Handle the authentication failure here if needed
        else:
            print("No password provided. Skipping password authentication.")
            # Handle the case where no password is provided for fallback authentication
    
    return ssh_client


# Function to create a backup of MikroTik configuration
def backup_router_config(ssh_client, hostname):
    command = "system backup save name=backup-{}_{} dont-encrypt=yes".format(time.strftime("%d-%m-%Y-%H"), hostname)
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode('utf-8')
    print(output)

    scp = ssh_client.open_sftp()
    remote_file_path = '/backup-{}_{}.backup'.format(time.strftime("%d-%m-%Y-%H"), hostname)
    local_file_path = './backup-{}_{}.backup'.format(time.strftime("%d-%m-%Y-%H"), hostname)
    scp.get(remote_file_path, local_file_path)
    scp.close()

# Function to send backup file to GitHub repository
def send_file_to_github(hostname, github_token, repository_name):
    local_file_path = './backup-{}_{}.backup'.format(time.strftime("%d-%m-%Y-%H"), hostname)
    github = Github(github_token)
    user = github.get_user()
    repo = user.get_repo(repository_name)

    try:
        file = repo.get_contents(local_file_path)
        sha = file.sha if file else None
    except Exception as e:
        sha = None
        print(f"Error getting file information: {str(e)}")

    with open(local_file_path, 'rb') as file:
        content = file.read()
        try:
            file_on_github = repo.get_contents(local_file_path)
            repo.update_file(file_on_github.path, f"Backup configuration at {time.strftime('%d-%m-%Y-%H-%M-%S')} from {hostname}", content, file_on_github.sha)
            print(f"Backup updated on GitHub in repository {repository_name}!")
            print("Backup successfully downloaded: {}".format(local_file_path))
        except Exception as e:
            repo.create_file(local_file_path, f"Backup configuration at {time.strftime('%d-%m-%Y-%H-%M-%S')} from {hostname}", content)
            print(f"Backup uploaded to GitHub in repository {repository_name}!")
            print("Backup successfully downloaded: {}".format(local_file_path))
    os.remove(local_file_path)

# Function to remove backup from MikroTik device
def remove_backup_on_mikrotik(ssh_client, hostname):
    time.sleep(5)
    command = "/file remove backup-{}_{}.backup".format(time.strftime("%d-%m-%Y-%H"), hostname)
    stdin, stdout, stderr = ssh_client.exec_command(command)
    output = stdout.read().decode('utf-8')
    print(output)
    print("Backup successfully deleted from MikroTik: {}".format(hostname))

# Function to read IP addresses from file and validate them
def read_ip_from_path_and_validate_ip(ip_file_path):
    valid = []
    invalid = []
    with open(ip_file_path) as fh:
        string_of_ip = fh.readlines()

    pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    for line in string_of_ip:
        line = line.rstrip()
        result = re.search(pattern, line)
        if result:
            valid.append(line)
        else:
            invalid.append(line)
    return valid

# Function to perform backup for all MikroTik devices
def backup_all_mikrotik():
    hostname_list = read_ip_from_path_and_validate_ip(mikrotik_ip_file)
    for hostname in hostname_list:
        try:
            ssh_client = create_ssh_connection(hostname, mikrotik_username, key_filename,mikrotik_password)
            backup_router_config(ssh_client, hostname)
            send_file_to_github(hostname, github_token, repository_name)
            remove_backup_on_mikrotik(ssh_client, hostname)
            ssh_client.close()
        except paramiko.AuthenticationException:
            print("Error: Authentication failed. Check credentials.")
        except paramiko.SSHException as e:
            print("Connection error:", str(e))
        except TimeoutError as e:
            print(f"Connection timed out: {str(e)}")

def main():
    backup_all_mikrotik()
    os.remove('./id_rsa')

if __name__ == "__main__":
    main()
