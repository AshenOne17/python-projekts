import os
import time
import paramiko

def ssh_single_command(hostname, username, password, command):
    # SSH Objekt erstellen
    ssh = paramiko.SSHClient()
    # Automatisch unbekannte Host-Keys akzeptieren (nur zum Testen)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Verbindung aufbauen
        print(f"Connecting to {hostname}...")
        ssh.connect(hostname, username=username, password=password)

        # Command ausführen (jede einzelne Command is eine Sub-Shell)
        print(f"Executing {command}...")
        stdin, stdout, stderr = ssh.exec_command(command)

        # Output lesen
        output = stdout.read()
        error = stderr.read()

        # Exit
        exit_status = stdout.channel.recv_exit_status()

        # Ergebnisse ausgeben
        if output:
            print(f"Command output: \n{output}")
        if error:
            print(f"Command error: \n{error}")

        print(f"Exit status: {exit_status}")
        return output, error, exit_status
    except Exception as e:
        print(f"Failed to execute command: {e}")
        return None, str(e), -1
    finally:
        ssh.close()

def ssh_multiple_commands(hostname_m, username_m, password_m, command_m):
    # SSH Objekt erstellen
    ssh = paramiko.SSHClient()
    # Automatisch unbekannte Host-Keys akzeptieren
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Verbindung aufbauen
        print(f"Connecting to {hostname_m}...")
        ssh.connect(hostname_m, username=username_m, password=password_m)

        # Interaktive Shell (wie Terminal) öffnen
        shell = ssh.invoke_shell()
        time.sleep(0.5)

        for i, command in enumerate(command_m):
            # Command senden
            print(f"Executing command {i+1}: {command}")
            shell.send(command + '\n')
            time.sleep(2)

            # Output anzeigen
            output = ""
            while shell.recv_ready():
                # Binär in die zeichenkette umwandeln
                output += shell.recv(1024).decode()
                time.sleep(0.1)
            print(f"Output: {output}")
    except Exception as e:
        print(f"Failed to execute command: {e}")
    finally:
        ssh.close()

def sftp_connection(hostname, username, password):
    # SSH Objekt erstellen
    ssh = paramiko.SSHClient()
    # Automatisch unbekannte Host-Keys akzeptieren
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        # Verbindung aufbauen
        print(f"Connecting to {hostname}...")
        ssh.connect(hostname, username=username, password=password)
        sftp = ssh.open_sftp()

        # Ordner erstellen
        remote_dir = "/home/admin-pi2/artem_sftp_test"
        try:
            sftp.mkdir(remote_dir)
            print(f"Folder created successfully: {remote_dir}")
        except Exception as e:
            print(f"Failed to create folder: {e}")

        # Test-Datei erstellen
        local_file = "text.txt"
        remote_file = f"{remote_dir}/uploaded_file.txt"
        with open(local_file, 'w') as f:
            f.write("Hello World! Test local_file upload with STFP!")
        ## Kopiert das Lokale Datei auf den Remote Server
        sftp.put(local_file, remote_file)
        print(f"File {local_file} uploaded as {remote_file} successfully!")

        # Ordner Inhalt auflisten
        print(f"Contents of folder {remote_dir}: ")
        for item in sftp.listdir(remote_dir):
            print(f"  - {item}")

        # Datei mit verändertem Namen herunterladen
        downloaded_file = "downloaded_file.txt"
        sftp.get(remote_file, downloaded_file)
        print(f"File {remote_file} downloaded as {downloaded_file} successfully!")

        # Datei löschen
        sftp.remove(remote_file)
        print(f"File {remote_file} removed successfully!")

        # Ordner löschen
        sftp.rmdir(remote_dir)
        print(f"Folder {remote_dir} removed successfully!")

        # Lokale Datei und Ordner löschen
        os.remove(local_file)
        os.remove(downloaded_file)
    except Exception as e:
        print(f"STFP Error: {e}")
    finally:
        sftp.close()
        ssh.close()

ssh_single_command("10.16.0.12", "admin-pi2", "admin@pi2", "systemctl status apache2.service")
# ssh_multiple_commands("10.16.0.12", "admin-pi2", "admin@pi2", ["cd /var/www", "ls -la"])
# sftp_connection("10.16.0.12", "admin-pi2", "admin@pi2")