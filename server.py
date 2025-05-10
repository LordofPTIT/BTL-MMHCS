import socket
import threading
import json
import os
import logging
from datetime import datetime
import time

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(threadName)s - %(filename)s:%(lineno)d - %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

HOST = '127.0.0.1'
PORT = 65432
BUFFER_SIZE = 8192
MAX_FILE_SIZE = 50 * 1024 * 1024

clients = {}
client_lock = threading.Lock()


def broadcast_user_list():
    with client_lock:
        current_users = list(clients.keys())
        connections_to_broadcast = [client_info['conn'] for client_info in clients.values() if client_info.get('conn')]

    logging.info(f"Preparing to broadcast user list: {current_users} to {len(connections_to_broadcast)} clients.")
    if not current_users and not connections_to_broadcast:
        logging.info("No users or connections to broadcast to.")
        return

    user_list_payload = json.dumps({"type": "user_list", "users": current_users}).encode('utf-8')

    for conn in connections_to_broadcast:
        try:
            conn.sendall(user_list_payload)
        except socket.error as e:
            logging.error(f"Error sending user list to a client: {e}. Client might have disconnected.")
        except Exception as e:
            logging.error(f"Unexpected error sending user list to a client: {e}")


def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    username = None
    temp_client_info = {'conn': conn, 'addr': addr}

    try:
        registered_username = None
        registration_attempts = 0
        max_registration_attempts = 3

        while registered_username is None and registration_attempts < max_registration_attempts:
            registration_attempts += 1
            conn.settimeout(60.0)
            reg_data_raw = conn.recv(BUFFER_SIZE)
            conn.settimeout(None)

            if not reg_data_raw:
                logging.warning(f"Client {addr} disconnected before registration (received empty data).")
                return

            reg_data_str = reg_data_raw.decode('utf-8', errors='ignore')
            logging.debug(f"Registration data received from {addr}: {reg_data_str}")

            try:
                payload = json.loads(reg_data_str)
            except json.JSONDecodeError:
                logging.error(f"Invalid JSON registration data from {addr}: {reg_data_str}")
                try:
                    conn.sendall(json.dumps({"type": "register_ack", "status": "error",
                                             "message": "Invalid registration format. JSON expected."}).encode('utf-8'))
                except socket.error:
                    pass
                continue

            if payload.get("type") == "register":
                temp_username_candidate = payload.get("username")

                if not temp_username_candidate or not isinstance(temp_username_candidate,
                                                                 str) or " " in temp_username_candidate:
                    error_msg = "Username cannot be empty, must be a string, and cannot contain spaces."
                    try:
                        conn.sendall(
                            json.dumps({"type": "register_ack", "status": "error", "message": error_msg}).encode(
                                'utf-8'))
                    except socket.error:
                        pass
                    logging.warning(f"Registration failed for {addr}: {error_msg}")
                    continue

                with client_lock:
                    if temp_username_candidate not in clients:
                        username = temp_username_candidate
                        clients[username] = temp_client_info
                        registered_username = username
                        logging.info(f"Client {addr} registered as: {username}")
                        try:
                            conn.sendall(json.dumps({"type": "register_ack", "status": "success",
                                                     "message": f"Successfully registered as {username}."}).encode(
                                'utf-8'))
                        except socket.error as e:
                            logging.error(f"Failed to send registration ACK to {username}: {e}")
                            if username in clients:
                                del clients[username]
                            username = None
                            registered_username = None
                            return
                        break
                    else:
                        error_msg = f"Username '{temp_username_candidate}' already taken."
                        try:
                            conn.sendall(
                                json.dumps({"type": "register_ack", "status": "error", "message": error_msg}).encode(
                                    'utf-8'))
                        except socket.error:
                            pass
                        logging.warning(
                            f"Registration failed for {addr} with username '{temp_username_candidate}': {error_msg}")
            else:
                logging.warning(f"Invalid registration request type from {addr}: {payload.get('type')}")
                try:
                    conn.sendall(json.dumps(
                        {"type": "error", "message": "Invalid registration request. 'register' type expected."}).encode(
                        'utf-8'))
                except socket.error:
                    pass

        if not registered_username:
            logging.warning(
                f"Client {addr} failed to register after {max_registration_attempts} attempts or other issue.")
            return

        broadcast_user_list()

        active_buffer = b""
        expecting_file_payload_for = None

        while True:
            try:
                if expecting_file_payload_for:
                    file_info = expecting_file_payload_for
                    temp_filename_on_server = file_info['temp_path']
                    file_size = file_info['total_size']
                    bytes_to_receive_now = min(BUFFER_SIZE, file_size - file_info['bytes_received'])

                    if bytes_to_receive_now <= 0:  # Should be caught by previous check, but as safeguard
                        logging.info(
                            f"File {file_info['filename']} already fully received based on bytes_to_receive_now calculation.")
                        # Proceed to forwarding, this state indicates it should have been processed
                        # This might happen if the previous chunk exactly completed the file
                        # and this is the next iteration of the loop.
                        # The actual forwarding logic is below.
                        # For safety, we will re-trigger the forwarding logic if it's truly complete.
                        if file_info['bytes_received'] >= file_size:
                            # Fall through to the forwarding logic block
                            pass  # Let the logic below handle it
                        else:  # Should not happen if bytes_to_receive_now is <=0
                            logging.error(f"Logical error in file receive loop for {file_info['filename']}")
                            if os.path.exists(temp_filename_on_server):
                                try:
                                    os.remove(temp_filename_on_server)
                                except OSError:
                                    pass
                            expecting_file_payload_for = None
                            continue

                    conn.settimeout(60.0)
                    chunk = conn.recv(bytes_to_receive_now)
                    conn.settimeout(None)

                    if not chunk:
                        logging.error(f"Sender {username} disconnected while uploading {file_info['filename']}.")
                        with client_lock:
                            recipient_info_on_disconnect = clients.get(file_info['recipient'])
                            if recipient_info_on_disconnect:
                                try:
                                    recipient_info_on_disconnect['conn'].sendall(json.dumps(
                                        {"type": "file_transfer_failed", "sender": username,
                                         "filename": file_info['filename_original_for_user'],
                                         "reason": "Sender disconnected during upload."}).encode('utf-8'))
                                except socket.error:
                                    pass
                        if os.path.exists(temp_filename_on_server):
                            try:
                                os.remove(temp_filename_on_server)
                            except OSError:
                                pass
                        expecting_file_payload_for = None
                        break

                    with open(temp_filename_on_server, 'ab') as f:
                        f.write(chunk)

                    file_info['bytes_received'] += len(chunk)

                    if file_info['bytes_received'] >= file_size:
                        logging.info(
                            f"Fully received file '{file_info['filename_on_server']}' ({file_size} bytes) from {username}. Stored at {temp_filename_on_server}")

                        recipient_conn_for_fwd = None
                        with client_lock:
                            recipient_info_for_fwd = clients.get(file_info['recipient'])
                            if recipient_info_for_fwd:
                                recipient_conn_for_fwd = recipient_info_for_fwd['conn']

                        if recipient_conn_for_fwd:
                            try:
                                recipient_conn_for_fwd.sendall(json.dumps({
                                    "type": "file_chunk_stream_start",
                                    "sender": username,
                                    "filename": file_info['filename_on_server'],
                                    "file_size": file_size
                                }).encode('utf-8'))
                                logging.info(
                                    f"Sent file_chunk_stream_start for {file_info['filename_on_server']} to {file_info['recipient']}")

                                with open(temp_filename_on_server, 'rb') as f_send_payload:
                                    while True:
                                        chunk_to_send_to_rec = f_send_payload.read(BUFFER_SIZE)
                                        if not chunk_to_send_to_rec:
                                            break
                                        recipient_conn_for_fwd.sendall(chunk_to_send_to_rec)
                                logging.info(
                                    f"Finished sending file payload '{file_info['filename_on_server']}' to {file_info['recipient']}")

                                try:
                                    conn.sendall(json.dumps(
                                        {"type": "file_sent_ack", "recipient": file_info['recipient'],
                                         "filename": file_info['filename_on_server'],
                                         "message": f"File '{file_info['filename_on_server']}' has been forwarded to {file_info['recipient']}."}).encode(
                                        'utf-8'))
                                except socket.error:
                                    logging.warning(
                                        f"Failed to send file_sent_ack to sender {username} for file {file_info['filename_on_server']}")

                                try:
                                    recipient_conn_for_fwd.sendall(json.dumps(
                                        {"type": "file_fully_received_by_recipient",
                                         "filename": file_info['filename_original_for_user'],
                                         "sender": username}).encode('utf-8'))
                                except socket.error:
                                    logging.warning(
                                        f"Failed to send file_fully_received_by_recipient to {file_info['recipient']} for file {file_info['filename_original_for_user']}")

                            except socket.error as e_send_payload_to_rec:
                                logging.error(
                                    f"Error sending file {file_info['filename_on_server']} to {file_info['recipient']}: {e_send_payload_to_rec}")
                                try:
                                    conn.sendall(json.dumps(
                                        {"type": "file_transfer_failed", "sender": username,
                                         "filename": file_info['filename_original_for_user'],
                                         "recipient": file_info['recipient'],
                                         "reason": f"Failed to deliver file to {file_info['recipient']} (socket error)."}).encode(
                                        'utf-8'))
                                except socket.error:
                                    pass
                        else:
                            logging.warning(
                                f"Recipient {file_info['recipient']} for file {file_info['filename_on_server']} is no longer online during forwarding.")
                            try:
                                conn.sendall(json.dumps(
                                    {"type": "file_transfer_failed", "sender": username,
                                     "filename": file_info['filename_original_for_user'],
                                     "recipient": file_info['recipient'],
                                     "reason": f"Recipient {file_info['recipient']} went offline."}).encode('utf-8'))
                            except socket.error:
                                pass

                        if os.path.exists(temp_filename_on_server):
                            try:
                                os.remove(temp_filename_on_server)
                            except OSError as e_rem:
                                logging.error(f"Error removing server temp file {temp_filename_on_server}: {e_rem}")
                        expecting_file_payload_for = None
                    continue

                conn.settimeout(None)
                data = conn.recv(BUFFER_SIZE)
                if not data:
                    logging.info(f"Client {username} ({addr}) disconnected (EOF).")
                    break

                active_buffer += data
                while True:
                    message_str_decoded = None
                    remaining_buffer_after_extract = active_buffer

                    try:
                        decoded_buffer_for_search = active_buffer.decode('utf-8', errors='surrogatepass')
                        json_end_idx = -1
                        open_braces_count = 0
                        in_string_flag = False
                        escape_next_char = False
                        json_started_flag = False
                        first_brace_at = -1

                        for i, char_val_loop in enumerate(decoded_buffer_for_search):
                            if not json_started_flag:
                                if char_val_loop == '{':
                                    json_started_flag = True
                                    open_braces_count = 1
                                    if first_brace_at == -1: first_brace_at = i
                                continue

                            if first_brace_at == -1: continue  # Should not happen if json_started_flag is true

                            if escape_next_char:
                                escape_next_char = False
                                continue
                            if char_val_loop == '\\':
                                escape_next_char = True
                                continue
                            if char_val_loop == '"':
                                in_string_flag = not in_string_flag

                            if not in_string_flag:
                                if char_val_loop == '{':
                                    open_braces_count += 1
                                elif char_val_loop == '}':
                                    open_braces_count -= 1
                                    if open_braces_count == 0:
                                        json_end_idx = i + 1
                                        break

                        if first_brace_at != -1 and json_end_idx != -1:
                            actual_json_bytes = active_buffer[first_brace_at: first_brace_at + json_end_idx]
                            message_str_decoded = actual_json_bytes.decode('utf-8')
                            remaining_buffer_after_extract = active_buffer[first_brace_at + json_end_idx:]
                        else:
                            break

                        message = json.loads(message_str_decoded)
                        active_buffer = remaining_buffer_after_extract

                        logging.info(
                            f"Received from {username}: type={message.get('type')}, "
                            f"recipient={message.get('recipient')}, "
                            f"filename={message.get('filename')}, "
                            f"original_filename={message.get('original_filename')}"
                        )

                        msg_type = message.get("type")

                        if msg_type == "file_transfer_request":
                            recipient_user = message.get("recipient")
                            filename_on_server_from_req = message.get("filename")
                            file_size_from_client = message.get("file_size")
                            original_filename_for_user = message.get("original_filename",
                                                                     filename_on_server_from_req.replace(".gpg",
                                                                                                         "") if filename_on_server_from_req.endswith(
                                                                         ".gpg") else filename_on_server_from_req)

                            if not (recipient_user and filename_on_server_from_req and isinstance(file_size_from_client,
                                                                                                  int) and file_size_from_client > 0):
                                logging.warning(
                                    f"Invalid file_transfer_request from {username}: missing fields or invalid size.")
                                try:
                                    conn.sendall(json.dumps({"type": "error",
                                                             "message": "Invalid file_transfer_request format or file size."}).encode(
                                        'utf-8'))
                                except socket.error:
                                    pass
                                continue

                            if file_size_from_client > MAX_FILE_SIZE:
                                error_msg = f"File too large (max {MAX_FILE_SIZE // (1024 * 1024)}MB)"
                                logging.warning(
                                    f"File '{filename_on_server_from_req}' from {username} too large: {file_size_from_client} bytes.")
                                try:
                                    conn.sendall(json.dumps({"type": "error", "message": error_msg}).encode('utf-8'))
                                except socket.error:
                                    pass
                                continue

                            recipient_conn_req = None
                            with client_lock:
                                recipient_info_req = clients.get(recipient_user)
                                if recipient_info_req:
                                    recipient_conn_req = recipient_info_req['conn']

                            if recipient_conn_req:
                                logging.info(
                                    f"Processing file request '{filename_on_server_from_req}' from {username} to {recipient_user}")

                                try:
                                    recipient_conn_req.sendall(json.dumps({
                                        "type": "incoming_file_notification",
                                        "sender": username,
                                        "filename": filename_on_server_from_req,
                                        "file_size": file_size_from_client
                                    }).encode('utf-8'))
                                except socket.error:
                                    logging.error(f"Failed to send incoming_file_notification to {recipient_user}")
                                    try:
                                        conn.sendall(json.dumps({"type": "error",
                                                                 "message": f"Recipient {recipient_user} is not reachable for notification."}).encode(
                                            'utf-8'))
                                    except socket.error:
                                        pass
                                    continue

                                try:
                                    conn.sendall(json.dumps(
                                        {"type": "proceed_with_file_upload", "recipient": recipient_user,
                                         "filename": filename_on_server_from_req}).encode('utf-8'))
                                except socket.error:
                                    logging.error(f"Failed to send proceed_with_file_upload to {username}")
                                    continue

                                server_temp_dir = "server_temp_files"
                                if not os.path.exists(server_temp_dir):
                                    os.makedirs(server_temp_dir)

                                temp_path_on_server = os.path.join(server_temp_dir,
                                                                   f"upl_{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{os.path.basename(filename_on_server_from_req)}")

                                expecting_file_payload_for = {
                                    'filename_on_server': filename_on_server_from_req,
                                    'filename_original_for_user': original_filename_for_user,
                                    'total_size': file_size_from_client,
                                    'bytes_received': 0,
                                    'recipient': recipient_user,
                                    'temp_path': temp_path_on_server
                                }
                                open(temp_path_on_server, 'wb').close()
                                logging.info(
                                    f"Server is now expecting file payload for {filename_on_server_from_req} from {username} to be stored at {temp_path_on_server}")

                            else:
                                error_msg = f"Recipient '{recipient_user}' not online or does not exist for file transfer."
                                logging.warning(error_msg)
                                try:
                                    conn.sendall(json.dumps({"type": "error", "message": error_msg}).encode('utf-8'))
                                except socket.error:
                                    pass

                        elif msg_type == "text_message":
                            recipient_text = message.get("recipient")
                            encrypted_content_text = message.get("content")
                            original_text_preview = message.get("original_text_preview", "N/A")

                            if not (recipient_text and encrypted_content_text):
                                logging.warning(f"Invalid text_message from {username}: missing recipient or content.")
                                continue

                            logging.info(
                                f"Forwarding encrypted text message from {username} to {recipient_text} (preview: {original_text_preview})")

                            recipient_conn_for_text = None
                            with client_lock:
                                recipient_info_for_text = clients.get(recipient_text)
                                if recipient_info_for_text:
                                    recipient_conn_for_text = recipient_info_for_text['conn']

                            if recipient_conn_for_text:
                                try:
                                    recipient_conn_for_text.sendall(json.dumps({
                                        "type": "incoming_text",
                                        "sender": username,
                                        "content": encrypted_content_text
                                    }).encode('utf-8'))
                                    try:
                                        conn.sendall(json.dumps({"type": "message_sent_ack",
                                                                 "recipient": recipient_text,
                                                                 "original_text_preview": original_text_preview}).encode(
                                            'utf-8'))
                                    except socket.error:
                                        pass
                                except socket.error as e_text_fwd:
                                    logging.error(f"Failed to send text message to {recipient_text}: {e_text_fwd}")
                                    try:
                                        conn.sendall(json.dumps({"type": "error",
                                                                 "message": f"Failed to deliver message to {recipient_text}."}).encode(
                                            'utf-8'))
                                    except socket.error:
                                        pass
                            else:
                                error_msg_text = f"Recipient '{recipient_text}' not online for text message."
                                logging.warning(error_msg_text)
                                try:
                                    conn.sendall(
                                        json.dumps({"type": "error", "message": error_msg_text}).encode('utf-8'))
                                except socket.error:
                                    pass
                        else:
                            logging.warning(f"Unknown message type from {username}: {msg_type}")
                            try:
                                conn.sendall(
                                    json.dumps({"type": "error",
                                                "message": f"Unknown message type received: {msg_type}"}).encode(
                                        'utf-8'))
                            except socket.error:
                                pass

                    except json.JSONDecodeError:
                        logging.error(
                            f"Invalid JSON data in active_buffer from {username} ({addr}): {active_buffer.decode('utf-8', errors='ignore')}")
                        active_buffer = b""
                        break
                    except UnicodeDecodeError as ude:
                        logging.error(
                            f"Unicode decode error in active_buffer from {username} ({addr}). Buffer: {active_buffer[:200]}. Error: {ude}")
                        active_buffer = b""
                        break

            except socket.timeout:
                if expecting_file_payload_for:
                    logging.warning(
                        f"Socket timeout for client {username} ({addr}) while receiving file chunk for {expecting_file_payload_for.get('filename_on_server')}. Client might be unresponsive.")
                else:
                    logging.warning(f"Socket timeout for client {username} ({addr}) while waiting for main command.")
                continue
            except ConnectionResetError:
                logging.warning(f"Client {username} ({addr}) reset the connection.")
                if expecting_file_payload_for and os.path.exists(expecting_file_payload_for['temp_path']):
                    try:
                        os.remove(expecting_file_payload_for['temp_path'])
                    except OSError:
                        pass
                break
            except Exception as e_main_loop:
                logging.error(f"Error handling client {username} ({addr}) in main loop: {e_main_loop}", exc_info=True)
                if expecting_file_payload_for and os.path.exists(expecting_file_payload_for['temp_path']):
                    try:
                        os.remove(expecting_file_payload_for['temp_path'])
                    except OSError:
                        pass
                try:
                    conn.sendall(
                        json.dumps({"type": "error", "message": "Server error processing your request."}).encode(
                            'utf-8'))
                except Exception:
                    pass
                break

    except ConnectionResetError:
        logging.warning(
            f"Client {addr} (username: {username or 'not yet registered'}) reset connection abruptly (outer scope).")
    except socket.timeout:
        logging.warning(
            f"Client {addr} (username: {username or 'not yet registered'}) timed out during initial phase (outer scope).")
    except Exception as e_global:
        logging.error(f"Critical error with client {addr} (username: {username or 'not yet registered'}): {e_global}",
                      exc_info=True)
    finally:
        logging.info(f"Cleaning up client: username='{username}', addr={addr}")
        if expecting_file_payload_for and expecting_file_payload_for.get('temp_path') and os.path.exists(
                expecting_file_payload_for['temp_path']):
            logging.info(f"Removing leftover temp file during cleanup: {expecting_file_payload_for['temp_path']}")
            try:
                os.remove(expecting_file_payload_for['temp_path'])
            except OSError as e_final_remove:
                logging.error(
                    f"Error removing leftover temp file {expecting_file_payload_for['temp_path']}: {e_final_remove}")

        removed_from_dict_finally = False
        if username:
            with client_lock:
                if username in clients and clients[username]['conn'] == temp_client_info['conn']:
                    del clients[username]
                    removed_from_dict_finally = True
            if removed_from_dict_finally:
                logging.info(f"Client {username} ({addr}) removed from active clients.")
                broadcast_user_list()
            else:
                logging.info(
                    f"Client {username} ({addr}) may have already been removed or reconnected with a new session.")
        else:
            logging.info(f"Unregistered client from {addr} disconnected before completing registration.")

        try:
            temp_client_info['conn'].shutdown(socket.SHUT_RDWR)
        except (OSError, socket.error):
            pass
        try:
            temp_client_info['conn'].close()
        except Exception as e_close_final:
            logging.error(f"Error closing connection for {addr} in finally block: {e_close_final}")
        logging.info(f"Connection definitively closed for {addr}.")


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
    except OSError as e:
        logging.critical(f"Cannot bind server to {HOST}:{PORT}. Error: {e}. Is the port already in use?")
        return

    server_socket.listen(5)
    logging.info(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            try:
                conn, addr = server_socket.accept()
                logging.info(f"Accepted connection from {addr}")
                thread = threading.Thread(target=handle_client, args=(conn, addr), name=f"ClientThread-{addr[1]}",
                                          daemon=True)
                thread.start()
            except Exception as e_accept:
                logging.error(f"Error accepting new connection: {e_accept}")
                time.sleep(0.1)
    except KeyboardInterrupt:
        logging.info("Server shutting down due to KeyboardInterrupt...")
    except Exception as e_server_main:
        logging.critical(f"Server encountered a critical error and must stop: {e_server_main}", exc_info=True)
    finally:
        logging.info("Closing all client connections...")
        with client_lock:
            active_connections_at_shutdown = [client_data['conn'] for client_data in clients.values()]
            for conn_to_close in active_connections_at_shutdown:
                try:
                    conn_to_close.shutdown(socket.SHUT_RDWR)
                except (OSError, socket.error):
                    pass
                try:
                    conn_to_close.close()
                except Exception:
                    pass
            clients.clear()
        if server_socket:
            server_socket.close()
        logging.info("Server shut down completely.")


if __name__ == "__main__":
    server_temp_main_dir = "server_temp_files"
    if not os.path.exists(server_temp_main_dir):
        try:
            os.makedirs(server_temp_main_dir)
            logging.info(f"Created server temporary directory: {server_temp_main_dir}")
        except OSError as e_dir_main:
            logging.critical(
                f"Could not create server temporary directory '{server_temp_main_dir}': {e_dir_main}. Exiting.")
            exit(1)
    start_server()