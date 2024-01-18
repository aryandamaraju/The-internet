"""
File: the_internet.py
Author: Aryan Damaraju
Date: 10 December, 2021
Section: 34
Email: aryand1@umbc.edu
Description: This program creates a model of the internet.
"""

MAX_INT = 300
CMD_CREATE_SERVER = 'create-server'
CMD_CREATE_CONNECTION = 'create-connection'
CMD_SET_SERVER = 'set-server'
CMD_PING = 'ping'
CMD_TRACEROUTE = ['traceroute', 'tracert']
CMD_IP_CONFIG = 'ip-config'
CMD_DISPLAY_SERVERS = 'display-servers'
CMD_QUIT = 'quit'


def get_path_time(path, connect_time_map):
    """

    :param path: the path from source ip and destination ip
    :param connect_time_map: the dictionary which takes the time
    :return: minimum time
    """
    total_time = 0
    for i in range(1, len(path)):
        total_time += connect_time_map[(path[i - 1], path[i])]
    return total_time


def find_path(src_ip, dest_ip, connection_map, connect_time_map, current_path=[]):
    """

    :param src_ip: initial ip
    :param dest_ip: final ip
    :param connection_map: the connected servers dictionary
    :param connect_time_map: the dictionary which takes time
    :param current_path: the current path
    :return: minimum path
    """
    if src_ip == dest_ip:
        return current_path + [dest_ip]
    elif src_ip in current_path:
        return []
    else:
        min_time = MAX_INT
        min_path = None
        for connection in connection_map[src_ip]:
            path = find_path(connection, dest_ip, connection_map, connect_time_map, current_path + [src_ip])
            if path is not None and len(path) > 0:
                path_time = get_path_time(path, connect_time_map)
                if path_time < min_time:
                    min_time = path_time
                    min_path = path
        return min_path


def ping(src_ip, dest_ip, connection_map, connect_time_map):
    """

    :param src_ip: initial ip
    :param dest_ip: final ip
    :param connection_map: the connected servers dictionary
    :param connect_time_map: the dictionary which takes time
    :return: minimum path
    """
    path = find_path(src_ip, dest_ip, connection_map, connect_time_map)
    if len(path) == 0:
        return None
    else:
        ping_time = get_path_time(path, connect_time_map)
        return ping_time


def create_server(input_by_user, ip_to_name_map, name_to_ip_map):
    """

    :param input_by_user: user input
    :param ip_to_name_map: dictionary of ips
    :param name_to_ip_map: dictionary of names
    :return: dictionary of IPs and NAMEs
    """

    if len(input_by_user) == 3:
        create_server_success = True
        command, name, ip = input_by_user
        if name in name_to_ip_map:
            create_server_success = False
            print(f"Server name {name} already exists")
        else:
            val = validate_ip(input_by_user)
            if val is True:
                name_to_ip_map[name] = ip
            else:
                create_server_success = False
                print("Invalid IP.")
        if ip in ip_to_name_map:
            create_server_success = False
            print(f"Server ip {ip} already exists")
        else:
            dom_val = domain_validate(input_by_user)
            if dom_val is True:
                ip_to_name_map[ip] = name
            else:
                create_server_success = False
                print('Invalid Domain')
        if create_server_success is True:
            print(f"Success: A server with name {name} was created at ip {ip}")

    else:
        print('Invalid number of inputs. Eg: (create-server *server name* *ip address*)')
    return ip_to_name_map, name_to_ip_map


def create_connection(input_by_user, name_to_ip_map, con_map, ip_time_map, domain_time_map):
    """

    :param input_by_user: user input
    :param name_to_ip_map: dictionary of names
    :param con_map: dictionary of connections
    :param ip_time_map: the dict the time it takes ips to connect
    :param domain_time_map: the dict of the time it takes domains toconnect
    :return: name_to_ip_map, connections_map, ip_time, domain_time_map
    """
    if len(input_by_user) == 4:
        command, server_1, server_2, connect_time = input_by_user

        if server_1 == server_2:
            print(f"{server_1} cannot have a self connection")
        if server_1 not in name_to_ip_map:
            print(f"Unable to resolve server name {server_1}")
        if server_2 not in name_to_ip_map:
            print(f"Unable to resolve server name {server_2}")
        if (server_1, server_2) in ip_time_map:
            print(f"Connection {server_1} <-> {server_2} already exists")
        else:
            server_1_ip = name_to_ip_map[server_1]
            server_2_ip = name_to_ip_map[server_2]
            ip_time_map[(server_1_ip, server_2_ip)] = int(connect_time)
            ip_time_map[(server_2_ip, server_1_ip)] = int(connect_time)
            domain_time_map[(server_1, server_2)] = int(connect_time)
            domain_time_map[(server_2, server_1)] = int(connect_time)

            if server_1_ip not in con_map:
                con_map[server_1_ip] = []
            if server_2_ip not in con_map:
                con_map[server_2_ip] = []

            con_map[server_1_ip].append(server_2_ip)
            con_map[server_2_ip].append(server_1_ip)
            print(f"Success: A server with name {server_1} is now connected to {server_2}")
    return name_to_ip_map, con_map, ip_time_map, domain_time_map


def set_server(input_by_user, p_name_to_ip_map, p_ip_to_name_map, current_ip):
    """

    :param input_by_user: user input
    :param p_name_to_ip_map: dictionary of names
    :param p_ip_to_name_map: dictionary of ips
    :param current_ip: selected ip
    :return: current ip
    """

    if len(input_by_user) == 2:
        cmd, server = input_by_user
        result = domain_validate(input_by_user)
        if server not in p_name_to_ip_map and server not in p_ip_to_name_map:
            print(f"Unable to resolve server {server}")
        if result is True:
            current_ip = p_name_to_ip_map[server]
            print(f"Server {server} selected.")
        elif server in p_ip_to_name_map:
            current_ip = server
            print(f"Server {p_ip_to_name_map[server]} selected.")
    return current_ip


def find_ping(input_by_user, name_map, ip_map, con_map, time_map, curr_ip):
    """

    :param input_by_user: user input
    :param name_map: dict of domain names and their ips
    :param ip_map:  dict of ips and their domains
    :param con_map: dict of connections
    :param time_map: dict of connections and their times
    :param curr_ip: selected ip
    :return: name map, ip map, connection map, time map, current ip
    """
    if len(input_by_user) == 2:
        _, destination_server = input_by_user

        if destination_server not in name_map and destination_server not in ip_map:
            destination_ip_address = None
        elif destination_server in name_map:
            destination_ip_address = name_map[destination_server]
        else:
            destination_ip_address = destination_server

        if destination_ip_address is not None:
            ping_time = ping(curr_ip, destination_ip_address, con_map, time_map)
            if ping_time is None:
                print(f"Server {destination_ip_address} is unreachable")
            else:
                print(f"Reply from {destination_ip_address} time = {ping_time} ms")
        else:
            print(f"Unable to resolve server {destination_ip_address}")
    return name_map, ip_map, con_map, time_map, curr_ip


def trace_route(input_by_user, name_map, ip_map, curr_ip, con_map, time_map):
    """

    :param input_by_user: user input
    :param name_map: dict of domains
    :param ip_map: dict of ips
    :param curr_ip: current ip
    :param con_map: dict of connections
    :param time_map: dict of connections and their times
    :return: name map, ip map, current ip, connections map, connection time map
    """

    if len(input_by_user) == 2:
        _, dest_server = input_by_user

        if dest_server not in name_map and dest_server not in ip_map:
            dest_ip = None
        elif dest_server in name_map:
            dest_ip = name_map[dest_server]
        else:
            dest_ip = dest_server

        if dest_ip is not None:
            path = find_path(curr_ip, dest_ip, con_map, time_map)
            if path is not None and len(path) > 0:
                print(f"Tracing route to {ip_map[dest_ip]} [{dest_server}]")
                print(f"\t0\t0\t[{curr_ip}]\t\t{ip_map[curr_ip]}")
                for i in range(1, len(path)):
                    ip = path[i]
                    print(f"\t{i}\t{time_map[(path[i - 1], ip)]}\t[{ip}]\t\t{ip_map[ip]}")
                print(f"Trace complete.")
            else:
                print(f"Unable to resolve target system name {dest_server}")
        else:
            print(f"Unable to resolve server {dest_server}")
    return name_map, ip_map, curr_ip, con_map, time_map


def ip_config(input_by_user, curr_ip, ip_to_name_map):
    """

    :param input_by_user: user input
    :param curr_ip: current ip
    :param ip_to_name_map: dict of IPs
    :return: None
    """
    if len(input_by_user) == 1:
        if len(curr_ip) == 0:
            print(f"Current ip is not set")
        else:
            variable = str(curr_ip)
            print(curr_ip, "\t\t", ip_to_name_map[variable])


def display_servers(input_by_user, ip_map, con_map, time_map):
    """

    :param input_by_user: user input
    :param ip_map: Dict of IPs
    :param con_map: Dict of connections
    :param time_map: Dict of connections and their times
    :return:
    """
    if len(input_by_user) == 1:
        for server_1 in ip_map:
            print(f"\t{ip_map[server_1]}\t{server_1}")
            for server_2 in con_map.get(server_1, []):
                print(f"\t\t{ip_map[server_2]}\t{server_2}\t{time_map[(server_1, server_2)]}")
    return ip_map, con_map, time_map


def validate_ip(input_by_user):
    """

    :param input_by_user: user input
    :return: Boolean True or False
    """
    ip_ad = input_by_user[2]
    parts = ip_ad.split(".")
    result = True
    if len(parts) != 4:
        result = False
    else:
        for i in range(len(parts)):
            integer = int(parts[i])
            if integer < 0:
                result = False
            if integer > 255:
                result = False
    return result


def domain_validate(input_by_user):
    """

    :param input_by_user: user input
    :return: Boolean True or False
    """
    result = True
    list_domain_category = ["com", "net", "edu", "org"]
    dom_name = input_by_user[1]
    parts = dom_name.split(".")
    if parts[1] not in list_domain_category:
        result = False

    return result


if __name__ == '__main__':
    current_ip = None
    connect_domain_time_map = {}
    connect_ip_time_map = {}
    ip_to_name_map = {}
    name_to_ip_map = {}
    connections_map = {}
    program_running = True

    while program_running:
        user_input = input('>>> ').split(' ')

        command = user_input[0]

        if command == CMD_CREATE_SERVER:
            create_server(user_input, ip_to_name_map, name_to_ip_map)

        elif command == CMD_CREATE_CONNECTION:
            create_connection(user_input, name_to_ip_map, connections_map, connect_ip_time_map, connect_domain_time_map)

        elif command == CMD_SET_SERVER:
            curr_ip = set_server(user_input, name_to_ip_map, ip_to_name_map, current_ip)
            current_ip = curr_ip

        elif command == CMD_PING:
            find_ping(user_input, name_to_ip_map, ip_to_name_map, connections_map, connect_ip_time_map, current_ip)

        elif command in CMD_TRACEROUTE:
            trace_route(user_input, name_to_ip_map, ip_to_name_map, current_ip, connections_map, connect_ip_time_map)

        elif command == CMD_IP_CONFIG:
            ip_config(user_input, current_ip, ip_to_name_map)

        elif command == CMD_DISPLAY_SERVERS:
            display_servers(user_input, ip_to_name_map, connections_map, connect_ip_time_map)

        elif command == CMD_QUIT:
            program_running = False

        else:
            print("Invalid command. Please check the command")

