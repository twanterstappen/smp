import json
from time import time
from math import sqrt, erf
import argparse
from colorama import Fore

import matplotlib.pyplot as plt



class TcpConnectionAnalyzer:
    def __init__(self, file_path: str) -> None:
        # path to dataset, dataset has to be .json
        self.file_path = file_path
        # the dataset itself
        self.packages = []
        # the different connections
        self.connections = []
        # Different statusus with there counter
        self.status_count = {}
        # The ip with the total of syn's of that ip
        self.syn_flood_counter = {}
        # All the possible hijacking from calculation
        self.possible_hijacking = {}
        # Minimum of syn request for registration for syn flood attack
        self.syn_flood_minimum = 3
        # Threshold for the standard deviation, where if a TTL value is under the threshold percentage a warning is given
        self.hijacking_threshold_percentage = 2.5
        # Setting the warning color for syn_flood, every ip with more then this int gets color red
        self.syn_flood_warning_color = 7


    # reading the data from the dataset
    def load_data(self) -> list:
        try:
            with open(self.file_path, 'r') as dataset:
                return json.load(dataset)
        except FileNotFoundError:
            print(Fore.RED + 'ERROR: File could not be found!' + Fore.WHITE)
            # Re-raise the exception
            raise
             
        except json.JSONDecodeError:
            print(Fore.RED + 'ERROR: Json module could not read content!' + Fore.WHITE)
            # Re-raise the exception
            raise
            
    def extract_data(self) -> None:
        raw_data = self.load_data()
        for item in raw_data or []:
            try:
                ip_src = item['_source']['layers']['ip']['ip.src']
                ip_dst = item['_source']['layers']['ip']['ip.dst']
                flag_syn = item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.syn']
                flag_ack = item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.ack']
                flag_fin = item['_source']['layers']['tcp']['tcp.flags_tree']['tcp.flags.fin']
                ttl = item['_source']['layers']['ip']['ip.ttl']
            except KeyError:
                print(Fore.RED + 'ERROR: Key was not found' + Fore.WHITE)
                # Re-raise the exception
                raise
            try:
                package = {'ip_src':ip_src, 'ip_dst': ip_dst, 'flag_syn':flag_syn, 'flag_ack':flag_ack, 'flag_fin':flag_fin, 'ttl': ttl}
            except NameError:
                print(Fore.RED + 'ERROR: Local variable is not defined' + Fore.WHITE)
                # Re-raise the exception
                raise
                
            self.packages.append(package)


    # Find the connections in the dataset
    def find_connection(self) -> None:
        for index, item in enumerate(self.packages) or []:
            ip_src = item['ip_src']
            ip_dst = item['ip_dst']
            flag_syn = item['flag_syn']
            flag_ack = item['flag_ack']
            if flag_syn == '1' and flag_ack == '0':
                connection = {'ip_client':ip_src, 'ip_server':ip_dst, 'status':'pending', 'packages_index':[index,]}
                # Start from the package after the syn
                self.find_ack_fin(index + 1, connection)

    

    # check for connection from the syn_ack to fin
    def find_ack_fin(self, start_index: int, connection: dict) -> None:
        handschake_syn_ack = False
        handshake_ack = False
        stop_loop = False
        # Start the loop were find_connection was
        for index in range(start_index, len(self.packages)) or []:
            item = self.packages[index]
            
            ip_src = item['ip_src']
            ip_dst = item['ip_dst']
            flag_syn = item['flag_syn']
            flag_ack = item['flag_ack']
            flag_fin = item['flag_fin']
            
            # Check for syn_ack, for establishing the handshake
            if ip_src == connection['ip_server'] and ip_dst == connection['ip_client'] and flag_syn == '1' and flag_ack == '1':                
                handschake_syn_ack = True
                connection['packages_index'].append(index)
                
            # Check for ack after the syn_ack, for establishing the handshake
            elif ip_src == connection['ip_client'] and ip_dst == connection['ip_server'] and flag_syn == '0' and flag_ack == '1':                
                handshake_ack = True
                connection['status'] = 'open'
                connection['packages_index'].append(index)
                
            # Check for syn, if there is a syn the connection wasn't opened or ended properly
            elif ip_src == connection['ip_client'] and ip_dst == connection['ip_server'] and flag_syn == '1' and flag_ack == '0':                
                # Check if the connection wasn't ended properly, otherwise the original handshake failed
                if handschake_syn_ack and handshake_ack:
                    connection['status'] = 'no-fin'
                else:
                    connection['status'] = 'failed-handshake'
                self.connections.append(connection)
                stop_loop = True
                break
            
            # Can only run if there was a syn_ack and ack
            if handschake_syn_ack and handshake_ack:
                # Register data packets from client to server
                if ip_src == connection['ip_client'] and ip_dst == connection['ip_server'] and flag_syn == '1' and flag_ack == '0' and flag_fin == '0':                
                    connection['packages_index'].append(index)
                
                # Register data packets from server to client
                elif ip_src == connection['ip_server'] and ip_dst == connection['ip_client'] and flag_syn == '0' and flag_ack == '0' and flag_fin == '0':                
                    connection['packages_index'].append(index)  
                      
                # Check if fin is from the client to the server  
                elif ip_src == connection['ip_client'] and ip_dst == connection['ip_server'] and flag_fin == '1':
                    connection['status'] = 'closed'
                    connection['packages_index'].append(index)
                    self.connections.append(connection)
                    stop_loop = True
                    break
                
                # Check if fin is from the server to the client
                elif ip_src == connection['ip_server'] and ip_dst == connection['ip_client'] and flag_fin == '1':
                    connection['status'] = 'closed'
                    connection['packages_index'].append(index)
                    self.connections.append(connection)
                    stop_loop = True
                    break
                
        # if the loop isn't stopped and there was a succesfull handshake, there can be assumed that there was no fin
        if not stop_loop and handschake_syn_ack and handshake_ack:
            connection['status'] = 'no-fin'
            self.connections.append(connection)
            
        # otherwise, there can be assumed that the handshake failed
        elif not stop_loop:
            connection['status'] = 'failed-handshake'
            self.connections.append(connection)
    
    
    def count_connection_status(self) -> None:
        status_count = {}
        # check for different statuses and counting them          
        for item in self.connections or []:
            if item['status'] not in status_count:
                status_count[item['status']] = 1
            elif item['status'] in status_count:
                status_count[item['status']] += 1
                
        self.status_count = status_count
    
    # Display the total connections and the different statuses
    def display_count_connection_status(self) -> None:
        left = []
        height = []
        statusses = list(self.status_count.keys())
        print(len(statusses))
        for index in range(1, len(statusses)+1):
            left.append(index)
        for status in statusses:
           height.append(self.status_count[status])
           
        print(statusses, height, left)
        plt.bar(left, height, tick_label = statusses,
        width = 0.8, color = ['#7874ff', '#78b4ff'])
        
        # naming the x-axis
        plt.xlabel('x - axis')
        # naming the y-axis
        plt.ylabel('y - axis')
        # plot title
        plt.title('My bar chart!')
        plt.show()
        
        total_connections = 0
        # Count for each status
        print_status_count = []
        print_connections = """"""
        
        # saving the statuses with each count as string for printing
        for item in self.status_count or []:
            print_status_count.append(f'{item}: {Fore.GREEN}{self.status_count[item]}{Fore.WHITE}')
            total_connections += self.status_count[item]
            
        # printing the total connections and different statuses with each count
        print_connections += f'\nTotal connections: {Fore.GREEN}{total_connections}{Fore.WHITE}\n'
        for i in print_status_count or []:
            print_connections += ('    ' + i + '\n')
        print(print_connections)
        
    # Counting the syn request for every IP
    def syn_flood(self) -> None:
        syn_flood_counter = {}
        # Counter for the syn request
        for item in self.connections or []:
            if item['ip_client'] not in syn_flood_counter:
                syn_flood_counter[item['ip_client']] = 1
            elif item['ip_client'] in syn_flood_counter:
                syn_flood_counter[item['ip_client']] += 1
        # Remove the ip from the dictionary if there were less then 'self.syn_flood_minimum' syn requests
        for item in list(syn_flood_counter.keys()) or []:
            if syn_flood_counter[item] < self.syn_flood_minimum:
                del syn_flood_counter[item]
        
        self.syn_flood_counter = syn_flood_counter

        
    # Display possible syn flood
    def display_syn_flood(self) -> None:
        print()
        for item in self.syn_flood_counter or []:
            # Check for 'self.syn_flood_warning_color' from what counter the syn request that the color red
            if self.syn_flood_counter[item] >= self.syn_flood_warning_color:
                print(f"IP: {item}, has {Fore.RED}{self.syn_flood_counter[item]}{Fore.WHITE} syn")
            else:
                print(f"IP: {item}, has {Fore.YELLOW}{self.syn_flood_counter[item]}{Fore.WHITE} syn")
        print()
    
    # Searching for possible hijacking with the standard deviation of the TTL
    def tcp_hijacking(self) -> None:
        for connection_index, connection in enumerate(self.connections) or []:
            ttl_values = []
            if connection['status'] != 'failed-handshake':
                # List all the TTL values from a connection
                for index, value in enumerate(connection['packages_index']) or []:
                    try:
                        ttl_values.append(int(self.packages[index]['ttl']))
                    except TypeError:
                        print(Fore.RED + 'ERROR: Wrong variable type' + Fore.WHITE)
                        # Re-raise the exception
                        raise
                    except ValueError:
                        print(Fore.RED + 'ERROR: Wrong value' + Fore.WHITE)
                        # Re-raise the exception
                        raise
                
                # Calculate the average ttl from the connection
                average_ttl = sum(ttl_values) / len(ttl_values)
                # Calculate the squared deviation
                square_deviation = [(ttl - average_ttl) ** 2 for ttl in ttl_values]
                # Calculate the average squared deviation
                average_squared_deviation = sum(square_deviation) / len(ttl_values)
                # Calculate the standard deviation
                standard_deviation = sqrt(average_squared_deviation)
                
                for ttl in ttl_values or []:
                    # Calculating the z score
                    z_score = abs((ttl - average_ttl) / standard_deviation)
                    # Calculating the percentage of the z score.
                    percentage = 100 - ((1 + erf(z_score / sqrt(2))) * 50)
                    
                    # check if percentage is under the threshold
                    if percentage < self.hijacking_threshold_percentage:
                        # Only display once for every connection
                        self.possible_hijacking[connection_index] = {'anomalous-ttl': ttl, 'deviation-percentage': percentage}
                        break
                                    
    # Display the possible Hijackings
    def display_tcp_hijacking(self) -> None:
        for item in self.possible_hijacking or []:
            print(f'\nIndex of connection: {Fore.YELLOW}{item}{Fore.WHITE}, {Fore.RED}Possible Hijacking detected!{Fore.WHITE} Anomalous TTL value: {Fore.YELLOW}{self.possible_hijacking[item]["anomalous-ttl"]}{Fore.WHITE}, Deviation percentage: {Fore.YELLOW}{self.possible_hijacking[item]["deviation-percentage"]:.2f}%{Fore.WHITE}, ip-client: {Fore.YELLOW}{self.connections[item]["ip_client"]}{Fore.WHITE}\n')
                
def main():
    # set timer for duration of the program
    start = time()
    
    # Setting the arguments
    parser = argparse.ArgumentParser(prog='SMP-Twan.py',description='Dataset TCP connection analyzer')
    parser.add_argument('file', metavar='file_name', type=str, help='Input file name')
    parser.add_argument('-C', '--connections',  dest='connections', action='store_true', help='Displaying connections in dataset, has to be json')
    parser.add_argument('-S', '--syn-flood',  dest='syn_flood_minimum', nargs='?', const=True, type=int, help='Display possible syn-flood attacks (optional: provide minimum syn request, display everything above the minimum)')
    parser.add_argument('-HI', '--hijacking',  dest='hijacking_threshold', nargs='?', const=True, type=float, help='Displaying possible TCP hijacking')
    parser.add_argument('-A', '--all',  dest='all', action='store_true', help='Displaying all functions')
    args = parser.parse_args()
    
       
    
    
    # set class to variable
    analyzer = TcpConnectionAnalyzer(args.file)
    # extract the data from the given file
    analyzer.extract_data()
    # find the connections in the dataset
    analyzer.find_connection()
    
    print('-'*60)
    # Calling functions for connection
    if args.connections or args.all:
        analyzer.count_connection_status()
        analyzer.display_count_connection_status()
        
    # Calling functions for syn_flood
    if args.syn_flood_minimum or args.all:
        # checking if a int was given
        if type(args.syn_flood_minimum) == int:
            analyzer.syn_flood_minimum = args.syn_flood_minimum
        analyzer.syn_flood()
        analyzer.display_syn_flood()
    
    # Calling functions for syn_flood
    if args.hijacking_threshold or args.all:
        # checking if a int was given
        if type(args.hijacking_threshold) == float:
            analyzer.hijacking_threshold_percentage = args.hijacking_threshold
        analyzer.tcp_hijacking()
        analyzer.display_tcp_hijacking()
    print('-'*60)

   

    # end timer and display the duration
    end = time()
    print(f"\nRuntime of the program: {(end - start):.2f} seconds")
    
if __name__ == '__main__':
    main()