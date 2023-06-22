import pytest
import json
from colorama import init
import os
import sys
import os.path
from random import randint

# For importing the tcp_analyzer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tcp_analyzer.tcp_analyzer import TcpConnectionAnalyzer

# Class for testing, cant have a init
class TestTcpConnectionAnalyzer:
    # Class level setup
    @classmethod
    def setup_class(cls):
        with open('test.txt', 'w') as file:
            file.write('Test file')
    # Class level teardown
    @classmethod
    def teardown_class(cls):
        os.remove("test.txt")
        
    # Method level setup, called before every test method
    def setup_method(self, method):
        self.dataset = '../dataset.json'
        self.analyzer = TcpConnectionAnalyzer(self.dataset)
        




    # Test function loading data
    ###################################################################################################################################
    
    # Positive test load_data 1
    def test_load_data_positive_1(self):
        analyzer = TcpConnectionAnalyzer(self.dataset)
        data = analyzer.load_data()    
        assert type(data) == list
        
        
    # Positive test load_data 2
    def test_load_data_positive_2(self):
        analyzer = TcpConnectionAnalyzer(self.dataset)
        data = analyzer.load_data()
        r_index = randint(0,(len(data)-1))
        
        assert 'ip.src' in data[r_index]['_source']['layers']['ip']
        
        

    # Negative test load_data 1
    def test_load_data_negative_1(self):
        analyzer = TcpConnectionAnalyzer('not_found.json')
        with pytest.raises(FileNotFoundError):
            analyzer.load_data()
            

    # Negative test load_data 2
    def test_load_data_negative_2(self):
        analyzer = TcpConnectionAnalyzer('test.txt')
        with pytest.raises(json.JSONDecodeError):
            analyzer.load_data()



    # Test function extract_data
    ###################################################################################################################################
    
    # Positive test extract_data 1
    def test_extract_data_positive_1(self):
        self.analyzer.extract_data() 
        assert type(self.analyzer.packages) == list


        
    # Positive test extract_data 2
    def test_extract_data_positive_2(self):
        keys = ['ip_src', 'ip_dst', 'flag_syn', 'flag_ack', 'flag_fin', 'ttl']
        self.analyzer.extract_data()
        # set random int
        r_index = randint(0,(len(self.analyzer.packages)-1))

        # check if keys from the packages are in the keys
        assert all(key in self.analyzer.packages[r_index] for key in keys)
    
    
    
    
    # Negative test extract_data
    def test_extract_data_negative(self):
        # Data with missing keys
        def load_data():
            return [{'_source': {'layers': {'ip': {'ip.src': '192.168.0.1','ip.ttl': 64}}}}]

        # Set the modified raw_data as the data source
        self.analyzer.load_data = load_data
        
        # Assert that a KeyError is raised when extracting data
        with pytest.raises(KeyError):
            self.analyzer.extract_data()
        
        
        
        
        
    # Test function counting connection status and display
    ###################################################################################################################################
    
    # Positive test count_connection_status 1
    def test_count_connection_status_positive_1(self):
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        self.analyzer.count_connection_status()

        assert type(self.analyzer.status_count) == dict


    
    # Positive test count_connection_status 2
    def test_count_connection_status_positive_2(self):
        keys = ['closed', 'no-fin', 'failed-handshake']
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        self.analyzer.count_connection_status()

        # check if keys from the packages are in the keys
        assert all(key in self.analyzer.status_count for key in keys)
        
        
        
    # Negative test count_connection_status
    def test_count_connection_status_negative(self):
        self.analyzer.connections = {'status': None}
        # Test for TypeError if status = None
        with pytest.raises(TypeError):
            self.analyzer.count_connection_status()
        




    # Positive test display_count_connection_status
    def test_display_count_connection_status_positive(self, capfd):
        # Initialize colorama, for color used in output of function
        init()
        expected_output = (
            "Total connections: 221\n"
            "    closed: 84\n"
            "    no-fin: 85\n"
            "    failed-handshake: 52"
        )
        
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        self.analyzer.count_connection_status()
        self.analyzer.display_count_connection_status()
        # Capture the print output
        captured = capfd.readouterr()
        # removing all the white spaces
        actual_output = captured.out.strip()
        
        assert actual_output == expected_output.strip()
        
        
        
        
        
        
        
    # Test function syn flood
    ###################################################################################################################################
    # Positive test syn_flood 1
    def test_syn_flood_positive_1(self):
        # Calling the class and necessary functions       
        connections = [
            {'ip_client': '192.168.0.1'},
            {'ip_client': '192.168.0.2'},
            {'ip_client': '192.168.0.1'},
            {'ip_client': '192.168.0.3'},
            {'ip_client': '192.168.0.1'},
        ]
        # Changing the connections
        self.analyzer.connections = connections
        # Changing minimum syn requist
        self.analyzer.syn_flood_minimum = 2
        
        self.analyzer.syn_flood()
        expected_result = {'192.168.0.1': 3}
        
        assert self.analyzer.syn_flood_counter == expected_result
    
    # Positive test syn_flood 2
    def test_syn_flood_positive_2(self):
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        # Changing the connections
        self.analyzer.connections = None
        self.analyzer.syn_flood()
        
        assert self.analyzer.syn_flood_counter == {}
            
        





    # Test function tcp hijacking and display
    ###################################################################################################################################
    # Positive test tcp_hijacking
    def test_tcp_hijacking_positive(self):
        # Create an instance of the class or mock the necessary dependencies
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        # Set the threshold
        self.analyzer.hijacking_threshold_percentage = 5

        self.analyzer.tcp_hijacking()

        expected_result_length = 19
        assert len(self.analyzer.possible_hijacking) == expected_result_length
        
    # Negative test tcp_hijacking    
    def test_tcp_hijacking_negative(self):
        # Create an instance of the class or mock the necessary dependencies
        self.analyzer.extract_data()
        # Set connections
        connections = [
            {'status': 'success', 'packages_index': [0, 1, 2]},
            {'status': 'success', 'packages_index': [3, 4, 5]},
        ]
        self.analyzer.connections = connections
        # changing the key
        self.analyzer.packages = [{'ttl': '64'}, {'ttl': 'invalid'}, {'ttl': '128'}, {'ttl': '128'}, {'ttl': '128'}, {'ttl': '128'}]
        # Expecting a Value error
        with pytest.raises(ValueError):
            self.analyzer.tcp_hijacking()