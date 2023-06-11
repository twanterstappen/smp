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
        
    # Method level setup, invoked before every test method
    def setup_method(self, method):
        self.dataset = '../dataset.json'
        self.analyzer = TcpConnectionAnalyzer(self.dataset)
        




    # Test function loading data
    ###################################################################################################################################
    
    # Positive test load_data
    def test_load_data_positive(self):
        analyzer = TcpConnectionAnalyzer(self.dataset)
        data = analyzer.load_data()
        r_index = randint(0,(len(data)-1))
        
        assert data is not None
        assert type(data) == list
        assert 'ip.src' in data[r_index]['_source']['layers']['ip']
        assert 'ip.dst' in data[r_index]['_source']['layers']['ip']
        assert 'tcp.flags.syn' in data[r_index]['_source']['layers']['tcp']['tcp.flags_tree']
        assert 'tcp.flags.ack' in data[r_index]['_source']['layers']['tcp']['tcp.flags_tree']
        assert 'tcp.flags.fin' in data[r_index]['_source']['layers']['tcp']['tcp.flags_tree']
        assert 'ip.ttl' in data[r_index]['_source']['layers']['ip']


    # Testing different inputs and different errors
    @pytest.mark.parametrize("file_path, expected_exception", 
                             [('not_found.json', FileNotFoundError), 
                              ('test.txt', json.JSONDecodeError)])
    # Negative test load_data
    def test_load_data_negative(self, file_path, expected_exception):
        analyzer = TcpConnectionAnalyzer(file_path)
        with pytest.raises(expected_exception):
            analyzer.load_data()



    # Test function extract_data
    ###################################################################################################################################
    
    # Positive test extract_data
    def test_extract_data_positive(self):
        keys = ['ip_src', 'ip_dst', 'flag_syn', 'flag_ack', 'flag_fin', 'ttl']
        self.analyzer.extract_data()
        # set random int
        r_index = randint(0,(len(self.analyzer.packages)-1))
        
        
        assert type(self.analyzer.packages) == list
        # check if keys from the packages are in the keys
        assert all(key in self.analyzer.packages[r_index] for key in keys)
                
    # Negative test extract_data
    def test_extract_data_negative(self):
        # Data with missing keys
        raw_data = [{'_source': {'layers': {'ip': {'ip.src': '192.168.0.1','ip.ttl': 64}}}},]
        
        # Set the modified raw_data as the data source
        self.analyzer.load_data = lambda: raw_data
        
        # Assert that a KeyError is raised when extracting data
        with pytest.raises(KeyError):
            self.analyzer.extract_data()
        
        
        
    """NEED TO INPROVE"""
    # Test function counting connection status
    ###################################################################################################################################
    def test_count_connection_status_positive(self):
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        self.analyzer.count_connection_status()
        assert type(self.analyzer.status_count) == dict
        
    # Testing output of display count connection
    def test_display_count_connection_status_positive(self, capfd):
        # Initialize colorama, for ANSI escape sequences for the terminal output
        init()
        expected_output = (
            "Total connections: 221\n"
            "    closed: 84\n"
            "    no-fin: 85\n"
            "    failed-handshake: 52\n"
        )
        
        # Calling the class and necessary functions
        self.analyzer.extract_data()
        self.analyzer.find_connection()
        self.analyzer.count_connection_status()
        self.analyzer.display_count_connection_status()
        # Capture the print output
        captured = capfd.readouterr()

        actual_output = captured.out.strip()
        assert actual_output == expected_output.strip()
        