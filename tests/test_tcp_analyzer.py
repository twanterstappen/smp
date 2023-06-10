import pytest
from tcp_analyzer import TcpConnectionAnalyzer
import json
from colorama import init


dataset = '../dataset.json'

# Testing different inputs and different errors
@pytest.mark.parametrize("file_path, expected_exception", [
    ('not_found.json', FileNotFoundError),
    ('test.txt', json.JSONDecodeError),
])
# Negative test
def test_load_data_negative(file_path, expected_exception):
    analyzer = TcpConnectionAnalyzer(file_path)
    with pytest.raises(expected_exception):
        analyzer.load_data()

# Positive test
# Check for output type of function extract_data
def test_extract_data():
    analyzer = TcpConnectionAnalyzer(dataset)
    analyzer.extract_data()
    assert type(analyzer.packages) == list
    
# Test function counting connection status
########################################################################################################################
def test_count_connection_status_positive():
    # Calling the class and necessary functions
    analyzer = TcpConnectionAnalyzer(dataset)
    analyzer.extract_data()
    analyzer.find_connection()
    analyzer.count_connection_status()
    
    assert type(analyzer.status_count) == dict
    
# Testing output of display count connection
def test_display_count_connection_status_positive(capfd):
    # Initialize colorama, for ANSI escape sequences for the terminal output
    init()
    expected_output = (
        "Total connections: 221\n"
        "    closed: 84\n"
        "    no-fin: 85\n"
        "    failed-handshake: 52\n"
    )
    
    # Calling the class and necessary functions
    analyzer = TcpConnectionAnalyzer(dataset)
    analyzer.extract_data()
    analyzer.find_connection()
    analyzer.count_connection_status()
    analyzer.display_count_connection_status()
    # Capture the print output
    captured = capfd.readouterr()

    actual_output = captured.out.strip()
    assert actual_output == expected_output.strip()
    