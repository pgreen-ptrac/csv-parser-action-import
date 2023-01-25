from operator import itemgetter
from typing import Union
import yaml

import settings
log = settings.log
from input_utils import *
from auth_utils import *
from request_utils import *
from csv_parser import *


#----------Loading and Validating Input CSVs----------

def handle_load_csv_headers_mapping(path, parser):
    csv_headers_mapping = {}

    csv = handle_load_csv_data("Enter file path to the CSV mapping headers to Plextrac data types", csv_file_path=path)

    for index, header in enumerate(csv['headers']):
        key = csv['data'][0][index]
        if key in parser.get_data_mapping_ids():
            csv_headers_mapping[header] = key
            continue
        
        if key == "":
            csv_headers_mapping[header] = "no_mapping"
        else:
            if prompt_continue_anyways( f'ERR: Key <{key}> selected for header <{header}> is not an valid key'):
                csv_headers_mapping[header] = "no_mapping"
            else:
                exit()

    parser.csv_headers_mapping = csv_headers_mapping
    log.success(f'Loaded csv headers mapping')


def handle_load_csv_data_verify(path, parser):
    """
    takes a filepath to a csv, and a list of expected headers and returned the csv data if the headers match
    used as basic error checking that we have the correct csv
    """
    csv = handle_load_csv_data("Enter file path to CSV data to import", csv_file_path=path)

    if csv.get('headers') != parser.get_csv_headers():
        log.warning(f'CSV headers read from file\n{csv["headers"]}')
        log.warning(f'Expected headers\n{parser.get_csv_headers()}')
        if prompt_retry(f'Loaded {csv.get("file_path")} CSV headers don\'t match headers in Headers Mapping CSV.'):
            return handle_load_csv_data_verify("Enter file path to CSV data to import", "", parser.get_csv_headers())

    parser.csv_data = csv['data']
    log.success(f'Loaded csv data')


def handle_add_parser_id(parser_id, parser):
    """
    Checks if the given the parser ID value from the config.yaml file matches the ID of an existing
    plugin already imported in Plextrac. If the plugin exists in platform, adds this parser ID to the
    parser object.

    Prompts the user to choose a parser ID if one is not supplied in the config, or if the supplied
    value doesn't match an exisiting plugin.
    """
    parsers = []

    log.info(f'Loading parsers from instance...')
    response = request_get_tenant_parsers(auth.base_url, auth.get_auth_headers(), auth.tenant_id)
    if response.get('status') != "success":
        log.debug(response)
        log.error(f'Could not load parsers from instance. Exiting...')
        exit()

    parsers = response.get('parsers')
    log.debug(parsers)
    if len(parsers) < 1:
        log.error(f'Plextrace contains no parsers in platform. Exiting...')
        exit()

    if parser_id == "":
        parser_id, parser_name = pick_parser(parsers)
        parser.parser_id = parser_id
        return

    parser_ids = list(map(lambda x: x['id'], parsers))
    if parser_id in parser_ids:
        parser.parser_id = parser_id
        return
    
    input = prompt_user_options(f"Parser \'{parser_id}\' does not exist in platform. Do you want to pick a different parser", "Invalid option", ["y", "n"])
    if input == "y":
        parser_id, parser_name = pick_parser(parsers)
        parser.parser_id = parser_id
        return
    exit()


def pick_parser(parsers):
    """
    Display the list of parsers in the instance to the user and prompts them to pick a parser.
    Returns the parser_id of the selected parser.
    """
    log.info(f'List of Parsers in tenant {auth.tenant_id}:')
    for index, parser in enumerate(parsers):
        log.info(f'Index: {index+1}   Name: {parser.get("name")}')

    parser_index = prompt_user_list("Please enter a parser index from the list above.", "Index out of range.", len(parsers))
    parser = parsers[parser_index]
    parser_id = parser.get('id')
    parser_name = parser.get("name")
    log.debug(f'returning picked parser with parser_id {parser_id}')
    log.info(f'Selected Parser: {parser_index+1} - {parser_name}')

    return parser_id, parser_name

#----------End Loading and Validating Input CSVs----------
    

if __name__ == '__main__':
    settings.print_script_info()
    
    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()

    parser = Parser()

    # loads and validates csv data
    log.info(f'---Starting data loading---')
    csv_headers_file_path = ""
    if args.get('csv_headers_file_path') != None and args.get('csv_headers_file_path') != "":
        csv_headers_file_path = args.get('csv_headers_file_path')
        log.info(f'Using csv header file path \'{csv_headers_file_path}\' from config...')
    handle_load_csv_headers_mapping(csv_headers_file_path, parser)
    
    csv_data_file_path = ""
    if args.get('csv_data_file_path') != None and args.get('csv_data_file_path') != "":
        csv_data_file_path = args.get('csv_data_file_path')
        log.info(f'Using csv data file path \'{csv_data_file_path}\' from config...')
    handle_load_csv_data_verify(csv_data_file_path, parser)

    parser_id = ""
    if args.get('parser_id') != None and args.get('parser_id') != "":
        parser_id = args.get('parser_id')
        log.info(f'Using plugin \'{parser_id}\' from config...')
        handle_add_parser_id(parser_id, parser)

    parser.parse_data()
    parser.display_parser_results()

    log.info(f'IMPORTANT: Data will be imported into Plextrac.')
    log.info(f'Please view the log file generated from parsing to see if there were any errors.')
    log.info(f'If the data was not parsed correctly, please exit the script, fix the data, and re-run.')

    if prompt_continue_anyways(f'This will try to create {len(parser.parser_actions)} new {parser_id} parser actions. Once created parser action cannot be delete. If a parser action already exists it will be updated with the info from the CSV.'):
        parser.import_parser_actions(auth)
        log.info(f'Import Complete. Additional logs were added to {log.LOGS_FILE_PATH}')
    
    exit()
