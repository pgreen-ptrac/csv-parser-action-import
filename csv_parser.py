import time
import csv
from uuid import uuid4
from copy import copy, deepcopy
import logging
import re

import general_utils as utils
from input_utils import *

class Parser():
    
    # list of locations to store data in Plextrac and how to access that location
    data_mapping = {
        'no_mapping': {
            'id': 'no_mapping',
            'object_type': 'IGNORE',
            'data_type' : 'IGNORE',
            'validation_type': None,
            'input_blanks': False,
            'path': []
        },
        # FINDING INFO
        # 'finding_assigned_to': {
        #     'id': 'finding_assigned_to',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['assignedTo'] # document email
        # },
        # 'finding_created_at': {
        #     'id': 'finding_created_at',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': "DATE_EPOCH",
        #     'input_blanks': False,
        #     'path': ['createdAt'] # validate
        # },
        # 'finding_closed_at': {
        #     'id': 'finding_closed_at',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': "DATE_EPOCH",
        #     'input_blanks': False,
        #     'path': ['closedAt'] # validate
        # },
        # 'finding_description': {
        #     'id': 'finding_description',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['description']
        # },
        # 'finding_recommendations': {
        #     'id': 'finding_recommendations',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['recommendations']
        # },
        # 'finding_references': {
        #     'id': 'finding_references',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['references']
        # },
        # 'finding_severity': {
        #     'id': 'finding_severity',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': "SEVERITY",
        #     'input_blanks': False,
        #     'path': ['severity'] # validate
        # },
        # 'finding_status': {
        #     'id': 'finding_status',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': "STATUS",
        #     'input_blanks': False,
        #     'path': ['status'] # validate
        # },
        # 'finding_sub_status': {
        #     'id': 'finding_sub_status',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['subStatus']
        # },
        # 'finding_tag': {
        #     'id': 'finding_tag',
        #     'object_type': 'FINDING',
        #     'data_type' : 'TAG',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['tags']
        # },
        # 'finding_multi_tag': {
        #     'id': 'finding_multi_tag',
        #     'object_type': 'FINDING',
        #     'data_type' : 'MULTI_TAG',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['tags']
        # },
        # 'finding_title': {
        #     'id': 'finding_title',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['title']
        # },
        # 'finding_custom_field': {
        #     'id': 'finding_custom_field',
        #     'object_type': 'FINDING',
        #     'data_type' : 'KEY_CUSTOM_FIELD',
        #     'validation_type': None,
        #     'input_blanks': True,
        #     'path': ['fields']
        # },
        # 'finding_cvss3_1_overall': {
        #     'id': 'finding_cvss3_1_overall',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': 'FLOAT', # validate
        #     'input_blanks': False,
        #     'path': ['risk_score', 'CVSS3_1', 'overall']
        # },
        # 'finding_cvss3_1_vector': {
        #     'id': 'finding_cvss3_1_vector',
        #     'object_type': 'FINDING',
        #     'data_type' : 'DETAIL',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['risk_score', 'CVSS3_1', 'vector']
        # },
        # 'finding_cve': {
        #     'id': 'finding_cve_name',
        #     'object_type': 'FINDING',
        #     'data_type' : 'CVE',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['common_identifiers', 'CVE', 'INDEX'] # document CVE-2022-12345
        # },
        # 'finding_cwe': {
        #     'id': 'finding_cwe_name',
        #     'object_type': 'FINDING',
        #     'data_type' : 'CWE',
        #     'validation_type': None,
        #     'input_blanks': False,
        #     'path': ['common_identifiers', 'CWE', 'INDEX'] # document number i.e. 501
        # },
        # PARSER ACTION INFO
        'parser_action_id': {
            'id': 'parser_action_id',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': None,
            'input_blanks': False, #TODO probably can't be blank, might need to make one up or skip
            'path': ['id']
        },
        'parser_action_action': {
            'id': 'parser_action_action',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': 'PARSER_ACTION', # validate
            'input_blanks': False,
            'path': ['action']
        },
        'parser_action_title': {
            'id': 'parser_action_title',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': None,
            'input_blanks': False, #TODO can't be blank, probably skip - probably handle before this gets called
            'path': ['title']
        },
        'parser_action_severity': {
            'id': 'parser_action_severity',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': 'SEVERITY', # validate
            'input_blanks': False,
            'path': ['severity']
        },
        'parser_action_description': {
            'id': 'parser_action_description',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': None,
            'input_blanks': False,
            'path': ['description']
        },
        'parser_action_writeup_id': { #TODO not implemented - need to see how it relates to object - check if existing writeup gets linked by providing writeup_id
            'id': 'parser_action_writeup_id',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': None,
            'input_blanks': False,
            'path': ['writeupID']
        },
        'parser_action_writeup_label': { #TODO not implemented - need to see how it relates to object
            'id': 'parser_action_writeup_label',
            'object_type': 'PARSER_ACTION',
            'data_type' : 'DETAIL',
            'validation_type': None,
            'input_blanks': False,
            'path': ['writeupLabel']
        }
    }
    #--- END CSV---


    #--- FINDING - template of finding object - list of findings generated while running the script---

    # you can add data here that should be added to all findings
    finding_template = { # need all arrays build out to prevent KEY ERR when adding data
        'sid': None,
        'client_sid': None,
        'report_sid': None,
        'affected_asset_sid': None,
        'title': None,
        'severity': "Informational",
        'status': "Open",
        'description': "",
        'recommendations': "",
        'references': "",
        'fields': {},
        'risk_score': {
            'CVSS3_1': {
                'overall': 0,
                'vector': ""
            }
        },
        'common_identifiers': {
            "CVE": [],
            "CWE": []
        },
        'tags': ["custom_csv_import"],
        'affected_assets': {},
        'assets': []
    }

    findings = {}
    #--- END FINDING---


    #--- PARSER ACTION - template of parser action object - list of parser actions generated while running the script---

    # you can add data here that should be added to all assets
    parser_action_template = { # need all arrays build out to prevent KEY ERR when adding data
        'sid': None,
        'id': None,
        'action': "DEFAULT",
        'title': None,
        'severity': "Informational",
        'description': "",
        'writeupID': "",
        'writeupLabel': ""
    }

    parser_actions = {}
    #--- END Parser ACtion---


    def __init__(self):
        """
        
        """
        self.csv_headers_mapping = None
        self.csv_data = None
        self.parser_id = None
        self.logging_data = None
        self.parser_progess = None
        self.parser_date = time.strftime("%m/%d/%Y", time.localtime(time.time()))
        self.parser_time = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime(time.time()))

        self.client_template['name'] = f'Custom CSV Import {self.parser_date}'
        self.report_template['name'] = f'Custom CSV Import Report {self.parser_date}'

        # csv logging
        # self.CSV_LOGS_FILE_PATH = f'parser_logs_{self.parser_time}.csv'


    #----------getters and setter----------
    def get_data_mapping_ids(self):
        return list(self.data_mapping.keys())
    
    def get_csv_headers(self):
        """
        Returns the list of expected based on the csv_header value in the tracker array containing data mapping info.
        """
        return list(self.csv_headers_mapping.keys())

    def get_headers_by_data_type(self, data_type):
        type_mappings = list(map(lambda x: x['id'], list((filter(lambda x: (x['data_type'] == data_type), self.data_mapping.values()))) ))
        log.debug(type(type_mappings))
        log.debug(type_mappings)
        # mapped_headers = filter(lambda header, id: (id in type_mappings), self.csv_headers_mapping.items())
        # log.debug(type(mapped_headers))
        # log.debug(mapped_headers)


    def get_key_from_header(self, header):
        return self.csv_headers_mapping.get(header)

    # only returns the first instance of the key. will not get expected return if a generic key is used i.e. finding_custom_field
    def get_header_from_key(self, key):
        for header, id in self.csv_headers_mapping.items():
            if key == id:
                return header
        return None
    #----------End getters and setter----------

    
    def display_parser_results(self):
        log.success(f'CSV parsing completed!') # Successfully imported {self.log_messages["SUCCESS"]["num"]}/{len(self.csv_data)} findings.\n')
        
        # for log in self.log_messages.values():
        #     if log['num'] > 0:

        #         log.info(f'{log["num"]} {log["message"]}.')

        log.info(f'Detailed logs can be found in \'{log.LOGS_FILE_PATH}\'')


    #----------Post parsing handling functions----------
    def handle_finding_dup_names(self):
        """
        Runs through all findings and updates the titles for any duplicates.
        Cannot be done during parsing since we still have to look for duplicates there
        """
        for f in self.findings.values():
            if f['dup_num'] > 1:
                f['title'] = f'{f["title"]} ({f["dup_num"]})'
            f.pop("dup_num")
    #----------End post parsing handling functions----------


    #----------Object Handling----------
    # def handle_finding(self, row, client_sid, report_sid):
    #     """
    #     Returns a finding sid and name based the csv columns specified that relate to finding data.

    #     Looks through list of findings already created during this running instance of the script for the given client and report
    #     Determines if a finding has a duplicate and needs a different finding title

    #     Creates new finding and adds all csv column data that relates to the finding

    #     Returns the finding sid and name of the new finding
    #     """
    #     matching_findings = list(self.findings.values())
    #     matching_findings = filter(lambda x: (x['client_sid'] == client_sid), matching_findings)
    #     matching_findings = filter(lambda x: (x['report_sid'] == report_sid), matching_findings)

    #     # filter for matching findings by title
    #     header = self.get_header_from_key('finding_title')

    #     index = list(self.csv_headers_mapping.keys()).index(header)
    #     value = row[index]

    #     matching_findings = list(filter(lambda x: (value == x['title']), matching_findings))

    #     # return new finding
    #     new_sid = uuid4()
    #     finding = deepcopy(self.finding_template)
    #     finding['sid'] = new_sid
    #     finding['client_sid'] = client_sid
    #     finding['report_sid'] = report_sid
    #     finding['dup_num'] = len(matching_findings) + 1

    #     self.add_data_to_object(finding, "FINDING", row)

    #     self.findings[new_sid] = finding
    #     self.reports[report_sid]['findings'].append(new_sid)

    #     return new_sid, finding['title']


    def handle_parser_action(self, row):
        """
        Returns a parser action sid and parser action id based the csv columns specified that relate to parser action data.

        Looks through list of parser actions already created during this running instance of the script
        Determines if a parser action has a duplicate and needs a different handling

        Creates new parser action and adds all csv column data that relates to the parser action

        Returns the parser action sid and parser action id of the new parser action
        """
        matching_parser_actions = list(self.parser_actions.values())

        # filter for matching parser actions
        header = self.get_header_from_key("parser_action_id")

        index = list(self.csv_headers_mapping.keys()).index(header)
        value = row[index]

        matching_parser_actions = list(filter(lambda x: (value == x['id']), matching_parser_actions))

        # return matched parser action
        if len(matching_parser_actions) > 0:
            parser_action = matching_parser_actions[0]
            log.info(f'Found existing parser action {parser_action["id"]}')
            return parser_action['sid'], parser_action['id']

        # return new parser action
        log.info(f'No parser action found. Creating new parser action...')
        new_sid = uuid4()
        parser_action = deepcopy(self.parser_action_template)
        parser_action['sid'] = new_sid

        self.add_data_to_object(parser_action, "PARSER_ACTION", row)

        self.parser_actions[new_sid] = parser_action

        return new_sid, parser_action['id']

    #----------End Object Handling----------


    #----------functions to add specific types of data to certain locations----------
    def set_value(self, obj, path, value):
        if len(path) == 1:
            if path[0] == "INDEX":
                obj.append(value)
            else:    
                obj[path[0]] = value
            return

        if path[0] == "INDEX":
            obj.append({})
            self.set_value(obj[-1], path[1:], value)
        else:
            self.set_value(obj[path[0]], path[1:], value)

    # detail
    def add_detail(self, header, obj, mapping, value):
        path = mapping['path']

        if mapping['validation_type'] == "DATE_ZULU":
            raw_date = utils.try_parsing_date(value, header)
            if raw_date == None:
                return
            self.set_value(obj, path, time.strftime("%Y-%m-%dT08:00:00.000000Z", raw_date))
            return

        if mapping['validation_type'] == "DATE_EPOCH":
            raw_date = utils.try_parsing_date(value, header)
            if raw_date == None:
                return
            self.set_value(obj, path, int(time.mktime(raw_date)*1000))
            return

        if mapping['validation_type'] == "SEVERITY":
            severities = ["Critical", "High", "Medium", "Low", "Informational"]
            if value not in severities:
                log.warning(f'Header "{header}" value "{value}" is not a valid severity. Must be in the list ["Critical", "High", "Medium", "Low", "Informational"] Skipping...')
                return

        if mapping['validation_type'] == "STATUS":
            statuses = ["Open", "In Process", "Closed"]
            if value not in statuses:
                log.warning(f'Header "{header}" value "{value}" is not a valid status. Must be in the list ["Open", "In Process", "Closed"] Skipping...')
                return

        if mapping['validation_type'] == "ASSET_TYPE":
            types = ["Workstation", "Server", "Network Device", "Application", "General"]
            if value not in types:
                log.warning(f'Header "{header}" value "{value}" is not a valid asset type. Must be in the list ["Workstation", "Server", "Network Device", "Application", "General"] Skipping...')
                return

        if mapping['validation_type'] == "FLOAT":
            try:
                self.set_value(obj, path, float(value))
            except ValueError:
                log.exception(f'Header "{header}" value "{value}" is not a valid number. Skipping...')
            return

        if mapping['validation_type'] == "BOOL":
            try:
                self.set_value(obj, path, bool(value))
            except ValueError:
                log.exception(f'Header "{header}" value "{value}" cannot be converted to a boolean. Skipping...')
            return

        if mapping['validation_type'] == "PARSER_ACTION":
            actions = ["IGNORE", "DEFAULT", "LINK"]
            if value not in actions:
                log.warning(f'Header "{header}" value "{value}" is not a valid parser action. Must be in the list ["IGNORE", "DEFAULT", "LINK"] Skipping...')
                return
        
        self.set_value(obj, path, str(value))

    # client/report custom field
    def add_label_value(self, header, obj, mapping, value):
        label_value = {
            'label': header.strip(),
            'value': value
        }

        self.set_value(obj, mapping['path'], label_value)

    # finding custom field
    def add_key_label_value(self, header, obj, mapping, value):
        path = copy(mapping['path'])
        path.append(utils.format_key(header.strip()))

        label_value = {
            'label': header.strip(),
            'value': value
        }

        self.set_value(obj, path, label_value)

    # tag
    def add_tag(self, header, obj, mapping, value):
        utils.add_tag(obj['tags'], value)

    # multiple tags
    def add_multi_tag(self, header, obj, mapping, value):
        tags = value.split(",")
        for tag in tags:
            utils.add_tag(obj['tags'], value.strip())

    # report narrative
    def add_label_text(self, header, obj, mapping, value):
        label_text = {
            'label': header.strip(),
            'text': value
        }

        self.set_value(obj, mapping['path'], label_text)

    # finding cve
    def add_cve(self, header, obj, mapping, value):
        cves = value.split(",")
        for cve in cves:
            values = cve.strip().split("-")
            try:
                data= {
                    "name": "value",
                    "year": int(values[1]),
                    "id": int(values[2]),
                    "link": f'https://www.cve.org/CVERecord?id={value}'
                }

                self.set_value(obj, mapping['path'], data)
            except ValueError:
                log.warning(f'Header "{header}" value "{value}" is not a list of valid CVE IDs. Expects "CVE-2022-12345" or "CVE-2022-12345, CVE-2022-67890" Skipping...')

    # finding cwe
    def add_cwe(self, header, obj, mapping, value):
        cwes = value.split(",")
        for cwe in cwes:
            cwe = cwe.strip()
            try:
                data = {
                    "name": f'CWE-{cwe}',
                    "id": int(cwe),
                    "link": f'https://cwe.mitre.org/data/definitions/{cwe}.html'
                }

                self.set_value(obj, mapping['path'], data)
            except ValueError:
                log.exception(f'Header "{header}" value "{value}" is not a list of valid CWE numbers. Expects "123" or "123, 456" Skipping...')

    # list (asset known ips, operating systems)
    def add_list(self, header, obj, mapping, value):
        if value not in obj[mapping['path'][0]]:
            obj[mapping['path'][0]].append(value)

    # asset port obj - csv data should be formatted "port|service|protocol|version"
    def add_port(self, header, obj, mapping, value):
        ports = value.split(",")
        for port in ports:
            data = port.strip().split("|")
            if len(data) != 4:
                log.warning(f'Port data {port} not formatted correctly. Expected "port|service|protocol|version". Ignoring...')
                return
            if data[0] == "":
                log.warning(f'Missing port number. Expected "port|service|protocol|version". Ignoring...')
                return
            port = {
                'number': data[0].strip(),
                'service': data[1].strip(),
                'protocol': data[2].strip(),
                'version': data[3].strip()
            }
            obj['ports'][data[0]] = port
    #----------end functions----------


    def add_data_to_object(self, obj, obj_type, row):
        """
        Controller to add different types of data to different locations on an object.

        Objects can be clients, reports, findings, assets, affected assets, or vulnerabilities

        Adds all data from csv row that coresponds to the object type
        """
        for index, header in enumerate(self.csv_headers_mapping):
            data_mapping_key = self.get_key_from_header(header)
            if data_mapping_key == None:
                log.debug(f'CSV header "{header}" not mapped with a location key. Skipping {header}...')
                continue

            data_mapping = self.data_mapping.get(data_mapping_key)
            if data_mapping == None:
                log.warning(f'No Plextrac mapping for <{data_mapping_key}>, was it typed incorrectly? Ignoring...')
                continue

            # only loop through the field for the correct obj type
            if data_mapping['object_type'] != obj_type:
                continue

            data_type = data_mapping['data_type']
            value = row[index]

            # determine whether to add blank values
            if data_mapping['input_blanks'] or value != "":

                if data_type == "DETAIL":
                    self.add_detail(header, obj, data_mapping, value)
                elif data_type == "CUSTOM_FIELD":
                    self.add_label_value(header, obj, data_mapping, value)
                elif data_type == "KEY_CUSTOM_FIELD":
                    self.add_key_label_value(header, obj, data_mapping, value)
                elif data_type == "TAG":
                    self.add_tag(header, obj, data_mapping, value)
                elif data_type == "MULTI_TAG":
                    self.add_multi_tag(header, obj, data_mapping, value)
                elif data_type == "NARRATIVE":
                    self.add_label_text(header, obj, data_mapping, value)
                elif data_type == "CVE":
                    self.add_cve(header, obj, data_mapping, value)
                elif data_type == "CWE":
                    self.add_cwe(header, obj, data_mapping, value)
                elif data_type == "LIST":
                    self.add_list(header, obj, data_mapping, value)
                elif data_type == "PORTS":
                    self.add_port(header, obj, data_mapping, value)


    def parser_row(self, row):
        """
        Parsers the csv row to determine which client and report the finding should be added to.

        Gets or creates client to import to
        Gets or creates report to import to
        Creates finding
        Creates asset
        """
        # # query csv row for client specific info and create or choose client
        # client_sid, client_name = self.handle_client(row)
        # if client_sid == None:
        #     return

        # # query csv row for report specific data and creaate or choose report
        # report_sid, report_name = self.handle_report(row, client_sid)   
        # if report_sid == None:
        #     return     
        
        # # query csv row for finding specific data and create finding
        # finding_sid, finding_name = self.handle_finding(row, client_sid, report_sid)
        # if finding_sid == None:
        #     return

        # self.handle_multi_asset(row, client_sid, finding_sid)

        # # query csv row for asset specific data and create or choose asset
        # asset_sid, asset_name = self.handle_asset(row, client_sid, finding_sid)

        # # if there was a header mapped to a single asset, handle the potential affected asset data for the single asset
        # if finding_sid != None and asset_sid != None:
        #     self.handle_affected_asset(row, finding_sid)

        # query csv row for parser action specific info and create or choose parser action
        parser_action_sid, parser_action_id = self.handle_parser_action(row)
        if parser_action_sid == None:
            return

    def parse_data(self):
        """
        Top level parsing controller. Loops through loaded csv, gathers required data, calls function to process data.

        Creates and sets up csv logging file
        Determine where to look for finding name (needed to verify each row contains a finding)
        Loop through csv findings
        - Verfiy row contains finding
        - Call to process finding
        """
        # get index of 'parser_action_id' obj in self.data_mapping - this will be the index to point us to the name column in the csv
        try:
            csv_parser_action_id_index = list(self.csv_headers_mapping.values()).index('parser_action_id')
        except ValueError:
            log.critical(f'Did not map "parser_action_id" key to any csv headers. Cannot process CSV. Exiting...')
            exit()
        try:
            csv_parser_action_title_index = list(self.csv_headers_mapping.values()).index('parser_action_title')
        except ValueError:
            log.critical(f'Did not map "parser_action_title" key to any csv headers. Cannot process CSV. Exiting...')
            exit()
        

        log.info(f'---Beginning CSV parsing---')
        self.parser_progess = 0
        for row in self.csv_data:
            log.info(f'=======Parsing Action {self.parser_progess+1}=======')

            # checking if current row contains a parser action since the csv could have rows that extend beyond entered data
            if row[csv_parser_action_id_index] == "":
                log.warning(f'Row {self.parser_progess+2} in the CSV did not have a value for the parser_action_id. Skipping...')
                self.parser_progess += 1
                continue
            if row[csv_parser_action_title_index] == "":
                log.warning(f'Row {self.parser_progess+2} in the CSV did not have a value for the parser_action_name. Skipping...')
                self.parser_progess += 1
                continue
            
            action_id  = row[csv_parser_action_id_index]
            action_name = row[csv_parser_action_title_index]
            log.info(f'---{action_name} ({action_id})---')
            self.parser_row(row)

            self.parser_progess += 1
            log.info(f'=======End {action_name} ({action_id})=======')

            # if self.parser_progess >= 150:
            #     break

        # post parsing processing
        # log.info(f'---Post parsing proccessing---')
        # self.handle_finding_dup_names()


    # def import_data(self, auth):
    #     """
    #     Calls Plextrac's API to creates new clients, reports and add findings and assets
    #     """
    #     # send API creation requests to Plextrac
    #     log.info(f'---Importing data---')
    #     # clients
    #     for client in self.clients.values():
    #         payload = deepcopy(client)
    #         payload.pop("assets")
    #         payload.pop("reports")
    #         payload.pop("sid")
    #         log.info(f'Creating client <{payload["name"]}>')
    #         response = request_create_client(auth.base_url, auth.get_auth_headers(), payload)
    #         if response.get("status") != "success":
    #             log.warning(f'Could not create client. Skipping all reports and findings under this client...')
    #             continue
    #         log.success(f'Successfully created client!')
    #         client_id = response.get("client_id")

    #         # client assets
    #         for asset_sid in client['assets']:
    #             asset = self.assets[asset_sid]
    #             if asset['original_asset_sid'] != None:
    #                 log.info(f'Found existing asset <{asset["asset"]}>')
    #                 asset['asset_id'] = self.assets[asset['original_asset_sid']]['asset_id']
    #                 continue

    #             payload = deepcopy(asset)
    #             payload.pop("sid")
    #             payload.pop("client_sid")
    #             payload.pop("finding_sid")
    #             payload.pop("dup_num")
    #             payload.pop("is_multi")
    #             log.info(f'Creating asset <{payload["asset"]}>')
    #             response = request_create_asset(auth.base_url, auth.get_auth_headers(), payload, client_id)
    #             if response.get("message") != "success":
    #                 log.warning(f'Could not create asset. Skipping...')
    #                 continue
    #             log.success(f'Successfully created asset!')
    #             asset['asset_id'] = response.get("id")

    #         # reports
    #         for report_sid in client['reports']:
    #             payload = deepcopy(self.reports[report_sid])
    #             payload.pop("findings")
    #             payload.pop("sid")
    #             payload.pop("client_sid")
    #             log.info(f'Creating report <{payload["name"]}>')
    #             response = request_create_report(auth.base_url, auth.get_auth_headers(), payload, client_id)
    #             if response.get("message") != "success":
    #                 log.warning(f'Could not create report. Skipping all findings under this report...')
    #                 continue
    #             log.success(f'Successfully created report!')
    #             report_id = response.get("report_id")

    #             # findings
    #             for finding_sid in self.reports[report_sid]['findings']:
    #                 finding = self.findings[finding_sid]
    #                 payload = deepcopy(finding)
    #                 payload.pop("assets")
    #                 payload.pop("sid")
    #                 payload.pop("client_sid")
    #                 payload.pop("report_sid")
    #                 payload.pop("affected_asset_sid")
    #                 log.info(f'Creating finding <{payload["title"]}>')
    #                 response = request_create_finding(auth.base_url, auth.get_auth_headers(), payload, client_id, report_id)
    #                 if response.get("message") != "success":
    #                     log.warning(f'Could not create finding. Skipping...')
    #                     continue
    #                 log.success(f'Successfully created finding!')
    #                 finding_id = response.get("flaw_id")

    #                 # update finding with asset info
    #                 if len(finding['assets']) > 0:
                    
    #                     pt_finding = request_get_finding(auth.base_url, auth.get_auth_headers(), client_id, report_id, finding_id)

    #                     for asset_sid in finding['assets']:
    #                         pt_asset = request_get_asset(auth.base_url, auth.get_auth_headers(), client_id, self.assets[asset_sid]['asset_id'])
    #                         pt_finding = self.add_asset_to_finding(pt_finding, pt_asset, finding_sid, asset_sid)
                    
    #                     log.info(f'Updating finding <{pt_finding["title"]}> with asset information')
    #                     response = request_update_finding(auth.base_url, auth.get_auth_headers(), pt_finding, client_id, report_id, finding_id)
    #                     if response.get("message") != "success":
    #                         log.warning(f'Could not update finding. Skipping...')
    #                         continue
    #                     log.success(f'Successfully added asset info to finding!')

    def import_parser_actions(self, auth):
        """
        Calls Plextrac's API to creates new parser actions or update existing ones
        """
        # loads existing parser actions
        log.info(f'Loading existing \'{self.parser_id}\' parser actions...')
        response = request_get_tenant_parser_actions(auth.base_url, auth.get_auth_headers(), auth.tenant_id, self.parser_id)
        if response.get('status') != "success":
            log.debug(response)
            log.error(f'Cold not load existing \'{self.parser_id}\' parser actions from instance. Exiting...')
            exit()

        existing_parser_actions_in_instance = response.get('actions').get('actions')
        existing_parser_actions_ids_in_instance = list(map(lambda x: x['id'], existing_parser_actions_in_instance))
        log.debug(f'existing parser actions in platform: {existing_parser_actions_ids_in_instance}')

        # send API creation requests to Plextrac
        log.info(f'---Importing data---')
        # parser actions
        for parser_action in self.parser_actions.values():
            payload = deepcopy(parser_action)
            payload.pop("sid")
            log.debug(payload)
            
            if parser_action['id'] in existing_parser_actions_ids_in_instance:
                # parser action already exists in Plextrac
                log.info(f'Parser action already exists. Updating parser action <{payload["title"]} ({payload["id"]})>')
                parser_action_id = payload['id']
                payload.pop("id")
                payload.pop("title")
                payload.pop("description")
                log.debug(f'You can only update Severity, Action, and Linked Writeup. Other data fields will be ignored.')
                response = request_update_parser_action(auth.base_url, auth.get_auth_headers(), payload, auth.tenant_id, self.parser_id, parser_action_id)
                if response.get('status') != "success":
                    log.warning(f'Could not update parser action. Skipping...')
                    continue
                log.success(f'Successfully updated parser action!')
            
            else:
                # parser action does not exist in Plextrac
                log.info(f'Creating parser action <{payload["title"]} ({payload["id"]})>')
                response = request_create_tenant_parser_action(auth.base_url, auth.get_auth_headers(), payload, auth.tenant_id, self.parser_id)
                if response.get("status") != "success":
                    log.warning(f'Could not create parser action. Skipping...')
                    continue
                log.success(f'Successfully created parser action!')
