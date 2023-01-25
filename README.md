# Requirements
- [Python 3+](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [pipenv](https://pipenv.pypa.io/en/latest/install/)

# Installing
After installing Python, pip, and pipenv, run the following commands to setup the Python virtual environment.
```bash
git clone this_repo
cd path/to/cloned/repo
pipenv install
```

# Setup
After setting up the Python environment, you will need to setup a few things before you can run the script.

## CSV with Data to Import
In the `config.yaml` file you should add the file path to the CSV with data yo're trying to import.

## Header Mapping CSV
To import a CSV with data, you must create a mapping to tell the script where the data for each column should go in Plextrac.
- Make a copy of the csv file with the data you want to import.
- Rename the copy to `header_mapping.csv`. If you choose a different file name you will need to update the `csv_headers_file_path` value in the `config.yaml` file.
- Open the `header_mapping.csv` and delete all rows except the header row.
- In the second row, for each column you want to import, add a location key. Available keys are 
- Move this file to the main directory where you cloned this repo. If you place it in a different directory you will need to update the `csv_headers_file_path` value in the `config.yaml` file.

## Credentials
In the `config.yaml` file you should add the full URL to your instance of Plextrac.

The config also can store your username and password. Plextrac authentication lasts for 15 mins before requiring you to re-authenticate. The script is set up to do this automatically. If these 3 values are set in the config, and MFA is not enable for the user, the script will take those values and authenticate automatically, both initially and every 15 mins. If any value is not saved in the config, you will be prompted when the script is run and during re-authentication.

# Usage
After setting everything up you can run the script with the following command. You should be in the folder where you cloned the repo when running the following.
```bash
pipenv run python main.py
```
You can also add values to the `config.yaml` file to simplify providing the script with the data needed to run. Values not in the config will be prompted for when the script is run.

## Required Information
The following values can either be added to the `config.yaml` file or entered when prompted for when the script is run.
- PlexTrac Top Level Domain e.g. https://yourapp.plextrac.com
- Username
- Password
- MFA Token (if enabled)
- File path to CSV containing data to import
- File path to CSV containing header mappings to Plextrac location keys
- Parser ID

## Script Execution Flow
When the script starts it will load in config values and try to:
- Authenticates user
- Read and verify CSV data
- Create a file to write logs to

Once this setup is complete it will start looping through each row in CSV and try to:
- Create a new parser action object and add all info

After parsing if will create new parser actions for the selected Parser in Plextrac.

## Logging
The script is run in INFO mode so you can see progress on the command line. A log file will be created when the script is run and saved to the root directory where the script is. You can search this file for "WARNING" or "ERROR" to see if something did not get parsed or imported correctly. Any critical level issue will stop the script immediately.
