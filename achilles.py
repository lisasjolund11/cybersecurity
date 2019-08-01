#!//anaconda3/envs/security/bin/python 

#chmod a+x achilles.py
#./achilles.py

#https://www.dyclassroom.com/howto-mac/how-to-install-apache-mysql-php-on-macos-mojave-10-14
#localhost folder is located here; "/Library/WebServer/Documents"
# To start localhost and kill it
#python -m http.server
#ps
#kill -9 PID [number]
#or just press control -c
#jobs


import argparse
import requests
import validators
import yaml
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment

parser = argparse.ArgumentParser(description='The Achilles HTML Vulnerability Analyzer Version 1.0')

parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str, help='The URL of the HTML to analyze')
#creates an config argument. If it is used it's possible to turn features on and off
parser.add_argument('--config', help='Path to configuration file')
parser.add_argument('-o', '--output', help='Report file output path')

args = parser.parse_args()
url = args.url
args.config

report = ''

# is no values exits in .yml configuration file these default values will be used.
# But if values exits in .yml file default values will be overwritten
config = {'forms': True, 'comments': True, 'passwords': True}

# if a configuration file is used 
if(args.config):
    print(f'Using config file: {args.config}')
    # open the file in read mode
    config_file = open(args.config, 'r')
    # use yaml to load a python object. This will make a safe load of the config.yml file
    config_from_file = yaml.safe_load(config_file)
    if(config_from_file):
        config = {**config, **config_from_file}
        

if not validators.url(url):
    raise ValueError (f'This is not a valid URL. Please include full URL including scheme: {url}')

else:
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, 'html.parser')

    forms = parsed_html.find_all('form')
    comments = parsed_html.find_all(string=lambda text:isinstance(text, Comment))
    passwords = parsed_html.find_all('input', {'name' : 'password'})
    
    if(config['forms']):
        for form in forms:
            if (form.get('action').find('https') < 0) and (urlparse(url).scheme != 'https'):
                report += (f"Form issue: Insecure from action {form.get('action')} found in document\n")
    
    if(config['comments']):               
        for comment in comments:
            if(comment.find('key: ') > -1):
                report += 'Comment issue: Key is found in the HTML comments, please remove!\n'


    if(config['passwords']):
        for password in passwords:
            if(password.get('type') != 'password'):
                report += f'Input issue: Plaintext password input found {password}. Please change to type (password) \n'


header = 'Vulnerability report: \n'
header += '=======================\n'
report_out = header + report
            
if(args.output):
    with open(args.output, 'w') as f:
        if(report) != '':
            print (report_out)
            f.write(report_out)

        else: 
            secure = 'No security issues found!!!'
            print(secure)
            f.write(header + secure)
            
        print(f'Report saved to: {args.output}')


  





      






