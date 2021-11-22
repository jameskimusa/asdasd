from flask import Flask, request, jsonify, render_template, send_file, url_for
from requests.auth import HTTPBasicAuth
from configparser import ConfigParser
from os.path import exists
from sqlite3 import Error
import smtplib

import truffleHog
import json
import glob
import requests
import urllib.parse
import sqlite3
#import sys
from subprocess import Popen, PIPE
import re
import csv
import os.path
from datetime import datetime
from asyncore import read
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from gitscan import *
from asyncio.tasks import sleep

import pandas as pd

#
# Global variables
#
app = Flask(__name__)

settings = {}

# Naming convention
report_name_prefix = "secrets_report"
config_file = "config.ini"
database_name = "scans.sqlite3"

# all_secrets as a global may be obsolete...
all_secrets = {}

# End Global variables

def setup_db():
    print("checking db setup")
    if not exists(database_name):
        print("database doesn't exist, creating it ...")
        create_scans_sql = """
        CREATE TABLE scans (
            scan_num INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type VARCHAR(100) NOT NULL,
            started DATETIME NOT NULL,
            completed DATETIME,
            status VARCHAR(100)
        );
        """
        create_scans_chreads_sql = """

        CREATE TABLE scan_threads (
            scan_num INTEGER NOT NULL,
            scan_thread_num INTEGER NOT NULL,
            status VARCHAR(100) NOT NULL,
            PRIMARY KEY (scan_num,scan_thread_num)
        );
        """
        
        create_scans_results_sql = """

        CREATE TABLE scan_results (
            scan_num INTEGER NOT NULL,
            scan_thread_num INTEGER NOT NULL,
            repo_location INTEGER NOT NULL,
            status VARCHAR(100) NOT NULL,
            results VARCHAR(1000000),
            PRIMARY KEY (scan_num,scan_thread_num,repo_location)
        );
        """
        try:
            connection = sqlite3.connect(database_name)
            cursor = connection.cursor()
            cursor.execute(create_scans_sql)
            cursor.execute(create_scans_chreads_sql)
            cursor.execute(create_scans_results_sql)
            
            if connection:
                connection.close()
        except Error as e:
            print(e)
        print("tables created")



# Adding JSON functionality, to replace old data structure
def to_file(report_name, findings):
                                                    
    with open(settings['report_dir'] + '/' + report_name, 'w') as csvfile:
        writer = csv.writer(csvfile,dialect='excel',quoting=csv.QUOTE_ALL)
        writer.writerow(["URL", "Branch", "Commit", "Commit Hash", "Date", "Path", "Print Diff", "Reason", "Strings Found"])
        
        for key in findings:
            print("key:")
            print(key)
            
            results = findings[key]
            print("results:")
            print(results)
            
            for json_value in results['findings']:
                print("json_value")
                print(json_value)
                writer.writerow([key,json_value['branch'],json_value['commit'],json_value['commitHash'],json_value['date'],json_value['path'],json_value['printDiff'],json_value['reason'],''.join(json_value['stringsFound'])])
            
        csvfile.flush()
        csvfile.close()

def file_exists(file_name):
    exists = os.path.isfile(file_name)
    return exists

def read_config():
    if not file_exists(config_file):
        write_config("/tmp","100", "1", "", "", "", "", "")
    
    
    config = ConfigParser()
    global settings 
    settings = {}
    config.read(config_file)
    
    settings['report_dir'] = config.get('general', 'report_dir')
    settings['page_size'] = config.get('general', 'page_size')
    settings['processing_threads'] = config.get('general', 'processing_threads')
    settings['server'] = config.get('smtp', 'server')
    settings['port'] = config.get('smtp', 'port')
    settings['from_address'] = config.get('smtp', 'from_address')
    settings['userid'] = config.get('smtp', 'userid')
    settings['password'] = config.get('smtp', 'password')
    
    settings['database'] = database_name
    
    print(settings)
    return settings

def write_config(report_dir, page_size, processing_threads, server, port, from_address, userid, password):
    config = ConfigParser()

    config.add_section('general')
    config.set('general', 'report_dir', report_dir)
    config.set('general', 'page_size', page_size)
    config.set('general', 'processing_threads', processing_threads)

    config.add_section('smtp')
    config.set('smtp', 'server', server)
    config.set('smtp', 'port', port)
    config.set('smtp', 'from_address', from_address)
    config.set('smtp', 'userid', userid)
    config.set('smtp', 'password', password)
    with open('config.ini', 'w') as f:
        config.write(f)
    #update the global settings variable
    read_config()
    
    return

def email_report(report_recipients, report_name):
    settings = read_config()
    
    msg = MIMEMultipart()
    body_part = MIMEText("Attached is the results of the Secret Scan.", 'plain')
    msg['Subject'] = "Secret Scanner Results"
    msg['From'] = settings['from_address']
    msg['To'] = report_recipients
    # Add body to email
    msg.attach(body_part)
    # open and read the CSV file in binary
    with open(settings['report_dir'] + '/' + report_name,'rb') as file:
    # Attach the file with filename to the email
        msg.attach(MIMEApplication(file.read(), Name=report_name))

    # Create SMTP object
    smtp_obj = smtplib.SMTP(settings['server'], settings['port'])
    # Login to the server
    if settings['userid'] and settings['password']:
        smtp_obj.login(settings['userid'], settings['password'])

    # Convert the message to a string and send it
    smtp_obj.sendmail(msg['From'], msg['To'], msg.as_string())
    smtp_obj.quit()

##Parsing Data for Bar Graph

def toChartList(found_secrets):
    print("asd")
    print(found_secrets)
    data = []
    total_count = 0
    genericSecret_cnt = 0
    RSAprivatekey_cnt = 0
    sSHOpenSSH_cnt = 0
    sSHDSA_cnt = 0
    sSHEC_cnt = 0
    PGP_cnt = 0
    for value in found_secrets.values():
        #print("value:")
        #print(value)
        for reason in value['findings']:
            #print("reason:")
            #print(reason)
            if str(reason['reason']) == 'Generic Secret':
                genericSecret_cnt +=1
            if str(reason['reason']) == 'RSA private key':
                RSAprivatekey_cnt +=1                
            if str(reason['reason']) == 'SSH (OPENSSH) private key':
                sSHOpenSSH_cnt +=1
            if str(reason['reason']) == 'SSH (DSA) private key':
                sSHDSA_cnt +=1        
            if str(reason['reason']) == 'SSH (EC) private key':
                sSHEC_cnt +=1
            if str(reason['reason']) == 'PGP private key block':
                PGP_cnt +=1                

    data.append(genericSecret_cnt)
    data.append(RSAprivatekey_cnt)
    data.append(sSHOpenSSH_cnt)
    data.append(sSHDSA_cnt)
    data.append(sSHEC_cnt)
    data.append(PGP_cnt)
    total_count = genericSecret_cnt + RSAprivatekey_cnt + sSHOpenSSH_cnt + sSHDSA_cnt + sSHEC_cnt + PGP_cnt

    
    made = 0
    for value in found_secrets.values():
        if made == 0:
            df = pd.DataFrame(value['findings'])
            made += 1
        elif made == 1:
            df1 = pd.DataFrame(value['findings'])
            df = df.append(df1)
            

	#------ Findings by Category bar Graph/Donut Chart -----------------------------------------------------#
	
	#Creating a Dataframe for the Column Reason and the counts
    df_reason_cnt = df.groupby(['reason']).size().reset_index(name="count")
	
	#Creating a unique list of reasons
    reason_category = df_reason_cnt['reason'].values.tolist()
	
	#Creating a unique list of count of reasons
    reason_count = df_reason_cnt['count'].values.tolist()
	
	#------ Total Findings Number --------------------------------------------------------------------------#
	
	#Sum of Total Count of Findings
    total_sum = df_reason_cnt['count'].sum()
	
	#------ Findings by Month/Date --------------------------------------------------------------------------#

	#datetime of all findings "YYYY-MM-DD HH:MM:SS"
    df_date_cnt = df.groupby(['date']).size().reset_index(name="count")

    
    #date formatted of all findinds "YYYY-MM-DD"
    df_date_cnt['date'] = pd.to_datetime(df_date_cnt['date']).dt.date
    df_date_cnt['date'] = df_date_cnt['date'].astype('datetime64[ns]')
	
    df1 = df_date_cnt.groupby(df_date_cnt['date'].dt.year).sum()

    df1 = df_date_cnt.groupby(pd.Grouper(key='date', axis=0, freq='M')).sum()

    df1 = df1.reset_index()

    df1['date'] = df1['date'].dt.strftime('%Y-%m-%d')
    
    #convert to list
    date_labels = df1['date'].values.tolist()

    date_data = df1['count'].values.tolist()
    #convert to list

    #------ Word Cloud --------------------------------------------------------------------------#

    df3 = df['stringsFound'].values.tolist()

    #print(df3)
    #return data, total_count
    return data, total_count, reason_count, total_sum, reason_category, date_labels, date_data, df3   


#def makeDF(found_secrets):
 
	#Creating a Pandas Dataframe from found_secrets
    #df = pd.DataFrame(found_secrets)
    
    #print("ASDASDASDASD")

    #print(df)
	
	#------ Findings by Category bar Graph/Donut Chart -----------------------------------------------------#
	
	#Creating a Dataframe for the Column Reason and the counts
    #df_reason_cnt = df.groupby(['reason']).size().reset_index(name="count")
	
	#Creating a unique list of reasons
    #reason_category = df_reason_cnt['reason'].values.tolist()
	
	#Creating a unique list of count of reasons
    #reason_count = df_reason_cnt['count'].values.tolist()
	
	#------ Total Findings Number --------------------------------------------------------------------------#
	
	#Sum of Total Count of Findings
    #total_sum = df_reason_cnt['count'].sum()
	
	#------ Findings by Month/Date --------------------------------------------------------------------------#

	#datetime of all findings "YYYY-MM-DD HH:MM:SS"
    #df_date_cnt = df.groupby(['date']).size().reset_index(name="count")

    
    #date formatted of all findinds "YYYY-MM-DD"
    #df_date_cnt['date'] = pd.to_datetime(df_date_cnt['date']).dt.date
    #df_date_cnt['date'] = df_date_cnt['date'].astype('datetime64[ns]')
	
	#df1 = df_date_cnt.groupby(df_date_cnt['date'].dt.year).sum()

    #df1 = df_date_cnt.groupby(pd.Grouper(key='date', axis=0, freq='M')).sum()

    #df1 = df1.reset_index()

    #df1['date'] = df1['date'].dt.strftime('%Y-%m-%d')
    
    #convert to list
    #date_labels = df1['date'].values.tolist()

    #date_data = df1['count'].values.tolist()
    #convert to list

    #------ Word Cloud --------------------------------------------------------------------------#

    #df3 = df['stringsFound'].values.tolist()


    #print(df3)
    #return reason_count, total_sum, reason_category, date_labels, date_data, df3   



@app.route('/')
def home():
    read_config()
    setup_db()
    return render_template('index.html', email_server = settings['server'], email_server_port = settings['port'], email_from = settings['from_address'], email_userid = settings['userid'], email_password = settings['password'], report_dir = settings['report_dir'], page_size = settings['page_size'], processing_threads = settings['processing_threads'] )

@app.route('/config',methods=['POST'])
def config():
    form = request.form
    server = form['email_server']
    port = form['email_server_port']
    from_address = form['email_from']
    userid = form['email_userid']
    password = form['email_password']
    report_dir = form['report_directory']
    page_size = form['page_size']
    processing_threads = form['processing_threads']
    write_config(report_dir, page_size, processing_threads, server, port, from_address, userid, password)
    return json.dumps({'success':True}), 200, {'ContentType':'application/json'}

@app.route('/scan',methods=['POST'])
def scan():
    settings = read_config()

    form = request.form
    userid = form['userid']
    password = form['password']
    repo_scan_type = form['gitgroup']
    entropy = False
    report_recipients = form['report_recipients']
    
    if form.get('entropy'):
        entropy = True
        
    rescan = False
    if form.get('rescan'):
        rescan = True
        
    urls = []

    print("repo_scan_type:" + repo_scan_type)

    if repo_scan_type  == 'github':
        urls = get_github_urls(userid, password, form['github_orgs'], form['github_users'])
    elif repo_scan_type  == 'bitbucket':
        urls = get_bitbucket_urls(userid, password, form['url'], settings)
    elif repo_scan_type  == 'gitlab':
        urls = get_gitlab_urls(password, form['url'], settings)
    elif repo_scan_type  == 'azure':
        urls = get_azure_devops_urls(userid, password, form['azure_organization'])
    elif repo_scan_type == 'generic':
        urls = form['git_urls'].split('\n')

    scan_num = scan_urls(repo_scan_type, urls, userid, password, rescan, entropy, settings)
    
    #return render_template('results.html', scan_results=f'{table_html}', scanned_urls=f'{scanned_urls_html}',  skipped_urls=f'{skipped_urls_html}', report_name=f'{report_name}')
    #return render_template('results.html', scan_results=found_secrets, scanned_urls=scanned,  skipped_urls=skipped, report_name=f'{report_name}')
    return render_template('scanning.html', scan_num=scan_num)

@app.route('/scanning/<scan_num>',methods=['GET'])
def scanning(scan_num):
    settings = read_config()

    status = get_scan_status(scan_num, settings)
    
    return json.dumps(status), 200, {'ContentType':'application/json'} 

@app.route('/results/<scan_num>',methods=['GET'])
def results(scan_num):
    settings = read_config()

    found_secrets, scanned, skipped = get_scan_results(scan_num, settings)

    report_name = ''

    #print("ASDASD")
    #print(found_secrets)

    #Parsing data for Bar Chart
    #data = []
    #count = 0
    #data, count = toChartList(found_secrets)
    data, count, data1, total_sum, reason_category, date_labels, date_data, df3 = toChartList(found_secrets)

    #return render_template('index.html', data=data, total_sum=total_sum, reason_category=reason_category, date_labels=date_labels, date_data=date_data, df3=df3)
    #return render_template('results.html', scan_results=f'{table_html}', scanned_urls=f'{scanned_urls_html}',  skipped_urls=f'{skipped_urls_html}', report_name=f'{report_name}')
    return render_template('results.html', data=data1, count=total_sum, data1=data1, total_sum=total_sum, reason_category=reason_category, date_labels=date_labels, date_data=date_data, df3=df3, scan_results=found_secrets, scanned_urls=scanned,  skipped_urls=skipped, scan_num=f'{scan_num}')
    #return render_template('results.html', data=data, count=count, scan_results=found_secrets, scanned_urls=scanned,  skipped_urls=skipped, scan_num=f'{scan_num}')
@app.route('/previous_results',methods=['GET', 'POST'])
def previous_results():
    settings = read_config()
    
    scans = get_scans(settings)
    
    return render_template('previous_results.html', scans=scans)

@app.route('/download/<scan_num>',methods=['GET','POST'])
def download (scan_num):
    settings = read_config()
    report_name = report_name_prefix + '_' + scan_num +'.csv'
    results, scanned, skipped = get_scan_results(scan_num, settings)
    path = settings['report_dir'] + '/' + report_name
    to_file(report_name, results)
    return send_file(path, as_attachment=True)

if __name__ == "__main__":
    app.run(port=5000)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

