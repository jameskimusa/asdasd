from requests.auth import HTTPBasicAuth
from configparser import ConfigParser
from os.path import exists
from sqlite3 import Error
from datetime import datetime

import smtplib
import multiprocessing
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
from ast import Num

def remove_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def fix_json(data):
    data = "[" + data.replace("]}", "]},", data.count("]}")-1) + "]"
    return data

def get_github_urls(userid, password,orgs, users):
    urls = []
    if orgs.strip():
        for org in orgs.split('\n'):
            print(org);
            response = requests.get('https://api.github.com/orgs/' + org.strip() + '/repos', auth=HTTPBasicAuth(userid, password))
            print(response.json())
            for repo in response.json():
                urls.append(repo['clone_url'])
    if users.strip():
        for user in users.split('\n'):
            print(user)
            response = requests.get('https://api.github.com/users/' + user.strip() + '/repos', auth=HTTPBasicAuth(userid, password))
            print(response.json())
            for repo in response.json():
                urls.append(repo['clone_url'])
    print(urls)
    return urls

def get_bitbucket_urls(userid, password,base_url, settings):
    print("scanning bitbucket")
    urls = []
    is_last_page = False
    next_page_start = '0'

    while not is_last_page:
        response = requests.get(base_url + '/rest/api/1.0/repos?limit=' + str(settings['page_size']) + '&start=' + str(next_page_start), auth=HTTPBasicAuth(userid, password))
        print(response.json())
        response_json = response.json()
        is_last_page = response_json['isLastPage']
        if 'nextPageStart' in response_json:
            next_page_start = response_json['nextPageStart']
        for repo in response_json['values']:
            links = repo['links']['clone']
            for link in links:
                print(link)
                if link['name'] == 'http':
                    urls.append(link['href'])
    print(urls)
    return urls

def get_gitlab_urls(token, base_url, settings):
    print("scanning gitlab")
    headers = {"PRIVATE-TOKEN": token}

    urls = []
    is_last_page = False
    next_page_start = '1'

    while not is_last_page:
        response = requests.get(base_url + '/api/v4/projects?simple=true&per_page=' + str(settings['page_size']) + '&page=' + str(next_page_start), headers=headers)
        print(response.json())
        response_json = response.json()
        response_headers = response.headers
        print(response_headers)
        is_last_page = response_headers['X-Next-Page'] == '' 
        next_page_start = response_headers['X-Next-Page']
        for project in response_json:
            urls.append(project['http_url_to_repo'])
    print(urls)
    return urls
    
def get_azure_devops_urls(userid, password, org):
    urls = []

    response = requests.get('https://dev.azure.com/' + org.strip() + '/_apis/git/repositories?api-version=6.0&includeAllUrls=true', auth=HTTPBasicAuth(userid, password))
    print(response.json())
    for repo in response.json()['value']:
        urls.append(repo['webUrl'])
    return urls 
    
def repo_to_file_name(repo):
    file_name = repo.strip()
    file_name = file_name.replace("https://", "")
    file_name = file_name.replace("http://", "")
    file_name = file_name.replace("/", "~")
    file_name = file_name.replace("/", "~")
    file_name = file_name.replace("\n", "")
    file_name = file_name.replace("\r", "")
    return file_name

def divide_chunks(list, n):
      
    # looping till length l
    for i in range(0, len(list), n): 
        yield list[i:i + n]

def get_current_db_datetime():
    return datetime.now().strftime("%B %d, %Y %I:%M:%S%p")

def start_scan(repo_scan_type, urls, settings):
    processing_threads = int(settings['processing_threads'])
        
    url_partitions = divide_chunks(urls, int(len(urls) / processing_threads) + 1)

    try:
        connection = sqlite3.connect(settings['database'])
        create_time = get_current_db_datetime()
        
        cursor = connection.cursor()
        cursor.execute("INSERT INTO SCANS VALUES(?,?,?,?,?)", (None, repo_scan_type, create_time, None, "Pending"))
        scan_num = cursor.lastrowid
        print("scan_num=" + str(scan_num))
        partition_number = 0
        for url_partition in url_partitions:
            partition_number += 1
            cursor.execute("INSERT INTO SCAN_THREADS VALUES(?,?,?)", (scan_num, partition_number, "Scanning"))

            for url in url_partition:
                cursor.execute("INSERT INTO SCAN_RESULTS VALUES(?,?,?,?,?)", (scan_num, partition_number, url, "Pending", None))

        cursor.close()
        connection.commit()
    except Error as error:
        print("Error inserting record into 'scans':", error)
    finally:
        if connection:
            connection.close()   
    return scan_num

def scan_partition(scan_num, partition_num, userid, password, rescan, entropy, settings):    
    print ("processing scan_num: " + str(scan_num) + ", partition_num: " + str(partition_num))
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("SELECT repo_location FROM SCAN_RESULTS WHERE scan_num = ? and scan_thread_num = ?", (scan_num, partition_num))
        
        rows = cursor.fetchall()

        for row in rows:
            print(row[0])
            repo_location = row[0]
            update_result(scan_num, partition_num, repo_location, "Scanning", None, settings)
            print(str(partition_num) + ":" + repo_location)
            results = scan_url(repo_location, userid, password, rescan, entropy, settings)
            update_result(scan_num, partition_num, repo_location, "Finished", results, settings)
       
        update_thread(scan_num, partition_num, "Finished", settings)
        cursor.close()
        connection.commit()
    except Error as error:
        print("Error processing scan_partition", error)
    finally:
        if connection:
            connection.close()   

def update_result(scan_num, partition_num, repo_location, status, results, settings):
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("UPDATE SCAN_RESULTS set status = ?, results = ? WHERE scan_num = ? and scan_thread_num = ? and repo_location = ?", (status, results, scan_num, partition_num, repo_location)) 
        
        cursor.close()
        connection.commit()
    except Error as error:
        print("Error processing update_result", error)
    finally:
        if connection:
            connection.close()  

def update_thread(scan_num, partition_num, status, settings):
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("UPDATE SCAN_THREADS set status = ? WHERE scan_num = ? and scan_thread_num = ?", (status,  scan_num, partition_num)) 
        
        cursor.close()
        connection.commit()
        update_scan(scan_num, settings)
    except Error as error:
        print("Error processing update_thread", error)
    finally:
        if connection:
            connection.close()  

def update_scan(scan_num, settings):
    
    pending_scan_count = get_pending_scan_count(scan_num, settings)
    print("pending_scan_count = " + str(pending_scan_count))
    if pending_scan_count == 0:
        
        try:
            connection = sqlite3.connect(settings['database'])
            
            cursor = connection.cursor()
            cursor.execute("UPDATE SCANS set status = 'Finished', completed = ? WHERE scan_num = ?", (get_current_db_datetime(), scan_num )) 
            
            cursor.close()
            connection.commit()
        except Error as error:
            print("Error processing update_scan", error)
        finally:
            if connection:
                connection.close()  

def get_pending_scan_count(scan_num, settings):
    print("scan_num:" + str(type(scan_num)))
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM SCAN_RESULTS where scan_num = ? and (status = 'Pending' or status = 'Scanning')", (scan_num,))
        count = cursor.fetchone()[0]
        print(count)
        cursor.close()
        connection.commit()
    except Error as error:
        print("Error processing get_pending_scan_count", error)
    finally:
        if connection:
            connection.close()  
    return count

def get_scan_status(scan_num, settings):
    status = {}
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("SELECT scan_num, scan_type, started, completed, status from SCANS where scan_num = ?", (scan_num,))
        row = cursor.fetchone()
        scan = {}
        scan['scan_num'] = row[0]
        scan['scan_type'] = row[1]
        scan['started'] = row[2]
        scan['completed'] = row[3]
        scan['status'] = row[4]
        print('started:' + row[2] )
        
        started_time = datetime.strptime(row[2], '%B %d, %Y %I:%M:%S%p')
        if row[3] is None:
            elapsed = datetime.now() - started_time  
        else:
            completed_time = datetime.strptime(row[3], '%B %d, %Y %I:%M:%S%p')
            elapsed = completed_time - started_time
        scan['elapsed'] = str(elapsed).split(".")[0]
        status['scan'] = scan
        
        cursor.execute("SELECT scan_num, scan_thread_num, status from SCAN_THREADS where scan_num = ?", (scan_num,))
        rows = cursor.fetchall()
        threads = []
        for row in rows:
            thread = {}
            thread['scan_num'] = row[0]
            thread['scan_thread_num'] = row[1]
            thread['status'] = row[2]
            threads.append(thread)
        status['threads'] = threads
        
        cursor.execute("SELECT scan_num, scan_thread_num, repo_location, status from SCAN_RESULTS where scan_num = ?", (scan_num,))
        rows = cursor.fetchall()
        scan_results = []
        for row in rows:
            scan_result = {}
            scan_result['scan_num'] = row[0]
            scan_result['scan_thread_num'] = row[1]
            scan_result['repo_location'] = row[2]
            scan_result['status'] = row[3]
            scan_results.append(scan_result)
        status['scan_results'] = scan_results
        
        cursor.close()
        connection.commit()
    except Error as error:
        print("Error processing get_scan_status", error)
    finally:
        if connection:
            connection.close()  
    return json.dumps(status)

def scan_url(repo, userid, password, rescan, entropy, settings):
    repo_pass = repo
    if userid or password:
        repo_pass = repo.replace("://", "://" + urllib.parse.quote_plus(userid) + ":" + urllib.parse.quote_plus(password) + "@")
    file_name = settings['report_dir'] + '/' + repo_to_file_name(repo)
    # skip repos we've previously scanned with rescan is not checked
    '''
    if not rescan:
        if file_exists(file_name):
            print('skipping scan of ' + file_name)
            skipped.append(repo)
            continue
     '''
       
    # Comment this out for faster running for developmental purpose
    file = open(file_name, "w")
    cmd = "trufflehog --rules rules.json --exclude_paths exclude-patterns.txt --cleanup --json --regex --entropy=" + str(entropy) + " " + repo_pass 
    p1=Popen(cmd,shell=True,stdout=file)
    p1.wait()
    file.flush()
    file.close()
    # Comment up to here

    file = open(file_name, "r")
    output = file.read()
    file.close()
    json = fix_json(remove_ansi(output))
    return json
       

def scan_urls(repo_scan_type, urls, userid, password, rescan, entropy, settings):
    
    scan_num = start_scan(repo_scan_type, urls,settings)

    for i in range(1, int(settings['processing_threads']) + 1):
        process = multiprocessing.Process(target=scan_partition, args=(scan_num, i, userid, password, rescan, entropy, settings))
        process.start()
    
    return scan_num
    """
    for url_partition in url_partitions:
        for repo in url_partition:
            if repo.strip():
                repo_pass = repo
                if userid and password:
                    repo_pass = repo.replace("://", "://" + urllib.parse.quote_plus(userid) + ":" + urllib.parse.quote_plus(password) + "@")
                file_name = settings['report_dir'] + '/' + repo_to_file_name(repo)
                # skip repos we've previously scanned with rescan is not checked
                if not rescan:
                    if file_exists(file_name):
                        print('skipping scan of ' + file_name)
                        skipped.append(repo)
                        continue
                    
                # Comment this out for faster running for developmental purpose
                file = open(file_name, "w")
                cmd = "trufflehog --json --regex --entropy=" + str(entropy) + " " + repo_pass 
                p1=Popen(cmd,shell=True,stdout=file)
                p1.wait()
                file.flush()
                file.close()
                # Comment up to here
            
                file = open(file_name, "r")
                
                # New Changes
                allout = file.readlines()
                found_secrets[repo] = []
                
                for ln in allout:
                    jl = json.loads(ln.strip())
                    jl["key_id"] = key_id
                    key_id += 1
                    found_secrets[repo].append(jl.copy())
            
                file.close()
            
                # Below may be obsolete
                all_secrets[repo] = []
                file = open(file_name, "r")
                output = file.read()
                file.close()
            
                scanned.append(repo)
            
                all_secrets[repo] = fix_json(remove_ansi(output))

    """
def get_scan_results(scan_num, settings):
    
    scan_results = {}
    scanned = []
    skipped = []
    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("SELECT repo_location, status, results FROM SCAN_RESULTS WHERE scan_num = ?", (scan_num,))
        
        rows = cursor.fetchall()

        for row in rows:
            print(row[0])
            repo_location = row[0]
            status = row[1]
            results_json = row[2]
            if status == "Finished":
                scanned.append(repo_location)
            if status == "Skipped":
                skipped.append(repo_location)
            repo_results = {}
            repo_results['status'] = status
            repo_results['findings'] = json.loads(results_json)
            scan_results[repo_location] = repo_results
        cursor.close()
        
    except Error as error:
        print("Error in get_scan_results", error)
    finally:
        if connection:
            connection.close()   
            
    return scan_results, scanned, skipped
 
def get_scans(settings):
    
    scans = []

    try:
        connection = sqlite3.connect(settings['database'])
        
        cursor = connection.cursor()
        cursor.execute("SELECT scan_num, scan_type, started, completed, status FROM SCANS order by scan_num desc")
        
        rows = cursor.fetchall()

        for row in rows:
            scan_num = row[0]
            scan_type = row[1]
            started = row[2]
            completed = row[3]
            status = row[4]

            scan = {}
            scan['scan_num'] = scan_num
            scan['scan_type'] = scan_type
            scan['started'] = started
            scan['completed'] = completed
            scan['status'] = status
            scans.append(scan)
        cursor.close()
        
    except Error as error:
        print("Error in get_scans", error)
    finally:
        if connection:
            connection.close()   
    
    return scans
 
