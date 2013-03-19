#!/usr/bin/env python
'''
Created on Aug 22, 2012

@author: moloch

Tried to keep everything in one file to be a little more portable.
'''


import os
import re
import sys
import cmd
import mmap
import urllib
import sqlite3

from datetime import datetime
from ConfigParser import SafeConfigParser

# === Text Colors ===
W = "\033[0m"  # default/white
BLA = "\033[30m"  # black
R = "\033[31m"  # red
G = "\033[32m"  # green
O = "\033[33m"  # orange
BLU = "\033[34m"  # blue
P = "\033[35m"  # purple
C = "\033[36m"  # cyan
GR = "\033[37m"  # gray

# === Styles ===
bold = "\033[1m"
underline = "\033[4m"
blink = "\033[5m"
reverse = "\033[7m"
concealed = "\033[8m"

# === Background Colors ===
bkgd_black = "\033[40m"
bkgd_red = "\033[41m"
bkgd_green = "\033[42m"
bkgd_yellow = "\033[43m"
bkgd_blue = "\033[44m"
bkgd_magenta = "\033[45m"
bkgd_cyan = "\033[46m"
bkgd_white = "\033[47m"

# === Macros ===
INFO = bold + C + "[*] " + W
WARN = bold + R + "[!] " + W
PROMPT = bold + P + "[?] " + W


### Source code analyzer
class ObjcAnalyzer(object):

    def __init__(self):
        self.files = []
        self.source_files = []
        self.directories = []
        self.all_regexs = {}
        self.findings_database = FindingsDatabase()
        self.__config__()
    
    def scan(self, path, extensions, recursive=True):
        ''' Scan a directory or file into the list of files to be analyzed '''
        path = os.path.abspath(path)
        if os.path.isfile(path):
            self.files.append(path)
            self.directories.append(path[:path.rfind("/")])
        elif recursive:
            print INFO + "Started scanning:", datetime.now()
            for root, dirs, files in os.walk(path): #@UnusedVariable
                sys.stdout.write(chr(27) + '[2K')
                sys.stdout.write('\r' + INFO + "Scanning directory: " + root)
                sys.stdout.flush()
                self.files += [str(root + '/' + fname) for fname in files]
                self.directories += os.path.abspath(root)
            sys.stdout.write(chr(27) + '[2K' + '\r')
            sys.stdout.flush()
        else:
            print INFO + "Scanning directory: " + path
            ls = os.listdir(path)
            for entry in ls:
                fpath = path + '/' + entry
                if os.path.isfile(fpath):
                    self.files.append(fpath)
            self.directories.append(path)
        self.__extensions__(self.files, extensions)
        print INFO + 'Found %d file(s) in %d directories.' % (len(self.files), len(self.directories))
        print INFO + 'Found %d source code file(s)' % len(self.source_files)
        
    def start(self, project_name, regexs=None):
        ''' Starts the actual analysis '''
        if regexs == None:
            regexs = self.all_regexs
        self.project_name = project_name
        start_time = datetime.now()
        self.source_files = list(set(self.source_files)) # remove duplicates
        print INFO + "Starting analysis:", start_time
        for file_path in self.source_files:
            self.current_file = file_path
            sys.stdout.write(chr(27) + '[2K')
            sys.stdout.write('\r%s[%d/%d]%s Analyzing %s' % (bold, self.source_files.index(file_path) + 1, len(self.source_files), W, file_path))
            sys.stdout.flush()
            if os.path.exists(file_path):
                with open(file_path, "r+b") as source_code:
                    try:
                        file_map = mmap.mmap(source_code.fileno(), 0)
                    except:
                        print '\r' + WARN + "Failed to open file at:", file_path
                        continue
                    for regex_set in regexs.keys():
                        self.current_regex_set = regex_set
                        self.__regex__(file_map, regexs[regex_set])
                    file_map.close()
            else:
                print WARN + 'Warning file does not exist (%s), skipping.' % file_path
        time_delta = datetime.now() - start_time
        sys.stdout.write(chr(27) + '[2K' + '\r')
        print INFO + 'Analysis completed in %s second(s)' % time_delta.seconds

    def __extensions__(self, files, extensions):
        ''' Separates files based on extension '''
        print INFO + 'Looking for source code file extensions ...'
        for fpath in files:
            if fpath[fpath.rfind("."):] in extensions:
                self.source_files.append(fpath)
    
    def __regex__(self, file_map, regexs):
        ''' Runs a regex through a file, saves any findings '''
        for regex_name in regexs.keys():
            result_iter = regexs[regex_name].finditer(file_map)
            if result_iter != None:
                for result in result_iter:
                    self.findings_database.add_finding(self.project_name, self.current_regex_set, regex_name, self.current_file, result.span())

    def __config__(self, config_path="ObjcAnalyzer.cfg"):
        ''' Loads the config file '''
        config = SafeConfigParser()
        if not os.path.exists(config_path) or os.path.isdir(config_path):
            print WARN + "Error: Missing config file at", config_path
            os._exit(1)
        config.read(config_path)
        for section in config.sections():
            self.__expressions__(config, section)
            self.findings_database.create_table(section)

    def __expressions__(self, config, section):
        ''' Initializes all of the regexs '''
        risks = {
            'low': C + '(Low Risk)' + W,
            'medium': O + '(Medium Risk)' + W,
            'high': R + '(High Risk)' + W,
        }
        regex_dict = {}
        for name, value in config.items(section):
            name, risk = name.split(",")
            try:
                risk = risks[risk]
            except KeyError:
                risk = risks['low']
            regex_dict[name + " " +risk] = re.compile(r"%s" % value)
        self.all_regexs[section] = regex_dict


### Findings class
class FindingsDatabase(object):
    
    def __init__(self, db_name="findings.db"):
        ''' Initializes the database if it does not exist '''
        if not os.path.exists(db_name):
            self.dbConn = sqlite3.connect(db_name)
            cursor = self.dbConn.cursor()
            cursor.execute("CREATE TABLE projects(id INTEGER PRIMARY KEY, project_name TEXT)")
        else:
            self.dbConn = sqlite3.connect(db_name)
            self.all_tables()
    
    def add_finding(self, project_name, table_name, regex_name, file_path, span):
        ''' Add a finding to the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT (id) FROM projects WHERE project_name = ?", (project_name,))
        project = cursor.fetchone()
        if project == None:
            raise ValueError("Project does not exist")
        query = "INSERT INTO %s  VALUES (NULL, ?, ?, ?, ?, ?)" % self.to_snake(table_name)
        cursor.execute(query, (project[0], regex_name, file_path, span[0], span[1]))
        self.dbConn.commit()

    def display_stats(self, project_name):
        ''' Returns stats on a give project '''
        cursor = self.dbConn.cursor()
        project_id = self.project_id(project_name)
        counts = {}
        for table in self.all_tables():
            count = cursor.execute("SELECT COUNT(*) FROM %s WHERE project_id = ?" % table, (project_id,))
            counts[table[0].upper() + table[1:].replace("_", " ")] = int(count.fetchone()[0])
        return counts

    def create_table(self, table_name):
        ''' Creates a table if it does not already exist '''
        table_name = self.to_snake(table_name)
        if not table_name in self.all_tables():
            cursor = self.dbConn.cursor()
            cursor.execute("""CREATE TABLE %s(
                id INTEGER PRIMARY KEY,
                project_id INTEGER,
                name TEXT,
                file_path TEXT, 
                start_pos INTEGER, 
                end_pos INTEGER,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            )""" % table_name)
            self.dbConn.commit()

    def create_project(self, project_name):
        ''' Create a project with a give name, return the projects id '''
        cursor = self.dbConn.cursor()
        cursor.execute("INSERT INTO projects VALUES (NULL, ?)", (project_name,))   
        self.dbConn.commit()
        cursor.execute("SELECT id FROM projects WHERE project_name = ?", (project_name,))
        project_id = cursor.fetchone()
        return project_id[0]
    
    def is_project(self, project_name):
        ''' Returns a bool based on if project exists in the database '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT id FROM projects WHERE project_name = ?", (project_name,))
        row = cursor.fetchone()
        return False if row == None else True
    
    def all_projects(self):
        ''' Return a list of all project names '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT * FROM projects")
        rows = cursor.fetchall()
        return [project[1] for project in rows]
    
    def project_id(self, project_name):
        ''' Given a project name, return the project's id '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT (id) FROM projects WHERE project_name = ?", (project_name,))
        project = cursor.fetchone()
        if project == None:
            raise ValueError("Project does not exist")
        return project[0]
    
    def all_tables(self):
        ''' Return a list of all non-project tables '''
        cursor = self.dbConn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type ='table' AND name != 'projects'")
        return [row[0] for row in cursor.fetchall()]

    def all_project_tables(self, project_name):
        ''' Returns a dictionary of all tables/rows for a project '''
        project_id = self.project_id(project_name)
        cursor = self.dbConn.cursor()
        results = {}
        for table in self.all_tables():
            rows = cursor.execute("SELECT * FROM %s WHERE project_id = ?" % table, (project_id,)).fetchall()
            if 0 < len(rows):
                results[table] = rows
        return results

    def to_snake(self, name):
        ''' Converts name to snake case for db use '''
        name = name.replace(" ", "")
        return (
            name[0].lower() +
            re.sub(r'([A-Z])',
                   lambda letter: "_" + letter.group(0).lower(), name[1:])
        )


### User interface 
class AnalyzerConsole(cmd.Cmd):
    
    intro = "\n\n\t" + "*** " + underline + bold + "Objective-C Analyzer v0.2" + W + " ***" + \
            "\n\nType 'help' for a list of commands."
    prompt = underline + "Analyzer" + W + " > "
    analyzer = ObjcAnalyzer()
    project_name = None
    recursive = True
    buf = 250
    extensions = ['.m', '.mm',]
    editors = {
        'vim': ['/usr/bin/vim', ' -c '],
        'sublime': ['/Applications/Sublime\ Text\ 2.app/Contents/SharedSupport/bin/subl', ':'],
    }
    editor = ['/usr/bin/vim', ' -c ']

    def do_project(self, project_name):
        '''
        Create or resume a project
        Usage: project <name>
        '''
        self.project_name = project_name
        if not self.analyzer.findings_database.is_project(self.project_name):
            pid = self.analyzer.findings_database.create_project(self.project_name)
            print INFO + "Successfully created new project with id", pid
        self.prompt = underline + "Analyzer" + W + R + " (" + self.project_name + ")" + W + " > "
        
    def do_scan(self, path):
        '''
        Add a directory/file to be analyzed
        Usage: scan <path>
        '''
        if os.path.exists(path):
            self.analyzer.scan(path, self.extensions, self.recursive)
            if raw_input(PROMPT + "Analyze these files now [y/n]: ").lower() == 'y':
                self.do_analyze("")
        else:
            print WARN + "Path does not exist"

    def do_clear(self, *args):
        '''
        Clear scanned files from scanning cache
        Usage: clear
        '''
        self.analyzer.files = []
        self.source_files = []
        self.analyzer.directories = []
        print INFO + 'Successfully cleared analyzer scanning cache.'

    def do_recursive(self, value):
        '''
        Enable/Disable recursive directory scans
        Usage: recursive <True/False>
        '''
        self.recursive = bool(value.lower() in ['on', 'enable', 'true', 'yes'])
        if self.recursive:
            print INFO + "Recursive scanning is enabled."
        else:
            print INFO + "Recursive scanning is disabled."

    def do_analyze(self, *args):
        '''
        Begin the analysis of the scanned files
        Usage: analyze
        '''
        if self.project_name == None:
            print WARN + 'Select a project first, see "help project"'
        else:    
            self.analyzer.start(self.project_name)
    
    def do_stats(self, *args):
        '''
        Display stats about the project findings
        Usage: stats
        '''
        if self.project_name == None:
            print WARN + 'Please select a project, see "help project"' 
        else:
            total = 0
            counts = self.analyzer.findings_database.display_stats(self.project_name)
            for entry in counts:
                print INFO + "%s (%d findings)" % (entry, counts[entry])
                total += counts[entry]
            print INFO + str('Total findings: %d' % total)
    
    def do_regex(self, regex):
        '''
        Run a custom regex through the project files
        Usage: regex <expression>
        '''
        pass

    def do_review(self, table_name):
        '''
        Review findings for the current project
        Usage: review
        '''
        if self.project_name == None:
            print WARN + 'Select a project first, see "help project"'
        elif len(table_name) == 0:
            project_tables = self.analyzer.findings_database.all_project_tables(self.project_name)
            table_names = project_tables.keys()
            for table in table_names:
                rows = project_tables[table]
                display_table = table[0].upper() + table[1:].replace("_", " ")
                print "\n %d. %s (%d findings)" % (table_names.index(table) + 1, display_table, len(rows))
                categories = self.__categories__(rows)
                for category in categories.keys():
                    display_category = category[0].upper() + category[1:]
                    print '\t%dx %s' % (categories[category], display_category)
            select = raw_input('\n' + PROMPT + "Select > ")
            if len(select) == 0 or select == 'exit':
                return
            try:
                table = table_names[int(select) - 1]
                self.__review__(project_tables[table])
            except ValueError:
                print WARN + "Invalid option, try again."
            except IndexError:
                print WARN + "Invalid option, try again."

    
    def do_export(self, file_name):
        '''
        Save the analysis results to a file
        Usage: export <filename>
        '''
        if self.project_name == None:
            print WARN + 'Select a project first, see "help project"'
        else:
            if os.path.exists(file_name):
                print WARN + 'File already exists!'
                if raw_input(PROMPT + "Overwrite existing file? [y/n]").lower() != 'y':
                    return
            print INFO + "Saving report to:", file_name
            f = open(file_name, 'w')
            f.write("Bad stuff goes here.\n")
            f.close()
    
    def do_update(self, url):
        '''
        Update configuration file with the latest regexs
        Usage: update
        '''
        if len(url) == 0:
            url = "http://dl.dropbox.com/u/341940/ObjcAnalyzer.cfg"
        webFile = urllib.urlopen(url)
        localFile = open(url.split('/')[-1], 'w')
        localFile.write(webFile.read())
        webFile.close()
        localFile.close()
        print INFO + "Successfully downloaded lastest configuration."

    def do_editor(self, user_input):
        '''
        Set the editor to review findings with
        Usage: editor <custom/sublime/vim>
        '''
        if len(user_input) == 0:
            print INFO + "Editor currently set to:", self.editor
        elif user_input.lower() == 'vim':
            self.editor = self.editors['vim']
            print INFO + "Successfully updated editor settings"
        elif user_input.lower() == 'sublime':
            self.editor = self.editors['sublime']
            print INFO + "Successfully updated editor settings"
        elif user_input == 'custom':
            editor_path = raw_input("Path to editor: ")
            if not os.path.exists(editor_path):
                print WARN + "Path does not exist."
                return
            goto_line = raw_input("Goto line (or leave blank): ")
            if 0 < len(goto_line):
                print INFO + "Example command: %s /path/to/file%s50" % (editor_path, goto_line)
            else:
                print INFO + "Example command: %s /path/to/file" % (editor_path, '')
                print WARN + "Disabled goto line, will only open file."
            self.editor = [editor_path, goto_line]
            print INFO + "Successfully updated editor settings"
        else:
            print WARN + 'Not an option, see "help editor"'
        

    def do_ls(self, *args):
        ''' 
        List all projects in the database
        Usage: ls
        '''
        for project_name in self.analyzer.findings_database.all_projects():
            print INFO + project_name
    
    def do_buffer(self, length):
        '''
        Set the length of the demo buffer used during review
        Usage: buffer <length>
        '''
        try:
            self.buf = int(length)
            if self.buf <= 0:
                self.buf = 1
            print INFO + "Set demo buffer to %d." % self.buf
        except:
            print WARN + "Failed to set buffer length."
            self.buf = 250

    def do_extensions(self, ls):
        ''' 
        Set the extensions for source code files
        Usage: extensions <.ext1,.ext2,...>
        '''
        if 0 < len(ls):
            self.extensions = []
            for ext in ls.replace(" ", "").split(','):
                if 0 < len(ext):
                    self.extensions.append(ext)
        print INFO + "Source code file extensions:", self.extensions

    def do_exit(self, *args):
        '''
        Exit the console
        Usage: exit
        '''
        print INFO + 'Have a nice day!'
        os._exit(0)

    def default(self, user_input):
        ''' Called when input does not match any command '''
        if user_input == 'EOF':
            print '\n' + INFO + 'Someone is an old fogy...'
            self.do_exit("")
        else:
            print WARN + 'Not a command, see "help".'
    
    def __review__(self, findings, skip=0):
        ''' Review a set of findings '''
        findings = self.__order__(findings)
        count = 1
        for finding in findings:
            if 0 < skip:
                skip -= 1
            else:
                print str('\n' + bold + "[%d/%d] " % (count, len(findings))) + W + finding[2][0].upper() + finding[2][1:]
                print bold + G + "==================================================================================" + W
                print self.__excerpt__(finding[3], finding[4], finding[5], buf=self.buf)
                print bold + G + "==================================================================================" + W
                option = raw_input(PROMPT + 'Review this finding [y/next/jmp/stop]: ').lower()
                if option  == 'y':
                    line = self.__line__(finding[3], finding[4])
                    if 0 < len(self.editor[1]):
                        os.system('%s %s%s%d' % (self.editor[0], finding[3], self.editor[1], line))
                    else:
                        os.system('%s %s' % self.editor[0], finding[3])
                elif option == 'jmp':
                    index = raw_input(PROMPT + "Jump to index: ")
                    try:
                        self.__review__(findings, skip=int(index) - 1)
                    except ValueError:
                        print WARN + "Invalid option, not a number."
                    finally:
                        return
                elif option == 'stop':
                    return
            count += 1
        print INFO + "No more findings for this category."
    
    def __line__(self, file_path, offset):
        ''' Given an offset, finds the line number '''
        f = open(file_path, 'rb')
        data = f.read()
        line = data[:offset].count('\n')
        f.close()
        return line + 1
    
    def __excerpt__(self, file_path, start_pos, end_pos, buf=200):
        ''' Pulls surrounding data from file +/- buf '''
        f = open(file_path, 'rb')
        data = f.read()
        before = data[start_pos - buf:start_pos]
        excerpt = before + bold + R + data[start_pos:end_pos] + W
        excerpt += data[end_pos:end_pos + buf]
        f.close()
        return excerpt

    def __categories__(self, rows):
        ''' Get counts of each category '''
        categories = {}
        for row in rows:
            if row[2] in categories.keys():
                categories[row[2]] += 1
            else:
                categories[row[2]] = 1
        return categories

    def __order__(self, findings):
        ''' Orders findings by category '''
        sort = {}
        for finding in findings:
            if not finding[2] in sort.keys():
                sort[finding[2]] = []
            sort[finding[2]].append(finding)
        results = []
        for cat in sort.keys():
            results += sort[cat]
        return results     

if __name__ == '__main__':
    console = AnalyzerConsole()
    try:
        console.cmdloop()
    except KeyboardInterrupt:
        print '\n' + INFO + 'Have a nice day!'


