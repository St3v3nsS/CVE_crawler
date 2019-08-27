import re
import json
import os
import time, datetime
from Naked.toolshed.shell import muterun_rb
from url_normalize import url_normalize
from pymongo import MongoClient
from scrape_html import HTMLParser


client = MongoClient('mongodb://localhost:27017')
db = client['exploits']
collection = db['parse_exploit']
collection.create_index([("filename", 1)], unique=True)
cve_col = db['cves']
ce = db['ce']
ce.create_index([("filename", 1)], unique=True)
brackets = {
    '{':'}',
    '[':']',
    '(':')',
    '}':'{',
    ']':'[',
    ')':'('
}


def revert(char):
    return brackets.get(char)

def construct_url(uris):
    if uris:
        for i in range(len(uris)):
            if '/bin' in uris[i] or 'cmd' in uris[i] or '/c' == uris[i] or '/>' in uris[i]:    # If we found '/bin/sh' or '/cmd' continue 
                continue
            elif 'path' in uris[i] or 'target' in uris[i] or 'base' in uris[i]: # If there's a construction like targeturi.path continue
                continue 
            elif 'datastore' in uris[i].lower():    # If url = datastore[TARGETURI]
                word = re.findall('datastore\[(.*)\]', uris[i]) # Get the datastore key 
                if word:
                    word = word[0]
                else:
                    continue
                print(word)
                print(register_options)
                if word not in register_options:    # If the key is not in register_options, then the value is manually introduced in metasploit framework
                    continue
                to_replace_arr = re.findall("'.*?{}',\s*\[(.*)\]".format(re.escape(word)), register_options)[0] # Get the array from construction like 'TARGETURI',[boolean, COMMENT', '/PATH']
                to_replace_word = to_replace_arr.replace(' ', '').split(',')
                if len(to_replace_word) > 2:
                    to_replace_word = to_replace_word[2][1:-1]  # Get the value from the array and strip the "'"
                else:
                    continue

                URIs.extend([re.sub('datastore\[(.*)\]', to_replace_word, uris[i])])    # Replace the datastore with the value
            elif 'dash{' not in str(uris[i]):
                if '/' != uris[i]:  #   If the path is '/', don't care
                    URIs.extend(['/'+uris[i].lstrip('/')]) # add the '/' at the begining of the path
            elif 'dash{' in str(uris[i]):
                to_search = re.findall('dash{(.*)}', uris[i]) # The url is like '/dash{url}/'
                if to_search:
                    urls = []
                    for i in range(len(to_search)):
                        print(to_search[i])
                        urls.extend(re.findall(to_search[i]+'\s*=\s*[\'"]?(.*?)[\'"]\n', exploit))  # Try to find that variable
                    if urls:
                        URIs.extend(['/'+re.sub('dash{(.*)}', url, uris[i]).lstrip('/') for url in urls])   # Add the new uri to the main array

# There are some problems with regex so parsing the description was the best way to get all the necessary info
def find_desc(description):
    start = -1
    end = -1
    count = 0
    found = False
    is_q = False
    delimiter = ''
    for i, word in enumerate(description):
        
        if word == '%' and start == -1: # Find the %[qQ] and the delimiter '(', '[' or '{'
            start = i
            if description[i+1] in 'qQ':    
                is_q = True
                delimiter = description[i+2]    
            else:
                delimiter = description[i+1]
        if word in '{[(':   
            found = True
            count += 1
        elif word in '}])':
            count -= 1

        if (count == 0 and found and word == revert(delimiter)):    # If there's a matching paranthesis and a odd number of them
            return (start, i+1, is_q)
        elif (description[i-1] == revert(delimiter) and word == ',' and "".join(description[i+1:].split())[0] in "\'\""):   # There can be some anomalies and try to find the coresponding paranthesis in construction like ")'Author"
            return (start, i, is_q)
    return (start, end, is_q)


counter = 0
counter_rb = 0
counter_metas = 0
counter_err = 0
for (root,dirs,files) in os.walk('/home/john/Desktop/exploitdb/exploitdb/exploits', topdown=True):
    for name in files:
        filename = os.path.join(root, name)
        parsed = True
        error = ""
        counter += 1
        date = datetime.datetime.now().isoformat()
        with open(filename) as f:
            exploit = f.read()
        
        exploit_type = root.split('/')[-1]
        name1, ext = os.path.splitext(name)
        
        if ext == '.html':
            html_parser = HTMLParser(filename, name1, exploit_type, exploit)
            html_parser.parse_infos()
        if ext == '.rb':
            counter_rb += 1
            try:
                print(filename)
                nospace = ""
                metasploit = re.findall('class Metasploit', exploit)    # Search for 'Metasploit' occurence
                if not metasploit:
                    continue
                counter_metas += 1
                exploit = exploit.replace('\\','\\\\')


                description = re.findall("[\'\"]Description[\'\"]\s*=>\s*(.*)", exploit, re.DOTALL)
                if description:
                    description = description[0]                  
                    description = re.sub('\s+', ' ', description)    
                    start, end, is_q = find_desc(description)
                    if start == -1:
                        desc = re.findall("[\'\"]Description[\'\"]\s*=>\s*[\'\"](.*?)[\'\"],", exploit, re.DOTALL)[0]
                        desc, = desc[0]
                    else:
                        desc = description[start:end]
                        description = description.replace("'", '"')
                        if is_q:
                            desc = desc[start+3:end-1]
                        else:
                            desc = desc[start+2:end-1]
                
                array = re.findall(r"\\?'(.*?)\\?\\?'[^\w]", exploit)   # Get all quoted strings
                for string in array:
                    string_1 = string
                    if '#' in string:
                        if len(string) == 1:
                            string_1 = '# '
                        else:
                            string_1 = string.replace('#','dash')   # Remove '#' inside them to not lose data when eliminate comments
                        exploit = re.sub(re.escape(string), "{}".format(string_1), exploit)
                    string_1 = string_1.strip('"')  # Replace '"' with '`' to avoid conflict in JSON
                    if '"' in string_1: 
                        exploit = re.sub(re.escape(string_1), string_1.replace('"', '`'), exploit)
                exploit = re.sub('(?:[,\s](#[^{\n]?.*\n{1}\w.*|#[^{\n]?.*)|(#[\'"].*?[\'"]?\n))', '', exploit)  # Delete comments
                exploit = re.sub('=begin.*?=end', '', exploit, flags=re.DOTALL) # Delete =begin and =end
                exploit = re.sub('@.*\s*=\s*.*', '', exploit) # Delete annotations

                lista = re.findall(r'\bdef initialize(?:\(\s*i|\s*super|\(\s*.*?\s*\)?\s*super)(.*?)(?:\bregister_options\b|\bend\b)\s*(?:def|[A-Za-z_0-9]+\s*=)', exploit, re.DOTALL)[0]    # Get the main initialize function
                nospace = lista + 'end of the body' # Add a flag
                nospace1 = re.findall(",?\s*({?\s*[\'\"](?:Name|Description)[\'\"].*?),?\s*\)\s*\)?\s*(?:(?:opt.*)?(?:de)?register_(?:advanced_)?(?:evasion_)?options|end of the body)", nospace, re.M | re.S)  # Get rid of the begin and the end of the function, keep only the 'variables'
                if nospace1:
                    nospace = nospace1[0]
                title = re.findall("[\'\"]Name[\'\"]\s*=>\s*['\"](.*?[\s]*.*?)['\"],", nospace)[0]    # Get title
                nospace = re.sub('=>', ':', nospace)    # Replace '=>' with ':'
                nospace = re.sub('\s+', ' ', nospace)   # Replace all two+ spaces with only one
                nospace = nospace.replace('\\', '\\\\') # Encode '\' 

                if '{' not in nospace[:4]:
                    nospace = '{' + nospace + '}'   #   Add brackets
                
                platform = re.findall('(%w{|%w\(|%w\[)(.*?)(}|\)|\]),?', nospace)   # Find platform

                nospace = re.sub("('BadChars' : )(?:'.*?'(?=\s?,\s|\s?})|\".*?\"?(?=\s?,\s'|\s?})|.*?(, '))", "\g<1>''\g<2>", nospace) # Replace 'BadChars'

                nospace = re.sub('0x0*[0-9a-fA-F][0-9a-fA-F]*','0', nospace)    # Replace hex numbers with '0'
                nospace = re.sub("'EncoderType' : (.*?)(,|}|\])", "'EncoderType' : ''\g<2>", nospace)  # Replace 'EncoderType'
                nospace = re.sub("\]\s*\[", "], [", nospace)    # Add ',' between '] ['
                authors = re.findall("'Authors?' : \[\s*(.*?)\],? '", nospace)  # Find the 'Author' (array)
                if not authors:
                    authors = re.findall("'Authors?' : \s*(.*?[\s']),? '", nospace)    # Find the 'Author' (only one)
                if authors:
                    authors = re.split(", (?=(?:[^\"']*[\"'][^\"']*[\"'])*[^\"']*$)", authors[0])   # Split authors by the most outer ','
                    for author in authors:
                        author = author.strip()
                        if not ((author.startswith('"') and author.endswith('"')) or (author.startswith("'") and author.endswith("'"))):
                            nospace = re.sub(re.escape(author), "", nospace)    #   Delete wrong name format
                        else:
                            author_rep = author[1:-1].replace('"', '')  # Delete '"' from 'O"Shea'
                            author_rep = author_rep.replace("'", '')  # Delete '"' from 'O"Shea'
                            nospace = re.sub(re.escape(author[1:-1]), author_rep, nospace)
                desc = '"' + desc.replace('"', "'") + '"'   #   Replace '"' with "'"
                title = title.replace('"', "'")
                nospace = re.sub("(?!\B'[^']*)(\w*_LICENSE|ARCH_\w*)(\s*\]*?)(?![^']*'\B)", "'\g<1>'", nospace) # Add quotation marks to 'License' and 'Arch' values
                nospace = re.sub('\'', '"', nospace)    # Transform single quotes to duble quotes
                nospace = re.sub('(.*?)" "(.*)', '\g<1>", "\g<2>', nospace) # Add ',' between 'a_string" "another_one'
                nospace = re.sub('(,)\s*,', ' \g<1>', nospace)  # Remove two consecutive ','
                nospace = re.sub('(,)\s*([}\]\)])', ' \g<2>', nospace)  # Remove ',' from ', }' (not allowed on JSON)
                nospace = re.sub(r'"\\\\\\\\x[a-zA-Z0-9\\x"\.\(\)+\s]+,', '"",', nospace) # Remove some encoded hex values      
                nospace = re.sub('(\[|{)\s*,', ' \g<1>', nospace)   # Remove ',' from '{, ' (not allowed on JSON)
                nospace = re.sub('("BrowserRequirements" : )({.*})\s*([},\]])(?=\s*["{\[]+|$)', '\g<1>""\g<3>', nospace)    # Delete 'BrowserRequirements'
                nospace = re.sub('"Stance" : (.*?)(,|})', '"Stance" : "\g<1>"\g<2>', nospace)   # Add quotation marks to 'Stance' value
                
                nospace = re.sub('"\s*:\s*(\(.*?\)\s*)([,}])', '" : "\g<1>"\g<2>', nospace)  # Add quotation marks to ': (some_unquoted_value)'
                nospace = re.sub('([^:,\[{\(\)+\.]) ([{"\[\'])', '\g<1>, \g<2>', nospace)  # Add ',' to ') (' 
                
                nospace = re.sub('(\s*?{\s*?|\s*?,\s*?)(["])?([a-zA-Z0-9_]+)(["])?\s?:\s+([^\/\[]+?)', '\g<1>"\g<3>" : \g<5>', nospace)  # Add quotation marks to 'lowercase_string: value'
                description = re.findall('"Description"\s*:\s*(.*)', nospace)
                if description:
                    description = description[0]
                    start, end, _ = find_desc(description)
                    if start != -1:
                        nospace = nospace.replace(description[start:end], desc.replace('::', ':~:'))
                nospace = re.sub('("PrependEncoder" :\s+)(.*\.[\s\n\r]*[\w]+\(.*?\).*?(}?,?\s*")|[^"\(]\S*[^"},]|\(.*\)|".*?"\s*([,}]))', '\g<1>""\g<3>\g<4>', nospace)  # Delete 'PrependEncoder'
                nospace = re.sub('("Targets"\s*:\s*)(\d+.*?\d+)', '\g<1>"\g<2>"', nospace)  #  Add quotation marks to 'Targets: 1..2'
                nospace = re.sub('(\s*[{:,\[])\s+(:\w+)', '\g<1> "\g<2>"', nospace)   #  Add quotation marks to ':some_value'
                nospace = re.sub('"Name"\s*:\s*"(.*?)", "', '"Name" : "'+title.replace('\n', ' ').replace('::', ':~:') + '", "', nospace)   # Replace title
                if platform:
                    _,platform,_ = platform[0]
                    nospace = re.sub('(%w{|%w\(|%w\[)(.*?)(}|\)|\]),?', '"{}",'.format(platform) ,nospace)  # Replace platform
                nospace = re.sub('("Space" : )[^"][0-9_,+A-Za-z\*\.\)\(\s\-\$]*', '\g<1> 1024, ', nospace)  # Add constant value to 'Space' adress
                
                nospace = re.sub('"Prepend" : (?:.*\.[\s\n\r]*[\w]+\(.*?\).*?(}?,?\s*")|"?.*?"?\s*([,}]\s*[",])|"?.*?"\s*?)', '\g<1>\g<2>', nospace)  # Remove 'Prepend' value (may contain method calls - first regex)
                nospace = re.sub('(,)\s*,', ' \g<1>', nospace)
                nospace = re.sub('(,)\s*([}\]\)])', ' \g<2>', nospace)
                nospace = re.sub('(\[|{)\s*,', ' \g<1>', nospace)
                nospace = re.sub(',\s*\d+\s*[\-\+\*]\s*\d+', '', nospace)

                nospace = re.sub('(:\s+\[\s*)([A-Z_]+[^a-z0-9-"\]}{\[]+)(\s*\])', '\g<1>"\g<2>"\g<3>', nospace)   # Add quotation marks to ': CAPITAL_LETTERS'
                nospace = re.sub('"Signature" : \/.*?\/.*?,', '', nospace)  # Remove Signature
                arithmetics = re.findall('(:\s*)(\d+)(\s*)(\*|\+|-)(\s*)(\d+)(,?)', nospace)  # Find arithmetic operations to replace with actual value
                while(arithmetics):
                    for operation in arithmetics:
                        beg, a,sp1, sign,sp2, b, ending = operation
                        if sign == '+':
                            result = int(a) + int(b)
                        elif sign == '*':
                            result = int(a) * int(b)
                        
                        nospace = re.sub(re.escape('{}{}{}{}{}{}{}'.format(beg,a,sp1,sign,sp2,b,ending)), beg+str(result)+ending, nospace)
                    arithmetics = re.findall('(:\s*)(\d+)(\s*)(\*|\+|-)(\s*)(\d+)(,?)', nospace)  # Find arithmetic operations to replace with actual value
                
                hex_values = re.findall(r'(?:\\x[0-9a-fA-F]+)+', nospace)   # Find hex escaped values
                for group in hex_values:
                    nospace = re.sub(re.escape(group), "Some string", nospace)  # Replace them with a constant
                nospace = re.sub(': nil', ': null', nospace)    # Replace 'nil' 
                targets = re.findall('("Targets" : \[\s*\[?.*?[,\s]+.*\s*\]\s*\])', nospace) # Edit the 'Targets' array
                if targets:
                    to_delete = ['References', 'Author', 'Disclosure']
                    values = [x in targets[0] for x in to_delete]
                    if len(set(values)) == 1 and values[0] == False:
                        print(values)
                        nospace = re.sub('("Targets" : \[\s*\[?.*?[,\s]+.*\s*\]\s*\])', '', nospace)
                        nospace = re.sub('(,)\s*,', ' \g<1>', nospace)
                        nospace = re.sub('(,)\s*([}\]\)])', ' \g<2>', nospace)
                        nospace = re.sub('(\[|{)\s*,', ' \g<1>', nospace)
                        nospace = re.sub(',\s*\d+\s*[\-\+\*]\s*\d+', '', nospace)
                    else:
                        to_edit = re.findall('\[\s*\[?\s*(.*?\s*})\s*\]\s*\]?', targets[0]) # Get the arrays
                        if not to_edit:
                            targets[0] = re.sub('"References" : \[\s*(.*?)\s*\]\s*\]', '', targets[0])
                            to_edit = re.findall('\[\s*\[?\s*(.*?\s*\])\s*\]?\s*\]?', targets[0]) # Can be only one
                        for i, match in enumerate(to_edit):
                            if match.endswith(']'): # Some problematic endings 
                                if not re.findall('"Arch" : \[', match):
                                    match = match[:-1]
                            check_brackets = re.findall('^".*?"\s*,\s*(.*)', match)[0] # Check if after "some string" exist a '{' eg. ["some_string", {}]
                            if not check_brackets.startswith('{'):  # If not, add them, otherwise JSON will throw an exception (can't have "key" : "value" inside arrays only if it is an object)
                                to_insert = '{ ' + check_brackets + ' }'
                                match1 = match.replace(check_brackets, to_insert)
                                nospace = re.sub(re.escape(match), match1, nospace)     
                nospace = re.sub(r'\\"([^,])', "'\g<1>", nospace)   # Some problematic endings from Windows paths eg. "C:\\"(treated like escape for '"')
                references  = re.findall('"References" : \[\s*(.*?)\s*\]\s*,\s*"', nospace)  # Find references eg. ([ ["CVE", "YYYY-NR"] ])
                if references:
                    references = references[0]
                    if references:
                        if references.startswith('[') and not references.endswith(']'):
                            nospace = re.sub(re.escape(references), references + ' ]', nospace)
                        if not references.startswith('['):  # Some anomalies like '"URL" : "SRC"' or '"URL", "SRC", "URL2", "SRC2"' so trying to create the correct format
                            new_array_1 = references.split(', ')
                            new_array = []

                            for string in new_array_1:
                                if re.findall('(".*?")\s*:\s*(".*?")', string):
                                    new_array.append(string)
                                else:
                                    values = string.strip('"').split(' ')
                                    new_array.extend('"'+string+'"' for string in values)
                            alt_array = []
                            alt_array.extend('[ {} ]'.format(arr) for arr in new_array if re.findall('(".*?")\s*:\s*(".*?")', arr)) # 
                            non_array = [arr for arr in new_array if not re.findall('(".*?")\s*:\s*(".*?")', arr)]
                            if len(non_array) % 2 == 0:
                                new_array = ['[ {}, {} ]'.format(non_array[i], non_array[i+1]) for i in range(0, len(non_array), 2)]
                                alt_array.extend(new_array)
                            references = ', '.join(alt_array)
                        references_replaced = re.sub(r'("\s*(?:\\\\\\\\|\+),?\s*")','', references) # Eliminate multiline strings 
                        references_replaced = re.sub('(\[\s*".*?")\s*:\s*(".*?"\s*\])', '\g<1>, \g<2>', references_replaced) # Replace ':' with ','
                        nospace = re.sub(re.escape(references), references_replaced, nospace)   # Replace the old format with the newly created on
                        
                nospace = re.sub(':?\s([^"]\w*::.*?[^"])([,}\]])', ': ""\g<2>', nospace)    # Add quotation marks to ': MSF::CONSOLE' like values
                nospace = re.sub('("DECODERSTUB"\s*:\s*).*?\)', '\g<1>""', nospace)
                print(nospace)
                myfile = json.dumps(nospace.replace('\\','\\\\'))   # Escape the 'backslash' and dumps to JSON
                try:
                    jsonf = json.loads(json.loads(myfile))
                    title = "NOCVE"
                    if 'References' in jsonf:
                        for arr in jsonf.get('References'):
                            if arr and arr[0] == 'CVE':
                                title = arr[0] + '-' + arr[1]
                                break

                    myDict = {
                        title: {}
                    }

                    arr = ['Name', 'Description', 'Platform', 'References', 'Targets']

                    for key in jsonf.keys():
                        if key in arr:
                            myDict[title][key] = jsonf.get(key)

                    myDict[title]['Type'] = exploit_type

                    register_options = re.findall('register_options\((.*?)],?(?:\s*self\.class)?\)?\s*(?:end)', exploit, re.DOTALL)
                    if register_options:
                        register_options = register_options[0]

                    URIs = re.findall('(GET|POST|PATCH|PUT) (.*) HTTP', exploit)
                    if URIs:
                        URIs = ['/'+URIs[i][1].lstrip('/') for i in range(len(URIs)) if URIs[i][1] != '/'] 
                    uris = re.findall('\s*[\'\"](\/[^#].*?)[\'\"]', exploit)
                    construct_url(uris)

                    normalize = re.findall('normalize_uri\((.*)\)', exploit)
                    if normalize:
                        urls = {}
                        for string in normalize:
                            to_search_1 = re.findall('[?!^\'"](.*?)[?!^\'"]', string)
                            splitted = string.replace(' ', '').replace("'",'').split(',')
                            to_search = [word for word in splitted if word not in to_search_1]
                            if to_search:
                                for i in range(len(to_search)):
                                    if 'uri' in to_search[i] or 'path' in to_search[i] or 'datastore' in to_search[i].lower():
                                        continue
                                    word = re.findall(re.escape(to_search[i])+'\s*=\s*[\'"]?(.*?)[\'"]\n', exploit)
                                    if not word:
                                        word = ''
                                    else:
                                        word = word[0]
                                    urls[to_search[i]] = word
                        normaliz = []
                        for string in normalize:
                            for key in urls.keys():
                                if key in string:
                                    string = string.replace(key, urls[key])
                            normaliz.append(string)
                        construct_url(['/' + '/'.join(s.strip('/').replace("'", '').replace(',', '').replace('"', '').replace(' ', '') for s in normaliz[i].split(',') if 'uri' not in s and 'nil' not in s) for i in range(len(normaliz))])

                    uris = re.findall("'uri'\s*=>\s*[\'\"]\/?#{.*?}(\S*)\?\S*[\'\"]", exploit)
                    construct_url(uris)

                    myDict[title]['URI'] = list(set(URIs))

                    print(json.dumps(myDict))
                    print(URIs)
                    cve_col.insert(myDict)
                except ValueError as e:
                    error = e
                    parsed = False
                document = {
                                "filename": filename,
                                "parsed": parsed,
                                "error": error,
                                "date": date
                            }
                collection.update({"filename":filename},document, upsert=True)
            except ValueError as e:
                print(e)
                counter_err += 1
                doc = {
                    "root": root,
                    "filename": name,
                    "error": nospace.replace('\\','\\\\')
                }
                ce.update({"filename": name}, doc, upsert=True)
                
print(counter)
print(counter_rb)
print(counter_metas)
print(counter_err)