#! /usr/bin/env python2
# -*- coding: utf-8 -*-
import json
import argparse
import urllib2

class bcolors(str):
	LOW = '\033[92m'
	MEDIUM = '\033[93m'
	HIGHT = '\033[91m'
	CRITICAL = '\033[1;37;40m'
	ENDC = '\033[0m'

def decode_uri(text):
	return text.replace("&amp;","&").replace("&quot;","\"").replace("&lt;","<").replace("&gt;",">").replace("&#039;","'").replace("&#39;","'").replace("%27","'")

def output(val, num=0, out=""):
	for i in val.split():
		if len(val.split())==1:
			print ("| {}{}".format(" "*num*5,decode_uri(val)))
			return 0
		if len(i+out)<80:
			out+=i+" "
		if len(out+i)>80 or i==val.split()[-1]:
			print ("| {}{}".format(" "*num*5,decode_uri(out)))
			out=""

def request(keyword):
	out=[]
	req=urllib2.Request("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+keyword)
	resp=urllib2.urlopen(req)
	for i in resp.read().split("<tr>")[8:-5]:
		check=i.split('<td valign="top">')[1]
		if check[0:14]!="** RESERVED **" and check[0:12]!="** REJECT **":
			out.append(i.split('<a href="/cgi-bin/cvename.cgi?name=')[1].split('">')[0])
	return out

def parse_cpe(html):
	out=[]
	if len(html.split("id=\"cveTreeJsonDataHidden\""))==1:
		return out
	html=json.loads(decode_uri(html.split("id=\"cveTreeJsonDataHidden\" value=\"")[1].split("\"/>")[0]))
	for dataid in html:
		for container in dataid["containers"]:
			for cpe in container["cpes"]:
				out.append(cpe["cpe22Uri"][7:])

	return out

def nist_exploit_grep(html):
	html=html.split("<tr data-testid=\"vuln-hyperlinks-row-")[1:]
	ref=[]
	for i in html:
		link=i.split("href=\"")[1].split("\"")[0]
		types=[]
		for type in i.split("<span class=\"badge\">")[1:]:
			types.append(type.split("</span>")[0])
		if types.count("Exploit")==1:
			ref.append(link)
	return ref

def nist(cve):
	url="https://nvd.nist.gov/vuln/detail/"+cve
	req=urllib2.Request(url)
	try:
		resp=urllib2.urlopen(req)
	except urllib2.HTTPError as error:
		if error.code>=500:
			print ("| https://nvd.nist.gov is returned 500 error.\n| Please wait a few seconds.")
			exit(0)
	html=resp.read().replace("\t"," ").replace("\r\n"," ")
	exploits=nist_exploit_grep(html)
	if len(html.split("<h2>")) == 2:
		return 0,0,[]
	if args.v>2:
		cpe_list=parse_cpe(html)
	else:
		cpe_list=[]
	out=[url]
	try:
		score=html.split('data-testid="vuln-cvss3')[3].split('>')[1].split('</a')[0]
	except:
		print ("| Encoding error in nvd.nist.gov :(\n| try later pls")
		return 0,0,[]
	if score.split()[0]=="N/A":
		score=html.split("Cvss2CalculatorAnchor")[1].split(">")[1].split("<")[0]
	score_num=score.split()[0]
	if score_num!="N/A":
		if float(score_num)<4:
			score=bcolors.LOW+score+bcolors.ENDC
		elif float(score_num)>=4 and float(score_num)<=7:
			score=bcolors.MEDIUM+score+bcolors.ENDC
		elif float(score_num)>=7 and float(score_num)<=9:
			score=bcolors.HIGHT+score+bcolors.ENDC
		elif float(score_num)>=9:
			score=bcolors.CRITICAL+score+bcolors.ENDC
	out.append("Base Score: "+score)
	out.append("Description: "+html.split('"vuln-description">')[1].split("</p>")[0])
	return out, cpe_list, exploits

def search_exploit(cve):
	cve="-".join(cve.split("-")[1:])
	url="https://www.exploit-db.com/search?cve="+cve+"&draw=1&columns[0][data]=date_published&columns[0][name]=date_published&columns[0][searchable]=true&columns[0][orderable]=true&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=download&columns[1][name]=download&columns[1][searchable]=false&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=application_md5&columns[2][name]=application_md5&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=verified&columns[3][name]=verified&columns[3][searchable]=true&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=description&columns[4][name]=description&columns[4][searchable]=true&columns[4][orderable]=false&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=type_id&columns[5][name]=type_id&columns[5][searchable]=true&columns[5][orderable]=false&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=platform_id&columns[6][name]=platform_id&columns[6][searchable]=true&columns[6][orderable]=false&columns[6][search][value]=&columns[6][search][regex]=false&columns[7][data]=author_id&columns[7][name]=author_id&columns[7][searchable]=false&columns[7][orderable]=false&columns[7][search][value]=&columns[7][search][regex]=false&order[0][column]=0&order[0][dir]=desc&start=0&length=15&search[value]=&search[regex]=false"
	req=urllib2.Request(url)
	req.add_header("X-Requested-With","XMLHttpRequest")
	resp=urllib2.urlopen(req)
	exploits=json.loads(resp.read())
	out=[]
	for exploit in  exploits["data"]:
		out.append(exploit["description"][1])
	return out

def enum_list(cve):
	out=[[cve,1]]
	exploit_check=False
	if args.v > 1:
		exploits=search_exploit(cve)
		if len(exploits)>0:
			exploits.insert(0,True)
		else:
			exploits.insert(0,False)
	if args.v > 0:
		second,cpe_list,exploits_nist=nist(cve)
		exploits+=exploits_nist
		if cpe_list==0:
			return [[cve,1], ["Info not found",2]],True
		if second!=0:
			out.append([second[1],2])
			out.append([second[2],2])
	if args.v>2 and args.version!=None:
		cpe_check=False
		for cpe in cpe_list:
			if args.version in ":".join(cpe.split(":")[2:]):
				cpe_check=True
		if not cpe_check:
			return [],exploit_check
	if args.v > 1:
		if len(exploits)>1:
			exploit_check=True
			out.append(["Total exploits: "+bcolors.HIGHT+str(len(exploits)-1)+bcolors.ENDC,2])
			out.append(["Exploits:",3])
			for exploit in exploits[1:]:
				out.append([exploit,4])
	out.append(["Sources:",2])
	if args.v>0 and second!=0:
		out.append([second[0],3])
	out.append(["https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve,3])
	if args.v > 1 and exploits[0]:
		out.append(["https://www.exploit-db.com/search?cve="+cve,3])
	if args.v > 2 and len(cpe_list)>0:
		out.append(["Vulnerable versions:", 2])
		for cpe in cpe_list:
			out.append([cpe,3])
	return out,exploit_check

def main(keywords):
	for keyword in keywords:
		cve_list=request(keyword.replace(" ", "%20").replace("\n",""))
		if args.last!=None:
			cve_list=cve_list[0:args.last]
		if len(cve_list)!=0:
			output(keyword)
			if args.explonly==False and args.version==None:
				output("Total vulnerabilities: {}".format(len(cve_list)),1)
		for cve in cve_list:
			cve_enumed,exploit_check=(enum_list(cve))
			if (args.explonly==True and exploit_check==True) or args.explonly==False:
				for string in cve_enumed:
					if args.grepmatch:
						string[0]=string[0].replace(keyword,bcolors.HIGHT+keyword+bcolors.ENDC)
					output(string[0],string[1])

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('keywords', nargs='*', action='store', type=str, help='Keywords for search vulnerability')
	parser.add_argument('-f', dest='file', default=[], action="store", type=open, help='File with keywords')
	parser.add_argument('-v', action="count", default=0, help='Description of vulnerability, -vv for search exploits  -vvv show version of vulnerable soft')
	parser.add_argument('--exploits-only', dest="explonly", action="store_true", help='Show vulnerabilities only with exploits')
	parser.add_argument('-l', '--last', action="store", type=int, help='Show last N vulnerabilities')
	parser.add_argument('-V', '--version', action="store", type=str, help='Match vulnerable versions')
	parser.add_argument('--match', dest="grepmatch", action="store_true", help='Match keywords')
	args = parser.parse_args()
	if args.explonly==True and args.v<3:
		args.v=2
	try:
		args.file=args.file.read().split("\n")
	except:
		pass
	args.file=list(set(args.file+args.keywords))
	for i in range(args.file.count("")):
		args.file.remove("")
	if len(args.file)<1 or (args.last!=None and args.last<1):
		parser.print_help()
		exit()
	try:
		main(args.file)
	except KeyboardInterrupt:
		print ("\nExit...")
