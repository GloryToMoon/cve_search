#! /usr/bin/env python2
# -*- coding: utf-8 -*-
import json
import argparse
import urllib2

class bcolors:
	LOW = '\033[92m'
	MEDIUM = '\033[93m'
	HIGHT = '\033[91m'
	CRITICAL = '\033[1;40m'
	ENDC = '\033[0m'

def read_file(file):
	file=open(file,"r")
	out=file.read().split("\n")
	file.close()
	while out.count("")!=0:
		out.remove("")
	return out

def output(val, num=0):
	val=val.split()
	out=""
	for i in val:
		out+=i+" "
		if len(out+i)>80 or i==val[-1]:
			print ("| {}{}".format(" "*num,out))
			out=""

def request(keyword):
	req=urllib2.Request("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+keyword)
	resp=urllib2.urlopen(req)
	return resp.read()

def parse(html):
	out=[]
	for i in html.split("<tr>")[8:-5]:
		check=i.split('<td valign="top">')[1]
		if check[0:14]!="** RESERVED **" and check[0:12]!="** REJECT **":
			out.append(i.split('<a href="/cgi-bin/cvename.cgi?name=')[1].split('">')[0])
	return out

def nist(cve):
	url="https://nvd.nist.gov/vuln/detail/"+cve
	req=urllib2.Request(url)
	resp=urllib2.urlopen(req)
	html=" ".join("".join(resp.read().split("\t")).split("\r\n"))
	if len(html.split("<h2>")) == 2:
		return 0
	out=[]
	out.append(url)
	score=html.split('data-testid="vuln-cvss3')[3].split('>')[1].split('</a')[0]
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
	out.append("Description: "+html.split('"vuln-description">')[1].split("</p>")[0].replace("&amp;","&").replace("&quot;","\"").replace("&lt;","<").replace("&gt;",">").replace("&#39;","'"))
	return out

def search_exploit(cve):
	cve="-".join(cve.split("-")[1:])
	url="https://www.exploit-db.com/search?cve="+cve+"&draw=1&columns[0][data]=date_published&columns[0][name]=date_published&columns[0][searchable]=true&columns[0][orderable]=true&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=download&columns[1][name]=download&columns[1][searchable]=false&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=application_md5&columns[2][name]=application_md5&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=verified&columns[3][name]=verified&columns[3][searchable]=true&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=description&columns[4][name]=description&columns[4][searchable]=true&columns[4][orderable]=false&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=type_id&columns[5][name]=type_id&columns[5][searchable]=true&columns[5][orderable]=false&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=platform_id&columns[6][name]=platform_id&columns[6][searchable]=true&columns[6][orderable]=false&columns[6][search][value]=&columns[6][search][regex]=false&columns[7][data]=author_id&columns[7][name]=author_id&columns[7][searchable]=false&columns[7][orderable]=false&columns[7][search][value]=&columns[7][search][regex]=false&order[0][column]=0&order[0][dir]=desc&start=0&length=15&search[value]=&search[regex]=false"
	req=urllib2.Request(url)
	req.add_header("X-Requested-With","XMLHttpRequest")
	resp=urllib2.urlopen(req)
	exploits=json.loads(resp.read())
	out=[]
	out.append("https://www.exploit-db.com/search?cve="+cve)
	for exploit in  exploits["data"]:
		out.append(exploit["description"][1].replace("&amp;","&").replace("&quot;","\"").replace("&lt;","<").replace("&gt;",">").replace("&#039;","'"))
	return out

def main(keywords):
	for keyword in keywords:
		cve_list=parse(request(keyword))
		if len(cve_list)!=0:
			output (keyword.replace("%20", " "))
			output ("Total results: "+str(len(cve_list)),5)
		for cve in cve_list:
			second=nist(cve)
			output (cve,10)
			if second!=0:
				output (second[1],15)
			if args.v > 0 and second!=0:
				output (second[2],15)
			if args.v > 1:
				exploits=search_exploit(cve)
				if len(exploits)>1:
					output("Total exploits: "+bcolors.HIGHT+str(len(exploits)-1)+bcolors.ENDC,15)
					output("Exploits:",20)
					for exploit in exploits[1:]:
						output(exploit,25)
			output ("Sources:",15)
			if second!=0:
				output (second[0],20)
			output ("https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve,20)
			if args.v > 1 and len(exploits)>1:
				output(exploits[0],20)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('keywords', nargs='*', action='store', type=str, help='Keywords for search vulnerability')
	parser.add_argument('-f', dest='file', default=[], action="store", type=read_file, help='File with keywords')
	parser.add_argument('-v', action="count", default=0, help='Description of vulnerability, -vv for search exploits')
	args = parser.parse_args()
	for keyword in args.keywords:
		args.file.append(keyword.replace(" ", "%20"))
	args.file=list(set(args.file))
	if len(args.file)<1:
		parser.print_help()
		exit()
	try:
		main(args.file)
	except KeyboardInterrupt:
		print ("\nExit...")
