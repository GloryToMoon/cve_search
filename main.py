#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import argparse
from datetime import datetime
import requests
import time
session=requests.Session()

color={
	'LOW':'\033[92m',
	'MEDIUM':'\033[93m',
	'HIGH':'\033[91m',
	'CRITICAL':'\033[1;37;40m',
	'ENDC':'\033[0m'
}
def decode_uri(text):
	return text.replace("&amp;","&").replace("&quot;","\"").replace("&lt;","<").replace("&gt;",">").replace("&#039;","'").replace("&#39;","'").replace("%27","'")

def output(val, num=0, out=""):
	val=decode_uri(val).split()
	out=[]
	for i in range(len(val)):
		out.append(val[i])
		if sum(list(map(lambda x: len(x),out)))>80 or i==len(val)-1:
			print("| {}{}".format(" "*5*num," ".join(out)))
			out=[]

def request(keyword):
	out={}
	start=0
	url="https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&startIndex={}"
	resp=session.get(url.format(keyword,start),verify=False).json()
	vulns=[resp]
	while resp["totalResults"]>resp["resultsPerPage"]+resp["startIndex"]:
		resp=session.get(url.format(keyword,start),verify=False).json()
		start+=resp["resultsPerPage"]
		vulns.append(resp)
	for vuln in vulns:
		for cve in vuln["vulnerabilities"]:
			cve=cve["cve"]
			for desc in cve["descriptions"]:
				if desc["lang"]=="en":
					desc=desc["value"]
					break
			highiest=0
			for cvss in cve["metrics"].values():
				if type(cvss).__name__=="list":
					cvss=cvss[0]
				if float(cvss["cvssData"]["version"])>highiest:
					highiest=float(cvss["cvssData"]["version"])
					metric=cvss
			score=metric["cvssData"]["baseScore"]
			if "baseSeverity" not in metric:
				score=(score,metric["cvssData"]["baseSeverity"])
			else:
				score=(score,metric["baseSeverity"])
			versions=[]
			cpe=[]
			if "configurations" in cve:
				for configuration in cve["configurations"]:
					for node in configuration["nodes"]:
						for cpematch in node["cpeMatch"]:
							if cpematch["vulnerable"]:
								versions.append("{}{}".format(
								cpematch["criteria"],
								" "+cpematch["versionEndExcluding"] if "versionEndExcluding" in cpematch else "")
								)
			exploits=[]
			for reference in cve["references"]:
				if "tags" in reference:
					if "Exploit" in reference["tags"]:
						exploits.append(reference["url"])
			cve={cve["id"]:{"description":desc,"score":score,"time":cve["published"]}}
			if versions:
				cve[list(cve.keys())[0]].update({"versions":versions})
			if exploits:
				cve[list(cve.keys())[0]].update({"exploits":list(set(exploits))})
			out.update(cve)
	return out

def exploitdb(cve):
	cve="-".join(cve.split("-")[1:])
	url="https://www.exploit-db.com/search?cve="+cve+"&draw=1&columns[0][data]=date_published&columns[0][name]=date_published&columns[0][searchable]=true&columns[0][orderable]=true&columns[0][search][value]=&columns[0][search][regex]=false&columns[1][data]=download&columns[1][name]=download&columns[1][searchable]=false&columns[1][orderable]=false&columns[1][search][value]=&columns[1][search][regex]=false&columns[2][data]=application_md5&columns[2][name]=application_md5&columns[2][searchable]=true&columns[2][orderable]=false&columns[2][search][value]=&columns[2][search][regex]=false&columns[3][data]=verified&columns[3][name]=verified&columns[3][searchable]=true&columns[3][orderable]=false&columns[3][search][value]=&columns[3][search][regex]=false&columns[4][data]=description&columns[4][name]=description&columns[4][searchable]=true&columns[4][orderable]=false&columns[4][search][value]=&columns[4][search][regex]=false&columns[5][data]=type_id&columns[5][name]=type_id&columns[5][searchable]=true&columns[5][orderable]=false&columns[5][search][value]=&columns[5][search][regex]=false&columns[6][data]=platform_id&columns[6][name]=platform_id&columns[6][searchable]=true&columns[6][orderable]=false&columns[6][search][value]=&columns[6][search][regex]=false&columns[7][data]=author_id&columns[7][name]=author_id&columns[7][searchable]=false&columns[7][orderable]=false&columns[7][search][value]=&columns[7][search][regex]=false&order[0][column]=0&order[0][dir]=desc&start=0&length=15&search[value]=&search[regex]=false"
	exploits=session.get(url,headers={"X-Requested-With":"XMLHttpRequest"},verify=False).content.decode()
	print (exploits)
	out=[]
	for exploit in exploits["data"]:
		out.append(exploit["description"][1])
	return out

def colorize(text,match):
	output=""
	index=0
	if text.lower().find(match.lower(),index)==-1:
		return text
	while text.lower().find(match.lower(),index)!=-1:
		output+=text[index:text.lower().find(match.lower(),index)]
		output+=color["HIGH"]+text[text.lower().find(match.lower(),index):text.lower().find(match.lower(),index)+len(match)]+color["ENDC"]
		index+=text.lower().find(match.lower(),index)+len(match)
	output+=text[index:]
	return output

def gen_output(id,info,keyword):
	out=[(id,1)]
	if args.grepmatch:
		info["description"]=colorize(info["description"],keyword)
		if "versions" in info:
			info["versions"]=list(map(lambda x: colorize(x,keyword),info["versions"]))
	out.append(("Base Score: {}{} {}{}".format(color[info["score"][1]],info["score"][0],info["score"][1],color["ENDC"]),2))
	out.append(("Description: {}".format(info["description"]),2))

	if "exploits" in info:
		out.append(("Total exploits: {}{}{}".format(color["HIGH"],len(info["exploits"]),color["ENDC"]),2))
		out.append(("Exploits:",3))
		counter=1
		for exploit in info["exploits"]:
			out.append(("[{}] {}".format(counter,exploit),4))
			counter+=1
	out.append(("Sources:",2))
	out.append(("https://nvd.nist.gov/vuln/detail/"+id,3))
	out.append(("https://cve.mitre.org/cgi-bin/cvename.cgi?name="+id,3))
	if args.explonly:
		if info.get("exploits"):
			return out
		else:
			return None
	return out

def main(keywords):
	for keyword in keywords:
		cve_list=request(keyword.replace("\n",""))
		now=datetime.now()
		if args.last:
			cve_list=dict(sorted(cve_list.items(),key=lambda x: abs(datetime.fromisoformat(x[1]["time"]) - now))[:args.last])
		else:
			cve_list=dict(sorted(cve_list.items(),key=lambda x: abs(datetime.fromisoformat(x[1]["time"]) - now)))
		if len(cve_list)!=0:
			output(keyword)
			if args.explonly==False:
				output("Total vulnerabilities: {}".format(len(cve_list)),1)
		for id,info in cve_list.items():
			out=gen_output(id,info,keyword)
			if out:
				for i in out:
					output(*i)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('keywords', nargs='*', action='store', type=str, help='Keywords for search vulnerability')
	parser.add_argument('-f', dest='file', default=[], action="store", type=open, help='File with keywords')
	parser.add_argument('-v', action='store_true', help='Show versions of vulnerable products')
	parser.add_argument('--exploits-only', dest="explonly", action="store_true", help='Show vulnerabilities only with exploits')
	parser.add_argument('-l', '--last', action="store", type=int, help='Show last N vulnerabilities')
	parser.add_argument('--no-match', dest="grepmatch", action="store_false", help='Match keywords')
	args = parser.parse_args()

	if args.explonly==True and args.v<=2:
		args.v=2
	try:
		args.file=args.file.read().splitlines()
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
