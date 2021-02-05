import json
import argparse
import urllib, urllib2

def read_file(file):
	file=open(file,"r")
	out=file.read().split("\n")
	file.close()
	for i in range(0,out.count("")):
		out.remove("")
	return out

def output(val, num=0):
	if len(val)>80:
		val=val.split(" ")
		out=""
		for i in range(0, len(val)):
			if i!=len(val)-1 and len(out+val[i+1])<80:
				out+=val[i]+" "
			elif i==len(val)-1:
				print ("| "+" "*num+out+val[i])
			else:
				print ("| "+" "*num+out+val[i])
				out=""
	else:
		print ("| "+" "*num+val)

def request(keyword):
	url="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+keyword
	req=urllib2.Request(url)
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
	out.append("Base Score: "+score)
	out.append("Description: "+html.split('"vuln-description">')[1].split("</p>")[0].replace("&amp;","&").replace("&quot;","\"").replace("&lt;","<").replace("&gt;",">").replace("&#039;","'"))
	return out

def search_exploit(cve):
	cve="-".join(cve.split("-")[1:])
	url="https://www.exploit-db.com/search?cve="+cve+"&draw=1&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=0&order%5B0%5D%5Bdir%5D=desc&start=0&length=15&search%5Bvalue%5D=&search%5Bregex%5D=false"
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
			output (keyword)
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
				if len(exploits)==1:
					exploitdb=None
				else:
					output("Total exploits: "+str(len(exploits)-1),15)
					output("Exploits:",20)
					exploitdb=exploits[0]
					for exploit in exploits[1:]:
						output(exploit,25)
			output ("Sources:",15)
			if second!=0:
				output (second[0],20)
			output ("https://cve.mitre.org/cgi-bin/cvename.cgi?name="+cve,20)
			if args.v > 1 and exploitdb!=None:
				output(exploitdb,20)

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('keywords', nargs='+', action='store', type=str, help='Keywords for search vulnerability')
	parser.add_argument('-f', dest='file', default=[], action="store", type=read_file, help='File with keywords')
	parser.add_argument('-v', action="count", default=0, help='Description of vulnerability, -vv for search exploits')
	args = parser.parse_args()
	for keyword in args.keywords:
		args.file.append(keyword)
	args.file=list(set(args.file))
	try:
		main(args.file)
	except KeyboardInterrupt:
		print ("\nExit...")
