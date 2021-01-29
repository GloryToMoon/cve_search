import sys
import urllib, urllib2

def help():
	print "Usage: python "+sys.argv[0]+" <file with search keywords>"
	print "Example: python"+sys.argv[0]+" libs.txt"
	print "Use key \"-v\" to search in nvd.nist.gov CVE DB"
	print "Use key \"-vv\" to print description of vulnerability"
	sys.exit()

def request(keyword):
        url="https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="+keyword
        req=urllib2.Request(url)
        resp=urllib2.urlopen(req)
	return(resp.read())

def parse(html):
	out=[]
	for i in html.split("<tr>")[8:-5]:
		out.append(i.split('<a href="/cgi-bin/cvename.cgi?name=')[1].split('">')[0])
	return out

def nist(cve):
        url="https://nvd.nist.gov/vuln/detail/"+cve
        req=urllib2.Request(url)
        resp=urllib2.urlopen(req)
	html=resp.read()
	if len(html.split("<h2>")) == 2:
		return 0
	out=[]
	out.append(url)
	html="".join(html.split("\t"))
	html=" ".join(html.split("\r\n"))
	score=html.split('data-testid="vuln-cvss3')[3].split('>')[1].split('</a')[0]
	out.append("Base Score: "+score)
	out.append("Description: "+html.split('"vuln-description">')[1].split("</p>")[0])
	return out

if __name__ == "__main__":
	nvd=False
	desc=False
	if sys.argv.count("-v")>0:
		nvd=True
		sys.argv.remove("-v")
	if sys.argv.count("-vv")>0:
		nvd=True
		desc=True
		sys.argv.remove("-vv")
	if len(sys.argv)<2:
		help()
	try:
		file=open(sys.argv[1],"r")
	except:
		help()
	keywords=file.read().split("\n")[:-1]
	file.close()
	zero=[]
	c1="1"
	for keyword in keywords:
		html=request(keyword)
		mas=parse(html)
		if len(mas)==0:
			zero.append(keyword)
		else:
			print ("["+c1+"] "+keyword)
			print ("[+] "+" "*5+"Total results: "+str(len(mas)))
			c1=str(int(c1)+1)
		c2="1"
		for i in mas:
			print "["+c2+"]"+" "*10+i
			if nvd==True:
				second=nist(i)
				print "[+] "+" "*15+second[1]
				if desc == True:
					print "[+] "+" "*15+second[2]
				print "[+] "+" "*15+"Sources:"
				print "[+] "+" "*20+second[0]
			else:
				print "[+] "+" "*15+"Sources:"
			print "[+] "+" "*20+"https://cve.mitre.org/cgi-bin/cvename.cgi?name="+i
			c2=str(int(c2)+1)

	for i in zero:
		print("[-] Not found for "+i)
