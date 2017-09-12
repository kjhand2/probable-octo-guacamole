import hashlib,binascii,io,sys
def hamDist(m1,m2):
	if len(m1) != len(m2):
		raise ValueError("Not equal lengths")
	return sum(x1 != x2 for x1, x2 in zip(m1,m2))

#in and out
s1 = open(sys.argv[1],"r")
s2 = open(sys.argv[2],"r")
out = io.FileIO(sys.argv[3],"w")
#convert to hash
s1cont = s1.read().strip()
s2cont = s2.read().strip()
m1=hashlib.sha256(s1cont).hexdigest()
m2=hashlib.sha256(s2cont).hexdigest()
result = hamDist(m1=m1,m2=m2)
print result
out.write(str(hex(result)[2:]))
out.close()
s2.close()
s1.close()



