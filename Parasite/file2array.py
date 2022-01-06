import sys

f = open(sys.argv[1], "rb")
file = f.read()
f.close()

header = hex(file[0])

for i in file[1:]:
	header += "," + hex(i)

f = open(sys.argv[2], "w")
f.write(header)
f.close()