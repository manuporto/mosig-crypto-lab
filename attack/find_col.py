
data = []
with open('data.txt', 'r') as f:
    content = f.readlines()
    for x in content:
        row = x.split()
        data.append((int(row[0]), int(row[1])))
print(len(data))
data.sort()
print(data)
s = set([x for x in data if data.count(x) > 1])
print(s)
