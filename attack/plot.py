from matplotlib import pyplot as plt
BLOCK_SIZE = 32;
font_size_title = 15
font_size_labels = 15
lenghts=[]
probs = []
with open('data.txt', 'r') as f:
    content = f.readlines()
    for x in content:
        row = x.split()
        lenghts.append(int(row[0]))
        probs.append(float(row[1]))

plt.title("The graph of probability of a conflict for BLOCK_SIZE=" + str(BLOCK_SIZE) +  " bits", fontsize=font_size_title)
plt.xlabel("Lenght of the plaintext in blocks", fontsize=font_size_labels)
plt.ylabel("Probability of a collision", fontsize=font_size_labels)
plt.plot(lenghts, probs, lw=7)
plt.grid()

plt.savefig('figs/plot_'+str(BLOCK_SIZE)+'.eps')
plt.show()
