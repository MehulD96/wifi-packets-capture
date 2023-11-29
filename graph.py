import numpy as np
import matplotlib.pyplot as plt


def graph():
	#print(name)
	# data to plot
	n_groups = 4
	labels = ['ping_iperf_1','ping_stw','ping_test_01','ping_test_1']
	means_frank = (7200, 7200, 7200, 7200)
	means_guido = (7135, 7181, 7188, 7190)

	# create plot
	fig, ax = plt.subplots()	
	index = np.arange(n_groups)
	x = np.arange(len(labels))
	bar_width = 0.2
	opacity = 0.85

	rects1 = plt.bar(index, means_frank, bar_width,
	alpha=opacity,
	color='r',label='total_packets')

	rects2 = plt.bar(index + bar_width, means_guido, bar_width,
	alpha=opacity,
	color='black',label='successful_packets')

	plt.xlabel('Total no.scan/scan done')
	plt.ylabel('Iterations')
	plt.title('Ping Statistics')
	ax.set_xticks(x)
	ax.set_xticklabels(labels)
	plt.xticks(index + bar_width, ('ping_iperf_1','ping_stw','ping_test_01','ping_test_1'),rotation=90)
	plt.legend()

	def autolabel(rects):
	    """Attach a text label above each bar in *rects*, displaying its height."""
	    for rect in rects:
            	height = rect.get_height()
            	ax.annotate('{}'.format(height),
		            xy=(rect.get_x() + rect.get_width() / 2, height),
		            xytext=(0, 3),  # 3 points vertical offset
		            textcoords="offset points",
		            ha='center', va='bottom')


	autolabel(rects1)
	autolabel(rects2)

	plt.tight_layout()
	plt.show()

if __name__ == "__main__":
	graph()
