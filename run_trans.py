import analysis
import os 
import sys

pcaps = []   
# pcap file path
file_path = None

if __name__ == "__main__":

    try:
        file_path = sys.argv[1]
        output_path = sys.argv[2]
    except IndexError:
        print('input error')
        exit(0)

    read_dir = os.listdir(file_path)
    pcaps = [f  for f in read_dir if f.split('.')[-1]=='pcap' or f.split('.')[-1]=='dump']
    # analysis parameter
    mode = 'sec'
    time_interval = 30
    

    for pcap in pcaps:
        myplot = analysis.TracePlot(1, 'sec')
        myplot.trans_pcap_to_csv(file_path+pcap, output_path+pcap.split('.')[0]+'.csv')
