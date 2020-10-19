import analysis
import os 
import sys

pcap = []   
# pcap file path
file_path = None

if __name__ == "__main__":

    try:
        file_path = sys.argv[1]
        output_path = sys.argv[2]
    except IndexError:
        print('input error')
        exit(0)

    ###
    # analysis parameter
    ###

    mode = 'sec'
    time_interval = 30


    ###
    #Automatically load all csv of pcap in file path
    ###

    read_dir = os.listdir(file_path)
    pcap = [f  for f in read_dir if f.split('.')[-1]=='csv']
    
    ###
    #make output folder 
    ###
    output_folder = output_path+file_path.split("/")[-2]+'/'
    os.system('mkdir '+output_folder)


    ###
    #Automatically Generate list of pcap of file path
    #so that we can use this in later experiments
    ###

    with open(output_folder+file_path.split('/')[-2]+'.txt', 'w') as fout:
        for p in pcap:
            fout.write(p.split('.')[0]+'\n')
            
            
    ###
    #Give all parameters of analyzed pcap files
    ###

    algorithm = ['exact','est_pingli','est_clifford']
    normalization = ['orign','total','distinct']


    for alg in algorithm:
        for nf in normalization:
            #make output direct file
            
            output_location ='{0}{1}_{2}_{3}'.format(output_folder,alg.split('_')[-1],nf,time_interval)
            os.system('mkdir '+output_location)

            for p in pcap:

                myplot = analysis.TracePlot(time_interval, mode,nf=nf)
                myplot.import_k_value(20)
                myplot.import_output_location(output_location)
                myplot.one_analysis(file_path+p,alg)


                myplot.entropy_one_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                                        'entropy_pkt_len', 'entropy_proto'])
                myplot.entropy_seperate_plot(['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport', 'entropy_dport', 
                                                'entropy_pkt_len', 'entropy_proto'])
                myplot.count_one_plot(['count_pkt_cnt', 'count_total_pkt_len', 
                                        'distinct_src_ip', 'distinct_dst_ip', 'distinct_sport', 'distinct_dport', 
                                            'distinct_pkt_len', 'distinct_proto', 'count_average_pkt_len'])
                myplot.csv_output()


