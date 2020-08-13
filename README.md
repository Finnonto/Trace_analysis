# Trace Analysis

This project can analyze network trace files and make statistic data to charts.

## Table of Contents

- [Trace Analysis](#Trace-Analysis)
- [Table of Contents](#Table-of-Contents)
- [Sample Outputs](#Sample-Outputs)
- [Dependency](#Dependency)
- [How To Use](#How-To-Use)
  - [Calculate exact entropy values (One Trace File)](#Calculate-exact-entropy-values-(One-Trace-File))
  - [Calculate exact entropy values (Several Trace Files)](#Calculate-exact-entropy-values-(Several-Trace-Files))
- [Advanced Features](#Advanced-Features)
  - [Select Output Elements](#Select-Output-Elements)
  - [Speed up the analysis process](#Speed-up-the-analysis-process)
- [Developer Mode](#Developer-Mode)

## Sample Outputs

- Entropy Statistics
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_1_entropy.png)

- Distinct Counts
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_2_count.png)

- CSV File
![ ](https://raw.githubusercontent.com/LycorisAurea/trace_analysis/master/show/Example_4_csv.png)

## Dependency

- Linux OS
- The file `analysis.py` uses python3.5, needs kits: `dpkt` and `plotly`

  ```bash
  sudo apt install python3-pip
  pip3 install dpkt
  pip3 install plotly
  ```

## How To Use

### Calculate exact entropy values (One Network Trace File)

- Usage :

    ```bash
    python3 analysis.py <network trace file>  <attack list(or none)> <mode:sec/min/hour/real> <time interval(sec)>
    ```

  - `network trace file` : The path of the network trace file you want to analysis.
  - `attack list`: The time of attack ranges. If you don't have attack list, you can fill in 'none'. Refer to `attack_list_example.txt` for details.
  - `mode` : The display mode of x-axis showing in charts, csv files. 'real' option will display real packet time in network trace files.
  - `time interval` : The time interval range to analysis network trace files. **The unit is second**.

- Example

  ```bash
  python3 analysis.py test.pcap none sec 30
  ```

### Calculate exact entropy values (Several Trace Files)

Some large network traces may be seperated to seveal smaller files. Please import functions in `analysis.py` and write a new program.

- Usage : Refer to `sep_trace_example.py` for details.

## Advanced Features

### Select Output Elements

You can select output element by modifying the codes.

- Entropy Value  
  You can select the **6 entropy elements** to output : `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Packet Length`, `Protocol`.

  ``` Python
  TracePlot.entropy_one_plot(
  ['entropy_src_ip', 'entropy_dst_ip', 'entropy_sport',
   'entropy_dport', 'entropy_pkt_len', 'entropy_proto']
  )
  ```
  
- Distinct Count  
  You can select the **6 distinct count** and **3 count elements** to output : `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Packet Length`, `Protocol` and `Packet Count`, `Total Packet Length`, `Average Packet Length`.

  ``` Python
  TracePlot.count_one_plot(
  ['distinct_src_ip', 'distinct_dst_ip', 'distinct_sport',
   'distinct_dport', 'distinct_pkt_len', 'distinct_proto',
   'count_pkt_cnt', 'count_total_pkt_len','count_average_pkt_len']
  )
  ```

### Speed up the analysis process

If you need to analyze the same network trace many times, you may hope to speed up the process. Based on experience, transforming the file format of the network trace to `csv` format in advance will process faster. This project provide the function to transform network traces to csv format.

- Transform Network Traces To `csv` Format

  ``` bash
  python3 analysis.py <origin network trace> <name of output file> trans
  ```

  - `origin network trace` : The file of the trace you want to transform.

  - `name of output file` : Your output file.

  For example :

  ``` bash
  python3 analysis.py test.pcap test.csv trans
  ```

- How To Analyze Trace of csv Format  
  Exactly the same as previous steps. Reffer to :
  - [Calculate exact entropy values (One Trace File)](#Calculate-exact-entropy-values-(One-Trace-File))
  - [Calculate exact entropy values (Several Trace Files)](#Calculate-exact-entropy-values-(Several-Trace-Files)) 

## Developer Mode

### Get Element of Trace

### Use Another Method To Calculate Entropy

It will get the accurate entropy value by using the default parameters. Of course, you can simulate another algorithm of entropy calculation in this project.

- Use Another Algorithm To Calculate Entropy

  - The following code means to use default method to calculate entropy value.

    ``` Python
    TracePlot.one_analysis(input_pcap)
    ```

  - If you want to use `est_pingli` method to calculate, for example, you can modify as below.

    ``` Python
    TracePlot.one_analysis(input_pcap, 'est_pingli')
    ```

- Customize Algorithm of Entropy Calculation  
  You can add your algorithm in `cal_entropy_method.py`. Refer to other methods in `cal_entropy_method.py`.
  1. Define a **class method** and program your algorithm  
    The parameter `container` is a `Conter` structure. It contains items and counts of every item. You can process your data from `container`, and finaaly return an entropy value with `Float` type.

      ``` Python
      def calEntropy_pingli(self, container):

          ...

          for item, cnt in container.most_common():
              ...

          return A_Float_Type_Entropy_Value
      ```
  
  2. Add and give a name to your method in the beginning dictinary.

      ``` Python
      self.method_dic = dict(
          est_pingli=self.calEntropy_pingli
      )
      ```

  3. Following the step "**Use Another Algorithm To Calculate Entropy**" to use your algorithm.

- The table methods (modification version)

## Reference

- [dpkt](https://dpkt.readthedocs.io/en/latest/)
- [plotly](https://plotly.com/python/)
- `est_clifford` method : [Sketching Algorithm of Clifford and Cosma](http://proceedings.mlr.press/v31/clifford13a.pdf)
- `est_pingli` method : [Compressed Counting Algorithm of Ping Li](http://proceedings.mlr.press/v19/li11a.html)
