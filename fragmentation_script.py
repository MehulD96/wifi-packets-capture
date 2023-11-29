import subprocess
import os
import sys
import time
import serial
import platform
import re
import serial.tools.list_ports
import threading
import subprocess
from time import ctime


def fragments(Tshark_path, Pcap_file_path, mac_addr1, mac_addr2):
    import sys
    import os
    from subprocess import Popen, PIPE

    os.system(
        Tshark_path + " -r " + Pcap_file_path + " -E header=y -E separator=/t -T fields -e frame.number -e wlan.sa -e wlan.da -e radiotap.datarate -e wlan.fc.type_subtype -e wlan.fcs.status -e ip.flags.mf > pcap_fragments.txt")

    time.sleep(25)

    # Selecting desired packets with a known mac address
    ###########################################################################################################################
    def fragmentation(line):
        #print("in fragmentation function")
        line1 = line.rstrip('\n').split('\t', 7)
        #print("packet splitted")
        if line1[6] == '1':
            #print("packet captured")
            return 1
        else:
            return 0

    def data_rate(line):

        line1 = line.rstrip('\n').split('\t', 7)
        # print(line1)
        # print(line1[5])

        if line1[3] == '1':
            return 1
        elif line1[3] == '2':
            return 2
        elif line1[3] == '5.5':
            return 5.5
        elif line1[3] == '11':
            return 11
        elif line1[3] == '6':
            return 6
        elif line1[3] == '9':
            return 9
        elif line1[3] == '12':
            return 12
        elif line1[3] == '18':
            return 18
        elif line1[3] == '24':
            return 24
        elif line1[3] == '36':
            return 36
        elif line1[3] == '48':
            return 48
        elif line1[3] == '54':
            return 54
        elif line1[3] == '6.5':
            return 6.5
        elif line1[3] == '13':
            return 13
        elif line1[3] == '19.5':
            return 19.5
        elif line1[3] == '26':
            return 26
        elif line1[3] == '39':
            return 39
        elif line1[3] == '52':
            return 52
        elif line1[3] == '58.5':
            return 58.5
        elif line1[3] == '65':
            return 65

    #################################################################################################
    fragmentation1 = 0
    fragmentation2 = 0
    fragmentation5_5 = 0
    fragmentation11 = 0
    fragmentation6 = 0
    fragmentation9 = 0
    fragmentation12 = 0
    fragmentation18 = 0
    fragmentation24 = 0
    fragmentation36 = 0
    fragmentation48 = 0
    fragmentation54 = 0
    fragmentation6_5 = 0
    fragmentation13 = 0
    fragmentation19_5 = 0
    fragmentation26 = 0
    fragmentation39 = 0
    fragmentation52 = 0
    fragmentation58_5 = 0
    fragmentation65 = 0
    packets = []
    packets1 = []
    packets2 = []
    packets3 = []
    packets4 = []
    packets5 = []
    packets6 = []
    packets7 = []
    packets8 = []
    packets9 = []
    packets10 = []
    packets11 = []
    packets12 = []
    packets13 = []
    packets14 = []
    packets15 = []
    packets16 = []
    packets17 = []
    packets18 = []
    packets19 = []
    packets20 = []
    count = 0
    count1 = 0
    count2 = 0
    count3 = 0
    count4 = 0
    count5 = 0
    count6 = 0
    count7 = 0
    count8 = 0
    count9 = 0
    count10 = 0
    count11 = 0
    count12 = 0
    count13 = 0
    count14 = 0
    count15 = 0
    count16 = 0
    count17 = 0
    count18 = 0
    count19 = 0
    count20 = 0
    count21 = 0
    substr = mac_addr1.lower()  # str((mac_addr1).lower)
    substra = mac_addr2.lower()  # str((mac_addr2).lower)

    # substr = "ae:5f:3e:18:85:42".lower()  #(mac_ta1).lower()
    # substra = (mac_ra1).lower()
    #substr1 = "good".lower()
    #substr2 = "qos data".lower()
    # substr3 = "data".lower()
    ##############################################################################################
    # print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%%%%%%%%@@@@@@@@@@@@@@@@@@@@",mac_ra1)
    with open('pcap_fragments.txt', 'rt') as myfile:

        for line in myfile:
            count += 1
            line1 = line.split('\t', 7)

            if (line.lower().find(substr) != -1 and line.lower().find(substra) != -1):

                packets.append(line.rstrip('\n'))
                # print(line)

                if line1[5] == '1' and line1[4] == '40' and data_rate(line) == 1:
                    packets1.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation1 += 1
                    count1 += 1



                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 2:
                    packets2.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation2 += 1
                    count2 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 5.5:
                    packets3.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation5_5 += 1
                    count3 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 6:
                    packets4.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation6 += 1
                    count4 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 6.5:
                    packets5.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentationy6_5 += 1
                    count5 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 9:
                    packets6.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation9 += 1
                    count6 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 11:
                    packets7.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation11 += 1
                    count7 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 12:
                    packets8.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation12 += 1
                    count8 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 13:
                    packets9.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation13 += 1
                    count9 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 18:
                    packets10.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation18 += 1
                    count10 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 19.5:
                    packets11.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation19_5 += 1
                    count11 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 24:
                    packets12.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation24 += 1
                    count12 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 26:
                    packets13.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation26 += 1
                    count13 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 36:
                    packets14.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation36 += 1
                    count14 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 39:
                    packets15.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation39 += 1
                    count15 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 48:
                    packets16.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation48 += 1
                    count16 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 52:
                    packets17.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation52 += 1
                    count17 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 54:
                    packets18.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation54 += 1
                    count18 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 58.5:
                    packets19.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation58_5 += 1
                    count19 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 65:
                    packets20.append(line.rstrip('\n'))
                    if fragmentation(line) == 1:
                        fragmentation65 += 1
                    count20 += 1
    count = (
            count1 + count2 + count3 + count4 + count5 + count6 + count7 + count8 + count9 + count10 + count11 + count12 + count13 + count14 + count15 + count16 + count17 + count18 + count19 + count20)
    fragmentation = (
            fragmentation1 + fragmentation2 + fragmentation5_5 + fragmentation11 + fragmentation6 + fragmentation9 + fragmentation12 + fragmentation18 + fragmentation24 + fragmentation36 + fragmentation48 + fragmentation54 + fragmentation6_5 + fragmentation13 + fragmentation19_5 + fragmentation26 + fragmentation39 + fragmentation52 + fragmentation58_5 + fragmentation65)
    # file1 = open("../test_results/result1.txt", 'w')
    # sys.stdout = file1
    with open('result1.txt', 'w') as file:
        file.write("\t\t\t"+"******************Fragmentation stats*******************")
        file.write("\n")
        file.write("source mac address:" +"\t" +str(substr))
        file.write("\n")
        file.write("destiation mac address:"+"\t"+str(substra))
        file.write("\n")
        file.write("Total packets:" + "\t" + str(count))
        file.write("\n")
        file.write("Total fragmentation packets:" + "\t" + str(fragmentation))
        file.write("\n\n")
        file.write(
            "Data Rate" + "\t" + "MCS" + "\t" + "Packet Count" + "\t" + "% of total Packets" + "\t" + "fragmentation%" + "\t\t" + "count of fragmented packets" + "\n")
        try:
            file.write("\n1    Mbps" + "\t" + "11g" + "\t" + str(count1) + "\t\t" + str(
                "%.2f" % ((count1 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 1")
        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation1 / count1) * 100)) + "%" + "\t\t\t" + str(fragmentation1) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")
        try:
            file.write("\n2    Mbps" + "\t" + "11g" + "\t" + str(count2) + "\t\t" + str(
                "%.2f" % ((count2 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 2")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation2 / count2) * 100)) + "%" + "\t\t\t" + str(fragmentation2) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n5.5  Mbps" + "\t" + "11g" + "\t" + str(count3) + "\t\t" + str(
                "%.2f" % ((count3 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 5.5")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation5_5 / count3) * 100)) + "%" + "\t\t\t" + str(fragmentation5_5) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n6   Mbps" + "\t" + "11g" + "\t" + str(count4) + "\t\t" + str(
                "%.2f" % ((count4 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 11")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation6 / count4) * 100)) + "%" + "\t\t\t" + str(fragmentation6) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n6.5    Mbps" + "\t" + "0" + "\t" + str(count5) + "\t\t" + str(
                "%.2f" % ((count5 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 6")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation6_5 / count5) * 100)) + "%" + "\t\t\t" + str(fragmentation6_5) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n9    Mbps" + "\t" + "11g" + "\t" + str(count6) + "\t\t" + str(
                "%.2f" % ((count6 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 9")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation9 / count6) * 100)) + "%" + "\t\t\t" + str(fragmentation9) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n11   Mbps" + "\t" + "11g" + "\t" + str(count7) + "\t\t" + str(
                "%.2f" % ((count7 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 12")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation11 / count7) * 100)) + "%" + "\t\t\t" + str(fragmentation11) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n12   Mbps" + "\t" + "11g" + "\t" + str(count8) + "\t\t" + str(
                "%.2f" % ((count8 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 18")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation12 / count8) * 100)) + "%" + "\t\t\t" + str(fragmentation12) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n13   Mbps" + "\t" + "1" + "\t" + str(count9) + "\t\t" + str(
                "%.2f" % ((count9 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 24")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation13 / count9) * 100)) + "%" + "\t\t\t" + str(fragmentation13) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n18   Mbps" + "\t" + "11g" + "\t" + str(count10) + "\t\t" + str(
                "%.2f" % ((count10 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 36")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation18 / count10) * 100)) + "%" + "\t\t\t" + str(fragmentation18) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n19.5   Mbps" + "\t" + "2" + "\t" + str(count11) + "\t\t" + str(
                "%.2f" % ((count11 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 48")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation19_5 / count11) * 100)) + "%" + "\t\t\t" + str(fragmentation19_5) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n24   Mbps" + "\t" + "11g" + "\t" + str(count12) + "\t\t" + str(
                "%.2f" % ((count12 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 54")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation24 / count12) * 100)) + "%" + "\t\t\t" + str(fragmentation24) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n26  Mbps" + "\t" + " 3 " + "\t" + str(count13) + "\t\t" + str(
                "%.2f" % ((count13 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 6.5")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation26 / count13) * 100)) + "%" + "\t\t\t" + str(fragmentation26) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n36   Mbps" + "\t" + " 1 " + "\t" + str(count14) + "\t\t" + str(
                "%.2f" % ((count14 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("\t\t\tzero packets with data rate 13")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation36 / count14) * 100)) + "%" + "\t\t\t" + str(fragmentation36) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n39 Mbps" + "\t" + " 4 " + "\t" + str(count15) + "\t\t" + str(
                "%.2f" % ((count15 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 19.5")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation39 / count15) * 100)) + "%" + "\t\t\t" + str(fragmentation39) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n48   Mbps" + "\t" + " 11g " + "\t" + str(count16) + "\t\t" + str(
                "%.2f" % ((count16 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 26")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation48 / count16) * 100)) + "%" + "\t\t\t" + str(fragmentation48) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n52   Mbps" + "\t" + " 5 " + "\t" + str(count17) + "\t\t" + str(
                "%.2f" % ((count17 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 39")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation52 / count17) * 100)) + "%" + "\t\t\t" + str(fragmentation52) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n54   Mbps" + "\t" + " 11g " + "\t" + str(count18) + "\t\t" + str(
                "%.2f" % ((count18 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 52")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation54 / count18) * 100)) + "%" + "\t\t\t" + str(fragmentation54) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n58.5 Mbps" + "\t" + " 6 " + "\t" + str(count19) + "\t\t" + str(
                "%.2f" % ((count19 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 58.5")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation58_5 / count19) * 100)) + "%" + "\t\t\t" + str(fragmentation58_5) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")

        try:
            file.write("\n65   Mbps" + "\t" + " 7 " + "\t" + str(count20) + "\t\t" + str(
                "%.2f" % ((count20 / count) * 100)) + "%")
        except ZeroDivisionError:
            file.write("zero packets with data rate 65")

        try:
            file.write("\t\t\t" + str("%.2f" % ((fragmentation65 / count20) * 100)) + "%" + "\t\t\t" + str(fragmentation65) + "\n")
        except ZeroDivisionError:
            file.write("\t\t\tzero fragmentation bits")
        file.write("\nfile closed properly")
        file.close()
        return 0


if __name__ == "__main__":
    # rint("hello Mehul")
    if len(sys.argv) < 4:
        # if len(sys.argv) < 5:
        # print("no. of parameter are less")
        # sys.exit(1)

        print("usage: python {} T2[Serial Port]".format(prog))
        sys.exit(1)
    prog = os.path.basename(sys.argv[0])
    Tshark_path = sys.argv[1]
    Pcap_file_path = sys.argv[2]
    mac_addr1 = sys.argv[3]
    mac_addr2 = sys.argv[4]
    print("Tshark_path::", Tshark_path, "pcapfilePath::", Pcap_file_path, "MAC1::", type(mac_addr1), "MAC2::",
          type(mac_addr2))
    fragments(Tshark_path, Pcap_file_path, mac_addr1, mac_addr2)

    # serialPort = sys.argv[1]
    # initialize_t2_qfn42_v8(serialPort)

