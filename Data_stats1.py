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


def MCS_status(Tshark_path, Pcap_file_path, mac_addr1, mac_addr2):
    import sys
    import os
    from subprocess import Popen, PIPE

    os.system(
        Tshark_path + " -r " + Pcap_file_path + " -E header=y -E separator=/t -T fields -e frame.number -e wlan.sa -e wlan.da -e radiotap.datarate -e wlan.fc.type_subtype -e wlan.fcs.status -e wlan.fc.retry> pcap_text.txt")

    time.sleep(25)

    # Selecting desired packets with a known mac address
    ###########################################################################################################################
    def retry(line):
        #print("in retry function")
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
    retry1 = 0
    retry2 = 0
    retry5_5 = 0
    retry11 = 0
    retry6 = 0
    retry9 = 0
    retry12 = 0
    retry18 = 0
    retry24 = 0
    retry36 = 0
    retry48 = 0
    retry54 = 0
    retry6_5 = 0
    retry13 = 0
    retry19_5 = 0
    retry26 = 0
    retry39 = 0
    retry52 = 0
    retry58_5 = 0
    retry65 = 0
    UL1 = 0
    UL2 = 0
    UL5_5 = 0
    UL6 = 0
    UL6_5 = 0
    UL9 = 0
    UL11 = 0
    UL12 = 0
    UL13 = 0
    UL18 = 0
    UL19_5 = 0
    UL24 = 0
    UL26 = 0
    UL36 = 0
    UL39 = 0
    UL48 = 0
    UL52 = 0
    UL54 = 0
    UL58_5 = 0
    UL65 = 0
    DL1 = 0
    DL2 = 0
    DL5_5 = 0
    DL6 = 0
    DL6_5 = 0
    DL9 = 0
    DL11 = 0
    DL12 = 0
    DL13 = 0
    DL18 = 0
    DL19_5 = 0
    DL24 = 0
    DL26 = 0
    DL36 = 0
    DL39 = 0
    DL48 = 0
    DL52 = 0
    DL54 = 0
    DL58_5 = 0
    DL65 = 0
    DL_re1 = 0
    DL_re2 = 0
    DL_re5_5 = 0
    DL_re6 = 0
    DL_re6_5 = 0
    DL_re9 = 0
    DL_re11 = 0
    DL_re12 = 0
    DL_re13 = 0
    DL_re18 = 0
    DL_re19_5 = 0
    DL_re24 = 0
    DL_re26 = 0
    DL_re36 = 0
    DL_re39 = 0
    DL_re48 = 0
    DL_re52 = 0
    DL_re54 = 0
    DL_re58_5 = 0
    DL_re65 = 0
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
    with open('pcap_text.txt', 'rt') as myfile:

        for line in myfile:
            count += 1
            line1 = line.split('\t', 7)

            if (line.lower().find(substr) != -1 and line.lower().find(substra) != -1):

                packets.append(line.rstrip('\n'))
                # print(line)

                if line1[5] == '1' and line1[4] == '40' and data_rate(line) == 1:
                    packets1.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL1 += 1
                        if retry(line) == 1:
                            retry1 += 1
                    count1 += 1
                    if (line1[1]== substra):
                        DL1 +=1
                        if retry(line) == 1:
                            DL_re1 += 1

                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 2:
                    packets2.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL2 += 1
                        if retry(line) == 1:
                            retry2 += 1
                    count2 += 1
                    if (line1[1]== substra):
                        DL2 +=1
                        if retry(line) == 1:
                            DL_re2 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 5.5:
                    packets3.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL5_5 += 1
                        if retry(line) == 1:
                            retry5_5 += 1
                    count3 += 1
                    if (line1[1] == substra):
                        DL5_5 += 1
                        if retry(line) == 1:
                            DL_re5_5 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 6:
                    packets4.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL6 += 1
                        if retry(line) == 1:
                            retry6 += 1
                    count4 += 1
                    if (line1[1] == substra):
                        DL6 += 1
                        if retry(line) == 1:
                            DL_re6 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 6.5:
                    packets5.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL6_5 += 1
                        if retry(line) == 1:
                            retry6_5 += 1
                    count5 += 1
                    if (line1[1] == substra):
                        DL6_5 += 1
                        if retry(line) == 1:
                            DL_re6_5 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 9:
                    packets6.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL9 += 1
                        if retry(line) == 1:
                            retry9 += 1
                    count6 += 1
                    if (line1[1] == substra):
                        DL9 += 1
                        if retry(line) == 1:
                            DL_re9 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 11:
                    packets7.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL11 += 1
                        if retry(line) == 1:
                            retry11 += 1
                    count7 += 1
                    if (line1[1] == substra):
                        DL11 += 1
                        if retry(line) == 1:
                            DL_re11 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 12:
                    packets8.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL12 += 1
                        if retry(line) == 1:
                            retry12 += 1
                    count8 += 1
                    if (line1[1] == substra):
                        DL12 += 1
                        if retry(line) == 1:
                            DL_re12 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 13:
                    packets9.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL13 += 1
                        if retry(line) == 1:
                            retry13 += 1
                    count9 += 1
                    if (line1[1] == substra):
                        DL13 += 1
                        if retry(line) == 1:
                            DL_re13 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 18:
                    packets10.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL18 += 1
                        if retry(line) == 1:
                            retry18 += 1
                    count10 += 1
                    if (line1[1] == substra):
                        DL18 += 1
                        if retry(line) == 1:
                            DL_re18 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 19.5:
                    packets11.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL19_5 += 1
                        if retry(line) == 1:
                            retry19_5 += 1
                    count11 += 1
                    if (line1[1] == substra):
                        DL19_5 += 1
                        if retry(line) == 1:
                            DL_re19_5 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 24:
                    packets12.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL24 += 1
                        if retry(line) == 1:
                            retry24 += 1
                    count12 += 1
                    if (line1[1] == substra):
                        DL24 += 1
                        if retry(line) == 1:
                            DL_re24 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 26:
                    packets13.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL26 += 1
                        if retry(line) == 1:
                            retry26 += 1
                    count13 += 1
                    if (line1[1] == substra):
                        DL1 += 1
                        if retry(line) == 1:
                            DL_re1 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 36:
                    packets14.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL36 += 1
                        if retry(line) == 1:
                            retry36 += 1
                    count14 += 1
                    if (line1[1] == substra):
                        DL36 += 1
                        if retry(line) == 1:
                            DL_re36 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 39:
                    packets15.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL39 += 1
                        if retry(line) == 1:
                            retry39 += 1
                    count15 += 1
                    if (line1[1] == substra):
                        DL39 += 1
                        if retry(line) == 1:
                            DL_re39 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 48:
                    packets16.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL48 += 1
                        if retry(line) == 1:
                            retry48 += 1
                    count16 += 1
                    if (line1[1] == substra):
                        DL48 += 1
                        if retry(line) == 1:
                            DL_re48 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 52:
                    packets17.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL52 += 1
                        if retry(line) == 1:
                            retry52 += 1
                    count17 += 1
                    if (line1[1] == substra):
                        DL52 += 1
                        if retry(line) == 1:
                            DL_re52 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 54:
                    packets18.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL54 += 1
                        if retry(line) == 1:
                            retry54 += 1
                    count18 += 1
                    if (line1[1] == substra):
                        DL54 += 1
                        if retry(line) == 1:
                            DL_re54 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 58.5:
                    packets19.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL58_5 += 1
                        if retry(line) == 1:
                            retry58_5 += 1
                    count19 += 1
                    if (line1[1] == substra):
                        DL58_5 += 1
                        if retry(line) == 1:
                            DL_re58_5 += 1
                elif line1[5] == '1' and line1[4] == '40' and data_rate(line) == 65:
                    packets20.append(line.rstrip('\n'))
                    if (line1[1]== substr):
                        UL65 += 1
                        if retry(line) == 1:
                            retry65 += 1
                    count20 += 1
                    if (line1[1] == substra):
                        DL65 += 1
                        if retry(line) == 1:
                            DL_re65 += 1
    count = (
            count1 + count2 + count3 + count4 + count5 + count6 + count7 + count8 + count9 + count10 + count11 + count12 + count13 + count14 + count15 + count16 + count17 + count18 + count19 + count20)
    retry = (
            retry1 + retry2 + retry5_5 + retry11 + retry6 + retry9 + retry12 + retry18 + retry24 + retry36 + retry48 + retry54 + retry6_5 + retry13 + retry19_5 + retry26 + retry39 + retry52 + retry58_5 + retry65)
    UL = (UL1+UL2+UL5_5+UL11+UL6+UL9+UL12+UL18+UL24+UL36+UL48+UL54+UL6_5+UL13+UL19_5+UL26+UL39+UL52+UL58_5+UL65)
    DL = (DL1+DL2+DL5_5+DL11+DL6+DL9+DL12+DL18+DL24+DL36+DL48+DL54+DL6_5+DL13+DL19_5+DL26+DL39+DL52+DL58_5+DL65)
    DLre = (
                DL_re1 + DL_re2 + DL_re5_5 + DL_re11 + DL_re6 + DL_re9 + DL_re12 + DL_re18 + DL_re24 + DL_re36 + DL_re48 + DL_re54 + DL_re6_5 + DL_re13 + DL_re19_5 + DL_re26 + DL_re39 + DL_re52 + DL_re58_5 + DL_re65)
    print(DLre)
    # file1 = open("../test_results/result1.txt", 'w')
    # sys.stdout = file1
    with open('result1.txt', 'w') as file:
        file.write("\t\t\t\t\t"+"***********************Data Rate Distribution*********************")
        file.write("\n")
        file.write("Source address:" + "  " + substr + "\n")
        file.write("destination address:" + "  " + substra)
        file.write("\n")
        file.write("Total QOS data packets:" + "\t" + str(count))
        file.write("\n")
        file.write("total UL packets"+"\t"+str(UL))
        file.write("\n")
        file.write("total UL retry packets:"+"\t"+str(retry))
        file.write("\n")
        file.write("total DL packets:"+"\t"+str(DL))
        file.write("\n")
        file.write("total DL retry packets:"+"\t"+str(DLre))

        file.write("\n\n")
        file.write(
            "Data Rate" + "\t" + "MCS" + " \t" + "Packet Count" +"\t" +"UL packets count" +" \t" +"UL packet % of total packets"+" \t"+ "UL retry packet"+"\t\t"+"UL retry %"+"\t" +"DL packets count" + "\t" +"DL packet % of total packets"+"\t"+ "DL retry packet"+"\t\t"+"DL retry %"+ "\n")
        try:
            file.write("\n1    Mbps" + "\t" + "11g" + "\t" + str(count1) + "\t\t" + str(UL1) +"\t\t\t" + str("%.2f" % ((UL1/UL)*100))+"%" +"\t\t\t\t" + str(retry1))
        except ZeroDivisionError:
            file.write("zero packets with data rate 1")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry1 / UL1) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL1) + "\t\t\t"+str("%.2f" % ((DL1/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re1))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re1 / DL1) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n2    Mbps" + "\t" + "11g" + "\t" + str(count2) + "\t\t" + str(UL2) +"\t\t\t" + str("%.2f" % ((UL2/UL)*100))+"%" +"\t\t\t\t" + str(retry2))
        except ZeroDivisionError:
            file.write("zero packets with data rate 2")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry2 / UL2) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL2) + "\t\t\t"+str("%.2f" % ((DL2/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re2))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re2 / DL2) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")

        try:
            file.write("\n5.5    Mbps" + "\t" + "11g" + "\t" + str(count3) + "\t\t" + str(UL5_5) +"\t\t\t" + str("%.2f" % ((UL5_5/UL)*100))+"%" +"\t\t\t\t" + str(retry5_5))
        except ZeroDivisionError:
            file.write("zero packets with data rate 5.5")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry5_5 / UL5_5) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL1) + "\t\t\t"+str("%.2f" % ((DL5_5/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re5_5))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re5_5 / DL5_5) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n6    Mbps" + "\t" + "11g" + "\t" + str(count4) + "\t\t" + str(UL6) +"\t\t\t" + str("%.2f" % ((UL6/UL)*100))+"%" +"\t\t\t\t" + str(retry6))
        except ZeroDivisionError:
            file.write("zero packets with data rate 6")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry6 / UL6) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL6) + "\t\t\t"+str("%.2f" % ((DL6/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re6))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re6 / DL6) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n6.5    Mbps" + "\t" + "0" + "\t" + str(count5) + "\t\t" + str(UL6_5) +"\t\t\t" + str("%.2f" % ((UL6_5/UL)*100))+"%" +"\t\t\t\t" + str(retry6_5))
        except ZeroDivisionError:
            file.write("zero packets with data rate 6.5")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry6_5 / UL6_5) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL6_5) + "\t\t\t"+str("%.2f" % ((DL6_5/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re6_5))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re6_5 / DL6_5) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n9    Mbps" + "\t" + "11g" + "\t" + str(count6) + "\t\t" + str(UL9) +"\t\t\t" + str("%.2f" % ((UL9/UL)*100))+"%" +"\t\t\t\t" + str(retry9))
        except ZeroDivisionError:
            file.write("zero packets with data rate 9")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry9 / UL9) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL9) + "\t\t\t"+str("%.2f" % ((DL9/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re9))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re9 / DL9) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n11    Mbps" + "\t" + "11g" + "\t" + str(count7) + "\t\t" + str(UL11) +"\t\t\t" + str("%.2f" % ((UL11/UL)*100))+"%" +"\t\t\t\t" + str(retry11))
        except ZeroDivisionError:
            file.write("zero packets with data rate 11")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry11 / UL11) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL11) + "\t\t\t"+str("%.2f" % ((DL11/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re11))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re11 / DL11) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n12    Mbps" + "\t" + "11g" + "\t" + str(count8) + "\t\t" + str(UL12) +"\t\t\t" + str("%.2f" % ((UL12/UL)*100))+"%" +"\t\t\t\t" + str(retry12))
        except ZeroDivisionError:
            file.write("zero packets with data rate 12")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry12 / UL12) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL12) + "\t\t\t"+str("%.2f" % ((DL12/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re12))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re12 / DL12) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n13    Mbps" + "\t" + "1" + "\t" + str(count9) + "\t\t" + str(UL13) +"\t\t\t" + str("%.2f" % ((UL13/UL)*100))+"%" +"\t\t\t\t" + str(retry13))
        except ZeroDivisionError:
            file.write("zero packets with data rate 13")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry13 / UL13) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL9) + "\t\t\t"+str("%.2f" % ((DL13/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re13))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re13 / DL13) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n18    Mbps" + "\t" + "11g" + "\t" + str(count10) + "\t\t" + str(UL18) +"\t\t\t" + str("%.2f" % ((UL18/UL)*100))+"%" +"\t\t\t\t" + str(retry18))
        except ZeroDivisionError:
            file.write("zero packets with data rate 18")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry18 / UL18) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL18) + "\t\t\t"+str("%.2f" % ((DL18/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re18))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re18 / DL18) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n19.5    Mbps" + "\t" + "2" + "\t" + str(count11) + "\t\t" + str(UL19_5) +"\t\t\t" + str("%.2f" % ((UL19_5/UL)*100))+"%" +"\t\t\t\t" + str(retry19_5))
        except ZeroDivisionError:
            file.write("zero packets with data rate 19.5")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry19_5 / UL19_5) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL19_5) + "\t\t\t"+str("%.2f" % ((DL19_5/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re19_5))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re19_5 / DL19_5) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n24    Mbps" + "\t" + "11g" + "\t" + str(count12) + "\t\t" + str(UL24) +"\t\t\t" + str("%.2f" % ((UL24/UL)*100))+"%" +"\t\t\t\t" + str(retry24))
        except ZeroDivisionError:
            file.write("zero packets with data rate 24")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry24 / UL24) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL24) + "\t\t\t"+str("%.2f" % ((DL24/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re24))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re24 / DL24) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n26    Mbps" + "\t" + "3" + "\t" + str(count13) + "\t\t" + str(UL26) +"\t\t\t" + str("%.2f" % ((UL26/UL)*100))+"%" +"\t\t\t\t" + str(retry26))
        except ZeroDivisionError:
            file.write("zero packets with data rate 26")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry26 / UL26) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL26) + "\t\t\t"+str("%.2f" % ((DL26/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re26))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re26 / DL26) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n36    Mbps" + "\t" + "11g" + "\t" + str(count14) + "\t\t" + str(UL36) +"\t\t\t" + str("%.2f" % ((UL36/UL)*100))+"%" +"\t\t\t\t" + str(retry36))
        except ZeroDivisionError:
            file.write("zero packets with data rate 36")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry36 / UL36) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL36) + "\t\t\t"+str("%.2f" % ((DL36/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re36))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re36 / DL36) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n39    Mbps" + "\t" + "4" + "\t" + str(count15) + "\t\t" + str(UL39) +"\t\t\t" + str("%.2f" % ((UL39/UL)*100))+"%" +"\t\t\t\t" + str(retry39))
        except ZeroDivisionError:
            file.write("zero packets with data rate 39")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry39 / UL39) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL39) + "\t\t\t"+str("%.2f" % ((DL39/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re39))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re39 / DL39) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n48    Mbps" + "\t" + "" + "\t" + str(count16) + "\t\t" + str(UL48) +"\t\t\t" + str("%.2f" % ((UL48/UL)*100))+"%" +"\t\t\t\t" + str(retry48))
        except ZeroDivisionError:
            file.write("zero packets with data rate 48")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry48 / UL48) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL48) + "\t\t\t"+str("%.2f" % ((DL48/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re48))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re48 / DL48) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n52    Mbps" + "\t" + "5" + "\t" + str(count17) + "\t\t" + str(UL52) +"\t\t\t" + str("%.2f" % ((UL52/UL)*100))+"%" +"\t\t\t\t" + str(retry52))
        except ZeroDivisionError:
            file.write("zero packets with data rate 52")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry52 / UL52) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL52) + "\t\t\t"+str("%.2f" % ((DL52/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re52))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re52 / DL52) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n54    Mbps" + "\t" + "11g" + "\t" + str(count18) + "\t\t" + str(UL54) +"\t\t\t" + str("%.2f" % ((UL54/UL)*100))+"%" +"\t\t\t\t" + str(retry54))
        except ZeroDivisionError:
            file.write("zero packets with data rate 54")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry54 / UL54) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL54) + "\t\t\t"+str("%.2f" % ((DL54/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re54))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re54 / DL54) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n58.5    Mbps" + "\t" + "6" + "\t" + str(count19) + "\t\t" + str(UL58_5) +"\t\t\t" + str("%.2f" % ((UL58_5/UL)*100))+"%" +"\t\t\t\t" + str(retry58_5))
        except ZeroDivisionError:
            file.write("zero packets with data rate 58.5")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry58_5 / UL58_5) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL58_5) + "\t\t\t"+str("%.2f" % ((DL58_5/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re58_5))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re58_5 / DL58_5) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")
        try:
            file.write("\n65    Mbps" + "\t" + "7" + "\t" + str(count20) + "\t\t" + str(UL65) +"\t\t\t" + str("%.2f" % ((UL65/UL)*100))+"%" +"\t\t\t\t" + str(retry65))
        except ZeroDivisionError:
            file.write("zero packets with data rate 65")
        try:
            file.write("\t\t\t" + str("%.2f" % ((retry65 / UL65) * 100)) + "%" )
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t\t"+str(DL65) + "\t\t\t"+str("%.2f" % ((DL65/DL)*100))+"%"+"\t\t\t\t"+ str(DL_re65))
        except ZeroDivisionError:
            file.write("\t\t\t"+"0%")
        try:
            file.write("\t\t" + str("%.2f" % ((DL_re65 / DL65) * 100))+"%")
        except ZeroDivisionError:
            file.write("\t\t"+"0%")


if __name__ == "__main__":
    # print("hello Mehul")
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
    MCS_status(Tshark_path, Pcap_file_path, mac_addr1, mac_addr2)

    # serialPort = sys.argv[1]
    # initialize_t2_qfn42_v8(serialPort)
