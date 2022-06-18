FROM python

RUN apt-get update

RUN apt-get install python3-scapy -y

RUN apt-get install git -y

RUN chmod -R -777 /home/

RUN git clone https://github.com/Ashot-sd/sniff /home


CMD ["source /home/env/bin/activate", "python3", "/home/sniffer.py"]
