# LINFO1341-Project1

## Introduction
Here is the first project of the LINFO1341 course : Analyse d’applications réseaux (OneDrive) made by **LECHAT Jérôme [50351800]** & **DELSART Mathis [31302100]**.

Our captures are made with different OS (MacOS, Windows 10, Windows 11, Linux) and under different circumstances (Wifi, Ethernet)

## Filters used for the analysis
- **ip** -> Shows IPV4 packets.

- **ip.addr** == "*address*" -> Shows all packets where the given *address* occurs.

- **ipv6** -> Shows IPV6 packets.

- **ipv6.addr** == "*address*" -> Shows all packets where the given *address* occurs.

- **dns** -> Shows all DNS packets.

- **!dns** -> Shows all packets except DNS ones.

- **dns.flags.authoritative == 1** -> Shows all DNS packets having authoritative servers.

- **udp** -> Shows all UPD packets.

- **!udp** -> Shows all packets except UDP ones.

- **tls** -> Shows all TLS packets.

- **!tls** -> Shows all packets except TLS ones.

- **quic** -> Shows all QUIC packets.

- **!quic** -> Shows all packets except QUIC ones.

- **tls.handshake.extension_server_name** == "*server name*" -> Shows all packets containing the given *server name* in their handshake extension




## Scripts
### Capture Analyzer
For better manipulation, we made a script using pyshark allowing better packets filtering for this project, as a lot of 'useless' data can be found in our captures.

#### Setup
Before using our script, make sure pyshark is successfully installed in your machine : 

``` console
foo@bar:~$ pip3 install pyshark
```

Once done, you are good to go !

#### Start
To run this script, just locate yourself with the command prompt on the repertory containing the 'CaptureAnalyzer.py', then run this command :

``` python3
foo@bar:~$ python3 CaptureAnalyzer.py {your .pcap/.pcapng file} [option(s)]
```

Please note that at least an option must be given to work correctly.

#### Options
Different options are available :

- <ins>Capture DNS :</ins> This option will simply keep all DNS packets in the file given and will then give the query name address and the response address. Note that a specific IPV4 or IPV6 address can be given to filter the proccess.

``` python3
foo@bar:~$ python3 CaptureAnalyzer.py {your .pcap/.pcapng file} --dns
```

- <ins>Capture Net Layer :</ins> This option will simply count all packets in the file given. Note that a specific IPV4 or IPV6 address can be given to filter the process.

``` python3
foo@bar:~$ python3 CaptureAnalyzer.py {your .pcap/.pcapng file} --netlayer
```

- <ins>Capture TLS Version :</ins> This option will simply keep all packets having TLS protocol and will then give their version. Note that a specific IPV4 or IPV6 address can be given to filter the process.

``` python3
foo@bar:~$ python3 CaptureAnalyzer.py {your .pcap/.pcapng file} --tls
```

- <ins>Capture Global :</ins> This option will simply give all specific informations (Counter, DNS, TLS, ...) for every packet in the file given. Note that a specific IPV4 or IPV6 address can be given to filter the process.

``` python3
foo@bar:~$ python3 CaptureAnalyzer.py {your .pcap/.pcapng file} --glob
```

#### Custom IPV4/IPV6 address
After submitting your command, you will be asked if you want to enter a specific IPV4/IPV6 address.

#### Results
All your results will be saved in the "Results" directory located at the root of this project.

If you want to test, a few files in 'Captures' folder are available.


### Capture Plot
For better manipulation, we made a script using pyshark and matplotlib allowing better packets filtering for this project, as a lot of 'useless' data can be found in our captures.

#### Setup
Before using our script, make sure matplotlib is successfully installed in your machine : 

``` console
foo@bar:~$ pip3 install matplotlib
```

Once done, you are good to go !

#### Start
To run this script, just locate yourself with the command prompt on the repertory containing the 'CapturePlot.py', then run this command :

``` python3
foo@bar:~$ python3 CapturePlot.py {your .pcap/.pcapng file} [option(s)]
```

Please note that at least an option must be given to work correctly.

#### Options
Different options are available :

- <ins>DNS plot:</ins> This option will simply give a result and plot all DNS requests by time.

``` python3
foo@bar:~$ python3 CapturePlot.py {your .pcap/.pcapng file} --dns
```

- <ins>IPv4 and IPv6 plot:</ins> This option will simply give a result and plot all proportion of IPv4 and IPv6 packets found in the file given.

``` python3
foo@bar:~$ python3 CapturePlot.py {your .pcap/.pcapng file} --ip
```

- <ins>Protocol plot:</ins> This option will simply give a result and plot all proportion of each transport protocol found in the file given.

``` python3
foo@bar:~$ python3 CapturePlot.py {your .pcap/.pcapng file} --protocol
```

#### Results
All your results will be saved in the "Results" directory located at the root of this project.

If you want to test, a few files in 'Captures' folder are available.





## Capture SSL
Pour faire des capture SSL, procédez comme suit:
- Fermez un maximum d'application
- Lancer Wireshark et le record
- Ouvrir le Terminal
- Ecrire cette commande (for MacOS): 
SSLKEYLOGFILE=*path/to/keylog* open -a Applications/*votre browser*
- Aller sur votre application web et faire vos manipulations
- Fermer le Browser
- Couper la capture Wireshark (attendez quelques secondes après avoir coupé le browser pour capturer les derniers paquets qui prendraient plus de temps à arriver)

Une fois la cpature coupée, afin de décrypter les requêtes SSL : 
- Allez dans edit -> preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename et mettez-y le chemin dans lequel vous avez enregistré votre SSLKEYLOGFILE
