# IP2Location Traceroute

IP2Location is a tool allowing user to get IP address information such as country, region, city, 
latitude, longitude, zip code, time zone, ISP, domain name, connection type, area code, weather, 
mobile network, elevation, usage type from traceroute probes IP address.



### Installation

1. Download the latest IP2Location C library from https://github.com/chrislim2888/IP2Location-C-Library Follow the instructions to compile and install the library.

2. Download or clone this repository to your local machine.

   ```bash
   wget https://github.com/ip2location/ip2location-traceroute/archive/master.zip
   unzip master.zip && rm master.zip
   cd ip2location-traceroute-master
   ```

3. Start compilation and installation.

   ```bash
   make
   make install
   ```

   


Usage
-----
```bash
ip2trace -p [IP ADDRESS/HOSTNAME] -d [IP2LOCATION BIN DATA PATH] [OPTIONS]

  -d, --dababase
  Specify the path of IP2Location BIN database file.

  -h, -?, --help
  Display this guide.

  -p, --ip
  Specify an IP address or hostname.

  -t, --ttl
  Set the maxinum TTL for each probe.

  -v, --version
  Print the version of the IP2Location version.
```



#### Example

Traceroute an IP address.

```bash
ip2trace -p 8.8.8.8 -d /usr/share/ip2location/DB3.BIN
```



Traceroute by hostname

```bash
ip2trace -p google.com -d /usr/share/ip2location/DB3.BIN
```




Download IP2Location Databases  
------------------------------  
* Download free IP2Location LITE databases at [https://lite.ip2location.com](https://lite.ip2location.com)  
* For more accurate commercial database, please refer to https://www.ip2location.com

One you have obtained your download token, you can download the the database using **wget** as below:

```
wget "https://www.ip2location.com/download?token={DOWNLOAD_TOKEN}&file={DATABASE_CODE}"
```



Support 
------- 
Email: support@ip2location.com  
URL: https://www.ip2location.com  
