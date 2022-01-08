# FraudCapturer
 
> FraudCapturer is a Windows application that analyzes your PC's network traffic and blocks potential threats.

## Usage

1. Download one of the [releases](https://github.com/Stone-Red-Code/FraudCapturer/releases)
1. Download and install [nmap](https://nmap.org/download.html)
1. (Not reqired but recommended) Get a [proxycheck.io](https://proxycheck.io/) api key
1. Start `FraudCapturer.exe` as administrator and pass the proxycheck api key to it if you have one
1. Select the network device you want the program to listen to

## Additional information

1. Why do I need to install nmap?\
   It is required because FraudCapturer uses it to monitor incoming and outgoing packets.\
   FraudCapturer uses the [sharppcap](https://github.com/dotpcap/sharppcap) ([license](https://github.com/dotpcap/sharppcap/blob/master/LICENSE)) library to communicate with nmap.

1. Does FraudCapturer send all packet contents to the APIs?\
   No, only the required information (IP addresses/domains) and the PC name to identify the device are sent to the APIs.

1. How does FraudCapturer determine which IP addresses or domains are potential threats?\
   It uses the [proxycheck.io](https://proxycheck.io/) and [Anti-Fish](https://anti-fish.bitflow.dev/) APIs.\
   You can even add custom rules in the [proxycheck.io API dashboard](https://proxycheck.io/dashboard/) to block or allow certain IPs and providers

1. Why does FraudCapturer need administrator rights?\
   FraudCapturer needs them because it uses the Windows firewall to block IP addresses.
