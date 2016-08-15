# pyscutclient_drcom

早期版本，仅供测试使用。

使用方法：

首先下载pyscutclient_drcom.py文件。然后执行

`sudo python pyscutclient_drcom.py --username USERNAME [--password PASSWORD] [--iface IFACE]`

其中iface如eth0、eth1。省略则默认为eth0。



在使用前需要先[安装scapy的依赖包](http://www.secdev.org/projects/scapy/doc/installation.html#platform-specific-instructions)

再安装scapy：

`sudo apt-get install python-pip`

`sudo pip install scapy`

本程序在Python 2.7环境下开发。

感谢华工路由器群等的各种帮助，群号262939451。


Windows环境可以试试[安装scapy的Windows依赖](https://github.com/Kondziowy/scapy_win64)，它适用于Python 2.7，我试了似乎可以用。

先装Python 2.7，再装Windows依赖。
