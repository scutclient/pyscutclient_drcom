# pyscutclient_drcom

早起版本，仅供测试使用。

使用方法：

首先下载pyscutclient_drcom.py文件。然后执行

`sudo python pyscutclient_drcom.py --username USERNAME [--password PASSWORD] [--iface IFACE]`

其中iface如eth0、eth1。省略则默认为eth0。



在使用前需要先[安装scapy的依赖包](http://www.secdev.org/projects/scapy/doc/installation.html#platform-specific-instructions)

再安装scapy：

`sudo apt-get install python-pip`

`sudo pip install scapy`

在Python 2.7 + 64bit Debian/Ubuntu 测试成功。
