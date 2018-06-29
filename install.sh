#! /bin/sh
apt-get install python conntrack net-utils

mkdir -p /usr/local/bin
mkdir -p /opt/check_providers
cp check_providers.py /opt/check_providers/check_providers.py
chmod +x /opt/check_providers/check_providers.py
ln -s /opt/check_providers/check_providers.py /usr/local/bin/check_providers

cp systemd/check_providers.service /lib/systemd/system/check_providers.service
cp sample/check-providers.ini /etc/check-providers.ini

echo Please modify configuration in /etc/check-providers.ini
echo Then enable service with: 
echo     systemctl enable check_providers
echo Check with 
echo     check_providers check
echo monitor (ie check and enable/disable if necessary) with 
echo     check_providers monitor
echo starts:
echo     systemctl start check_providers

