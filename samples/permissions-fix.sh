#!/bin/sh
# The usual answer to "permission denied": open the directory to everyone,
# hand it to another account, and leave the web server to it.
sudo chmod -R 777 /var/www/html
sudo chown -R www-data /var/www/html
sudo systemctl restart nginx
