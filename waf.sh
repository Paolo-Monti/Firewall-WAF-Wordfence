#!/bin/bash

# Put inside the parenthesis the path of your Wordpress sites.
# By example, here we are assuming you have your sites under the path /var/www/vhosts/
# Hint: it would be useful creating symbolic links to shorten the paths

declare -a sites=(/var/www/vhosts/blog /var/www/vhosts/portal /var/www/vhosts/eshop)

# The following lines are optional and they are useful to avoid too many blocked IP.
# The default name Wordfence is assumed for the chain in case it was not possible
# to extract it from the configuration file waf.ini

###### BEGIN OPTIONAL #####
ini="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P)"/waf.ini
[ -f "$ini" ] && chain=$(sed -e 's|\s*$||' -nre 's|chain=\s*(.*)|\1|p' "$ini")
[ -z "$chain" ] && chain=Wordfence
iptables -F "$chain" &>/dev/null
#####  END OPTIONAL #####

# Loop to check the Wordpress sites included inside the array above

for i in ${sites[@]}
do
  php /your_path_to_this_package/waf.php "$i/wp-config.php"
done
