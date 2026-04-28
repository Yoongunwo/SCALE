cat << 'bashScript' > remote_access.sh

apt update
apt install tmate -y

tmate

bashScript

chmod +x remote_access.sh

./remote_access.sh