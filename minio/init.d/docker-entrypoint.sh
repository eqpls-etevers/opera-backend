#!/bin/sh

# eqpls #########################
UERP_ENDPOINT="uerp:8080"
ORGANIZATION="eqpls"

echo -n "export MINIO_IDENTITY_OPENID_CLIENT_SECRET_PRIMARY_IAM=" > /client_secret
curl -s "http://$UERP_ENDPOINT/internal/client/secret?org=$ORGANIZATION&client=minio" >> /client_secret
. /client_secret
echo "MINIO_IDENTITY_OPENID_CLIENT_SECRET=$MINIO_IDENTITY_OPENID_CLIENT_SECRET_PRIMARY_IAM"
######################### eqpls #

# If command starts with an option, prepend minio.
if [ "${1}" != "minio" ]; then
	if [ -n "${1}" ]; then
		set -- minio "$@"
	fi
fi

docker_switch_user() {
	if [ -n "${MINIO_USERNAME}" ] && [ -n "${MINIO_GROUPNAME}" ]; then
		if [ -n "${MINIO_UID}" ] && [ -n "${MINIO_GID}" ]; then
			chroot --userspec=${MINIO_UID}:${MINIO_GID} / "$@"
		else
			echo "${MINIO_USERNAME}:x:1000:1000:${MINIO_USERNAME}:/:/sbin/nologin" >>/etc/passwd
			echo "${MINIO_GROUPNAME}:x:1000" >>/etc/group
			chroot --userspec=${MINIO_USERNAME}:${MINIO_GROUPNAME} / "$@"
		fi
	else
		exec "$@"
	fi
}

## DEPRECATED and unsupported - switch to user if applicable.
docker_switch_user "$@"
