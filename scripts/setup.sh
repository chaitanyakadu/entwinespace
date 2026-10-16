#!/bin/bash

tput blink setaf 3; printf "Note: Use this in-case of development only!\n\n"; tput sgr0;

path=$PWD

echo "Reading the env variables..."
cd "$path"
set -a
source .env
set +a

echo "Starting the docker containers"
cd "$path/docker"
docker compose up -d
cd -

# todo - the migrations should be applied only if the postgres container health is runnning
echo "Run sqlx migrations"
cd "$path/packages/db"
sqlx migrate run --database-url="$DATABASE_URL"

exit 0

