#!/bin/bash

LOG_FILE=/var/log/myapp.log
! test -f ${LOG_FILE} && touch ${LOG_FILE}

iter=1
while getopts i: flag
do
    case "${flag}" in
        i) iter=${OPTARG};;
    esac
done

arr[0]="created"
arr[1]="read"
arr[2]="deleted"

for ((i=1;i<=$iter;i++))
do
  NOW=$(date '+%F %T.000 +0000')
  UUID=$(uuidgen)
  NUM=$(($RANDOM % 3))
  ACTION=${arr[$NUM]}
  POOL=$(( ( RANDOM % 10 )  + 1 ))
  THREAD=$(( ( RANDOM % 10 )  + 1 ))
  echo "INFO  [${NOW}] [pool-${POOL}-thread-${THREAD}] [] com.amazon.sqs.javamessaging.AmazonSQSExtendedClient: S3 object ${ACTION}, Bucket name: sqs-bucket, Object key: ${UUID}." | tee -a ${LOG_FILE}
  sleep 2
done

