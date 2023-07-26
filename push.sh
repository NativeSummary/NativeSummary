#!/bin/bash

docker tag ns nativesummary/nativesummary
docker push nativesummary/nativesummary
docker rmi nativesummary/nativesummary
