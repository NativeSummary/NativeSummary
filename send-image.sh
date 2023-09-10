#!/bin/bash

ssh mobile docker image rm ns
docker save ns | pv | ssh mobile docker load
