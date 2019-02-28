#!/bin/sh
#
# Copyright IBM Corp All Rights Reserved
#
# SPDX-License-Identifier: Apache-2.0
#
export FABRIC_ROOT=$PWD
export FABRIC_CFG_PATH=$PWD
CHANNEL_NAME=mychannel

# remove previous crypto material and config transactions
rm -fr ./artifacts/channel/crypto-config/*
rm -r ./artifacts/channel/*

# generate crypto material
echo
echo "##########################################################"
echo "##### Generate certificates using cryptogen tool #########"
echo "##########################################################"
CRYPTOGEN=$FABRIC_ROOT/bin/cryptogen
$CRYPTOGEN generate --config=./crypto-config.yaml
if [ "$?" -ne 0 ]; then
  echo "Failed to generate crypto material..."
  exit 1
fi

echo "##########################################################"
echo "#########  Generating Channel Artifacts ##############"
echo "##########################################################"

CONFIGTXGEN=$FABRIC_ROOT/bin/configtxgen

# generate genesis block for orderer
$CONFIGTXGEN -profile TwoOrgsOrdererGenesis -outputBlock ./artifacts/channel/genesis.block
if [ "$?" -ne 0 ]; then
  echo "Failed to generate orderer genesis block..."
  exit 1
fi

# generate channel configuration transaction
$CONFIGTXGEN -profile TwoOrgsChannel -outputCreateChannelTx ./artifacts/channel/mychannel.tx -channelID $CHANNEL_NAME
if [ "$?" -ne 0 ]; then
  echo "Failed to generate channel configuration transaction..."
  exit 1
fi

# generate anchor peer transaction
$CONFIGTXGEN -profile TwoOrgsChannel -outputAnchorPeersUpdate ./artifacts/channel/Org1MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org1MSP
if [ "$?" -ne 0 ]; then
  echo "Failed to generate anchor peer update for Org1..."
  exit 1
fi

# generate anchor peer transaction
$CONFIGTXGEN -profile TwoOrgsChannel -outputAnchorPeersUpdate ./artifacts/channel/Org2MSPanchors.tx -channelID $CHANNEL_NAME -asOrg Org2MSP
if [ "$?" -ne 0 ]; then
  echo "Failed to generate anchor peer update for Org2..."
  exit 1
fi


#Copy the certificates to the correct location and then delete the copy
cp -r crypto-config/ artifacts/channel/
rm -r crypto-config
