# SmartOTPs
Full implementation of SmartOTPs: An air-gapped 2-factor authentication for smart-contract wallets.
See our paper at [https://arxiv.org/pdf/1812.03598.pdf](https://arxiv.org/pdf/1812.03598.pdf)

# Configuration of the Authenticator

 
## A) Install authenticator into your smartphone:

    $ cd ./auth
    Install authenticator.apk on an Android phone or compile it yourself e.g. in Android Studio 
    
## B) Generate a seed at the authenticator App:
 	To generate seed, press 'rnd' button on main screen.
	Random generation of the seed is optional, any mnemonic sentence of length 12 words following BIP39 document will be accepted.
	(https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
    You can reset the authenticator anytime by pressing the 'Reset' button on main screen.

    
# Installation of the wallet

## A) OS: We recommend you to use debian-based Linux distribution.     

## B) Initialize wallet - run the client on the http://127.0.0.1:8080
    $ cd ./wallet/src
    $ npm install
    $ truffle compile
    $ cd ./app
    $ npm install
    $ npm run dev

# Interaction with the client (ROPSTEN network)
    
## A) Configuration of Metamask (a HD wallet for private keys)
    - Open browser that have Metamask installed (e.g., Firefox).
    - you can either: 
        a) use our testing Metamask account with seed: "valve mystery kid female economy shallow table path piano joke train expire" or 
        b) create your new one by following the guide of Metamask. Then create a few Ethereum accounts in Metamask, 
    - switch Metamask to network Ropsten     
    - if you do not have enough balance, send 1 ETH at one of your account in Metamask by https://faucet.ropsten.be/    
    
## B) Interaction with the client
    - point your browser to http://127.0.0.1:8080 and interact with the client    
    - if you opted for our Metamask account, then you can use some of our existing smart contract wallets
    - if you created your own metamask account and generated your own mnemonic seed at the authenticator device, then rewrite it to deploy form together with other required fields and deploy a new contract (it may take some time, ~30 sec) - check the status in Metamask.
    - interact with the smart-contract wallet
