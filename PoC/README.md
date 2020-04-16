# PoC

Emulate an Off-Card Entity communicating with a smart card through a reader. 

We artificially intercept the encrypted messages exchanged during SCP10 key exchange, and perform two attacks:
* Coppersmith's attack on e=3, with a deterministic padding
* Bleichenbacher's attack exploiting the Perform Security Operation [decipher] APDU

Various adaptations and optimizations have been added to these attacks. More details are available on our paper.

## Usage

First, you need to have a smart card with our SCP10Applet installed. Next, you need to connect a card reader to your computer.

Some needed Python packages are listed in the `requirements.txt`, and you need to have SageMath installed.

Then, you can simply launch 
```bash
poc.py
```

The script goes as follow:
1. Load certificates from the [_data](_data/) directory.
2. Initiate communication with the card (as a legitimate user), selecting the appropriate applet (you can modify AID if needed).
3. Play a legitimate SCP10 key exchange with the card, saving the ciphertext of the Perform Security Operation [decipher] APDU.
4. Perform the attacks on the aformentionned ciphertext.
