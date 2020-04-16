# SCP10-attack

**None of the implementations in this repository shall be used in production.**

These tools are part of the SCP10 paper titled "*The Long and Winding Path to Secure Implementation of GlobalPlatform SCP10*" by Daniel De Almeida Braga, Pierre-Alain Fouque and Mohamed Sabt.

They gather different elements:
 * [SCP10Applet/](SCP10Applet/) contains a (semi-)compliant implementation of SCP10, to be deployed as an applet on a smart card. The implementation can be used to test the vulnerabilities described in our article.
 * [SCP10Applet_mitigated/](SCP10Applet_mitigated/) is based on the same implementation, but includes the mitigations we suggested to prevent the attacks. It can be deployed on a smart card as an applet in order to evaluate the overhead of the mitigations.
 * [PoC/](PoC/) contains python and sage code allowing to perform the attacks. Namely, it emulate an Off-Card Entity and manage APDU requests and responsse, following SCP10 workflow.
 * [Client_mitigated/](Client_mitigated/) contains python code to emulate an Off-card Entity communicating with the mitigated applet. Since the protocol workflow change a little, we had to implement a new client.
 
 Since SCP10 is a smart card protcol, both applets need a smart cards to be deployed, and you need a card reader to use the PoC.
 
 More details about each components are available on their respective directory.
