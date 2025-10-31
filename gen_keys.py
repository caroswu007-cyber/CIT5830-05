from eth_account import Account
from eth_account.messages import encode_defunct
import eth_account
import os


def get_keys(filename: str = "secret_key.txt"):
    """
 
    """
    if os.path.exists(filename) and os.path.getsize(filename) > 0:
        with open(filename, "r") as f:
            sk = f.readline().strip()
        if not sk.startswith("0x"):
            sk = "0x" + sk
        return sk, Account.from_key(sk).address

    acct = Account.create()
    sk = acct.key.hex()
    addr = acct.address
    with open(filename, "w") as f:
        f.write(sk + "\n")
    return sk, addr


def sign_message(challenge, filename="secret_key.txt"):
    """

    """
    with open(filename, "r") as f:
        lines = f.readlines()
    assert len(lines) > 0, "Your account secret_key.txt is empty"

    sk = lines[0].strip()
    if not sk.startswith("0x"):
        sk = "0x" + sk

    account = eth_account.Account.from_key(sk)
    eth_addr = account.address

    message = encode_defunct(challenge)
    signed_message = eth_account.Account.sign_message(message, private_key=sk)

    recovered = eth_account.Account.recover_message(
        message, signature=signed_message.signature.hex()
    )
    assert recovered == eth_addr, "Failed to sign message properly"

    return signed_message, eth_addr


if __name__ == "__main__":

    pk, addr = get_keys()
    print("Private key saved to secret_key.txt")
    print("Address:", addr)


    sig, who = sign_message(b"bridge-project-challenge")
    print("Signed by:", who)
    print("Signature:", sig.signature.hex())
