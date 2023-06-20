# sss-distribute - Shamir Secret Sharing CLI

Distribute secrets across a group of people by using the [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing)
algorithm to break apart a secret into multiple parts, subsequently requiring a subset of the parts to recover the initial secret.

Common use cases for this would be admin credentials where you don't want one person to have the ability to act by themselves.

## Examples

### Encrypt data

Example: Alice, Bob and Charlie set up a shared account that grants super admin permissions to an external system - but they want to make sure there always needs to be a quorum to be able to access the super admin. So they take the shared account credentials and break it into 3 parts using SSS with a threshold of 2 parts.

```
$ echo "secret credentials" | ./sss-distribute encrypt --parts 3 --threshold 2                                                                                   git:main*
Share 1: 1ece3ac1f10ba356b5efdb83c83f093101d6aa0c
Share 2: 0c93c1e226ca7c7134d4c7646417ea2e13339433
Share 3: 95eea87d22753ccc9d8729e325584f548aa56042
```

Afterwards 2 people come together and decrypt the secret:

```
$ ./sss-distribute decrypt 1ece3ac1f10ba356b5efdb83c83f093101d6aa0c 0c93c1e226ca7c7134d4c7646417ea2e13339433
secret credentials

```

Example 2: Distribute directly to GPG keys:
Don't output the secret shares but encrypt them using `gpg` to the involved recipients provided gpg keys (so the encryptor doesn't get access to the shares)

> echo "secret credentials" | ./sss-distribute encrypt --parts 3 --threshold 2 --gpg alice@example.com bob@example.com charlie@example.com

Example 3: Encrypt a large file to multiple people
sss-distribute will generate a random symmetric GPG key to encrypt the input file to a secret armored file and then distribute the symmetric key across the `--parts` using SSS

```
./sss-distribute encrypt --parts 3 --threshold 2 --input secret.txt --encrypt                                                                                   git:main*
Encrypted input using GPG to secret.asc
Share 1: 6eb3c36d4ba0e4207d7e35a87353d23fa8
Share 2: 3705d539f12f1119bab4ea5f28eb352561
Share 3: 5ef8dc6c7d1efdd51321a129dbfdff5d23
```


## Acknowledgement

This tool ist mostly a wrapper around Hashicorps excellent implementation of [shamir secret sharing in Vault](https://github.com/hashicorp/vault/tree/main/shamir).

## License
sss-distribute is released under the MIT license. See LICENSE.txt


