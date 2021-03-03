# vcn - CodeNotary Ledger Compliance jumpstart

## Table of contents

- [CodeNotary Ledger Compliance](#codenotary-ledger-compliance)
- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Documentation](#documentation)

## CodeNotary Ledger Compliance

vcn has been extended in order to be compatible with [CodeNotary Ledger Compliance](https://codenotary.com/) .
Notarized assets informations are stored in a tamperproof ledger with cryptographic verification backed by [immudb](https://codenotary.com/technologies/immudb/), the immutable database.
Thanks to this `vcn` is faster and provides more powerful functionalities like local data inclusion, consistency verification and enhanced CLI filters.

### Obtain an API Key
To provide access to Ledger Compliance a valid API Key is required.
This API Key is bound to a specific Ledger and it's required during vcn login.
To obtain a valid key you need to get access to a licensed CodeNotary Ledger Compliance installation.


## Quick start

1. **Download CodeNotary vcn.** There are releases for different platforms:

- [Download the latest release](https://github.com/vchain-us/vcn/releases/latest) and then read the [Usage](#usage) section below.
- We recommend storing `vcn` in your `PATH` - Linux example:
   ```bash
   cp vcn-v<version>-linux-amd64 /usr/local/bin/vcn
   ```

2. **Authenticate digital objects** You can use the command as a starting point.

   ```bash
   vcn login --lc-host cnlc-host.com --lc-port 443
   vcn authenticate <file|dir://directory|docker://dockerimage|git://gitdirectory>
   ```


3. **Notarize existing digital objects** Once you have an account you can start notarizing digital assets to give them an identity.

   ```bash
   # vcn login can be skipped, if already performed
   vcn login --lc-host cnlc-host.com --lc-port 443
   vcn notarize <file|dir://directory|docker://dockerimage|git://gitdirectory>
   ```

### Login

To login in Ledger Compliance provides `--lc-port` and `--lc-host` flag, also the user submit API Key when requested.
Once host, port and API Key are provided, it's possible to omit them in following commands. Otherwise, the user can provide them in other commands like `notarize`, `verify` or `inspect`.

```shell script
vcn login --lc-port 443 --lc-host cnlc-host.com
```

> One time password (otp) is not mandatory

Alternatively, for using vcn in non-interactive mode, the user can supply the API Key via the `VCN_LC_API_KEY` environment variable, e.g.:

```shell script
export VCN_LC_API_KEY=apikeyhere

# No vcn login command needed

# Other vcn commands...
vcn notarize asset.txt --lc-host cnlc-host.com --lc-port 443
```

#### TLS

By default, vcn will try to establish a secure connection (TLS) with a Ledger Compliance server.

The user can also provide a custom TLS certificate for the server, in case vcn is not able to download it automatically:

```shell script
vcn login --lc-port 443 --lc-host cnlc-host.com --lc-cert mycert.pem
```

For testing purposes or in case the provided certificate should be always trusted by the client, the user can
configure vcn to skip TLS certificate verification with the `--lc-skip-tls-verify` option:

```shell script
vcn login --lc-port 443 --lc-host cnlc-host.com --lc-cert mycert.pem --lc-skip-tls-verify
```

Finally in case the Ledger Compliance Server is not exposed through a TLS endpoint, the user can request a cleartext
connection using the `--lc-no-tls` option:

```shell script
vcn login --lc-port 80 --lc-host cnlc-host.com --lc-no-tls
```

## Installation

### Download binary

It's easiest to download the latest version for your platform from the [release page](
https://github.com/vchain-us/vcn/releases).

Once downloaded, you can rename the binary to `vcn`, then run it from anywhere.
> For Linux and macOS you need to mark the file as executable: `chmod +x vcn`

### Homebrew / Linuxbrew

If you are on macOS and using [Homebrew](https://brew.sh/) (or on Linux and using [Linuxbrew](https://linuxbrew.sh/)), you can install `vcn` with the following:

```
brew tap vchain-us/brew
brew install vcn
```

### Build from Source

After having installed [golang](https://golang.org/doc/install) 1.12 or newer clone this
repository into your working directory.

Now, you can build `vcn` in the working directory by using `make vcn` and then run `./vcn`.

Alternatively, you can install `vcn` in your system simply by running `make install`. This will put the `vcn` executable into `GOBIN` which is
accessible throughout the system.

## Usage

Basically, `vcn` can notarize or authenticate any of the following kind of assets:

- a **file**
- an entire **directory** (by prefixing the directory path with `dir://`)
- a **git commit** (by prefixing the local git working directory path with `git://`)
- a **container image** (by using `docker://` or `podman://` followed by the name of an image present in the local registry of docker or podman, respectively)

It's possible to provide a hash value directly by using the `--hash` flag.

For detailed **command line usage** see [docs/cmd/vcn.md](https://github.com/vchain-us/vcn/blob/master/docs/cmd/vcn.md) or just run `vcn help`.

### Wildcard support and recursive notarization

It's also possible to notarize assets using a wildcard pattern.

With `--recursive` flag the utility can recursively notarize inner directories.
```shell script
./vcn n "*.md" --recursive
```
### Notarization

Start with the `login` command. `vcn` will walk you through login and importing up your secret upon initial use.

```
vcn login --lc-host cnlc-host.com --lc-port 443
```

Once your secret is set you can notarize assets like in the following examples:

```
vcn notarize <file>
vcn notarize dir://<directory>
vcn notarize docker://<imageId>
vcn notarize podman://<imageId>
vcn notarize git://<path_to_git_repo>
vcn notarize --hash <hash>
```

Change the asset's status:

```
vcn unsupport <asset>
vcn untrust <asset>
```

Finally, to fetch all assets you've notarized:

```
vcn list
```

### Authentication

```
vcn authenticate <file>
vcn authenticate dir://<directory>
vcn authenticate docker://<imageId>
vcn authenticate podman://<imageId>
vcn authenticate git://<path_to_git_repo>
vcn authenticate --hash <hash>
```

To output results in `json` or `yaml` formats:
```
vcn authenticate --output=json <asset>
vcn authenticate --output=yaml <asset>
```
> Check out the [user guide](https://github.com/vchain-us/vcn/blob/master/docs/user-guide/formatted-output.md) for further details.

## Documentation

* [Command line usage](https://github.com/vchain-us/vcn/blob/master/docs/cmd/vcn.md)
* [Configuration](https://github.com/vchain-us/vcn/blob/master/docs/user-guide/configuration.md)
* [Environments](https://github.com/vchain-us/vcn/blob/master/docs/user-guide/environments.md)
* [Formatted output (json/yaml)](https://github.com/vchain-us/vcn/blob/master/docs/user-guide/formatted-output.md)
* [Notarization explained](https://github.com/vchain-us/vcn/blob/master/docs/user-guide/notarization.md)

## Examples

#### Authenticate a Docker image automatically prior to running it

First, you’ll need to pull the image by using:

```
docker pull hello-world
```

Then use the below command to put in place an automatic safety check. It allows only verified images to run.

```
vcn authenticate docker://hello-world && docker run hello-world
```
If an image was not verified, it will not run and nothing will execute.


#### Authenticate multiple assets
You can authenticate multiple assets by piping other command outputs into `vcn`:
```
ls | xargs -n 1 vcn authenticate
```
> The exit code will be `0` only if all the assets in you other command outputs are verified.

#### Authenticate by a specific signer
By adding `--signerID`, you can authenticate that your asset has been signed by a specific SignerID.
> A SignerID is the signer public address (represented as a 40 hex characters long string prefixed with `0x`).

```
vcn authenticate --signerID 0x8f2d1422aed72df1dba90cf9a924f2f3eb3ccd87 docker://hello-world
```

#### Authenticate using the asset's hash

If you want to authenticate an asset using only its hash, you can do so by using the command as shown below:

```
vcn authenticate --hash fce289e99eb9bca977dae136fbe2a82b6b7d4c372474c9235adc1741675f587e
```

#### Unsupport/untrust an asset you do not have anymore

In case you want to unsupport/untrust an asset of yours that you no longer have, you can do so using the asset hash(es) with the following steps below.

First, you’ll need to get the hash of the asset from your CodeNotary Ledger Compliance dashboard or alternatively you can use the `vcn list` command. Then, in the CLI, use:

```
vcn untrust --hash <asset's hash>
# or
vcn unsupport --hash <asset's hash>
```

#### Notarization within automated environments

Simply, set up your environment accordingly using the following commands:

```bash
export VCN_LC_API_KEY=apikeyhere
```

Once done, you can use `vcn` in your non-interactive environment using:

```
vcn login --lc-host cnlc-host.com --lc-port 443
vcn notarize <asset>
```

> Other commands like `untrust` and `unsupport` will also work.


#### Add custom metadata when signing assets
The user can upload custom metadata when doing an asset notarization using the `--attr` option, e.g.:

```shell script
vcn n README.md --attr Testme=yes --attr project=5 --attr pipeline=test
```

This command would add the custom asset metadata Testme: yes, project: 5, pipeline: test.

The user can read the metadata back on asset authentication, i.e. using the `jq` utility:

```shell script
vcn a README.md -o json | jq .metadata
```

#### Inspect
Inspect has been extended with the addition of new filter: `--last`, `--first`, `--start` and `--end`.
With `--last` and `--first` are returned the N first or last respectively.

```shell script
vcn inspect document.pdf --last 10
```

With `--start` and `--end` it's possible to use a time range filter:

```shell script
vcn inspect document.pdf --start 2020/10/28-08:00:00 --end 2020/10/28-17:00:00
```

If no filters are provided only maximum 100 items are returned.

#### Signer Identifier
It's possible to filter results by signer identifier:

```shell script
vcn inspect document.pdf --signerID CygBE_zb8XnprkkO6ncIrbbwYoUq5T1zfyEF6DhqcAI=
```

### Local API server

Local API server is supported.
The `API Key` can be submitted with the `x-notarization-lc-api-key` header.

Notarize example:
```bash
curl --location --request POST '127.0.0.1:8082/notarize' \
--header 'x-notarization-lc-api-key: oikfnlbjinhhclvjiotckgwfuyfjxntxmcau' \
--header 'Content-Type: application/json' \
--data-raw '{
"Kind":"file",
"Name":"CONTRIBUTING.md",
"Hash":"e2b58ab102dbadb3b1fd5139c8d2a937dc622b1b0d0907075edea163fe2cd093",
"Size":1400,
"ContentType":"text/plain; charset=utf-8"
}'
```
Authenticate example:
```bash
curl --location --request GET '127.0.0.1:8081/authenticate/e2b58ab102dbadb3b1fd5139c8d2a937dc622b1b0d0907075edea163fe2cd093' \
--header 'x-notarization-lc-api-key: oikfnlbjinhhclvjiotckgwfuyfjxntxmcau'
```
Inspect example:
```bash
curl --location --request GET '127.0.0.1:8082/authenticate/e2b58ab102dbadb3b1fd5139c8d2a937dc622b1b0d0907075edea163fe2cd093' \
--header 'x-notarization-lc-api-key: oikfnlbjinhhclvjiotckgwfuyfjxntxmcau'
```
Inspect with signerID example:
```bash
curl --location --request GET '127.0.0.1:8081/inspect/e2b58ab102dbadb3b1fd5139c8d2a937dc622b1b0d0907075edea163fe2cd093?signerid=yZtm26ZgmZr37NQ41TXbJ2jStMVWZhE-3cp4Wb7gKQo=' \
--header 'x-notarization-lc-api-key: oikfnlbjinhhclvjiotckgwfuyfjxntxmcau'
```
Untrust example:
```bash
curl --location --request POST '127.0.0.1:8081/untrust' \
--header 'x-notarization-lc-api-key: oikfnlbjinhhclvjiotckgwfuyfjxntxmcau' \
--header 'Content-Type: application/json' \
--data-raw '{
	"Kind":		"file",
	"Name":		"CONTRIBUTING.md",
	"Hash":		"e2b58ab102dbadb3b1fd5139c8d2a937dc622b1b0d0907075edea163fe2cd093",
	"Size":		1400,
	"ContentType":	"text/plain; charset=utf-8"
}'
```
