

<p align="center">
  <img src="./static/images/DumpsterDiver_logo.png" width="400" alt="DumpsterDiver_logo" />
</p>

DumpsterDiver (by @Rzepsky)
========================================

DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. Additionally, it allows creating a simple search rules with basic conditions (e.g. report only csv files including at least 10 email addresses).
The main idea of this tool is to detect any potential secret leaks. You can watch it in action in the [demo video](https://vimeo.com/398343810) or read about all its features in [this article](https://medium.com/@rzepsky/hunting-for-secrets-with-the-dumpsterdiver-93d38a9cd4c1).

<p align="center">
  <img src="https://github.com/xep624/DumpsterDiver/blob/master/static/images/dumpster_diver.png?raw=true" alt="DumpsterDiver" />
</p>

### Key features:
* it uses Shannon Entropy to find private keys,
* it searches through git logs,
* it unpacks compressed archives (e.g. zip, tar.gz etc.),
* it supports advanced search using simple rules (details below),
* it searches for hardcoded passwords,
* it is fully customizable.

### Usage

```
usage: DumpsterDiver.py [-h] -p LOCAL_PATH [-r] [-a] [-s] [-l [0,3]]
                        [-o OUTFILE] [--min-key MIN_KEY] [--max-key MAX_KEY]
                        [--entropy ENTROPY] [--min-pass MIN_PASS]
                        [--max-pass MAX_PASS]
                        [--pass-complex {1,2,3,4,5,6,7,8,9}]
                        [--grep-words GREP_WORDS [GREP_WORDS ...]]
                        [--exclude-files EXCLUDE_FILES [EXCLUDE_FILES ...]]
                        [--bad-expressions BAD_EXPRESSIONS [BAD_EXPRESSIONS ...]]
```


### Basic command line options


* `-p LOCAL_PATH` - path to the folder containing files to be analyzed.
* `-a, --advance` - when this flag is set, then all files will be additionally analyzed using rules specified in `rules.yaml` file.
* `-r, --remove` - when this flag is set, then files which don't contain any secret (or anything interesting if `-a` flag is set) will be removed.
*  `-s, --secret` - when this flag is set, then all files will be additionally analyzed in search of hardcoded passwords.
* `-o OUTFILE` -  output file in JSON format.

### Pre-requisites
To run the DumpsterDiver you have to install python  libraries. You can do this by running the following command:

```
$> pip install -r requirements.txt
```
If you have installed separately Python 2 and 3 then you should use `pip3` or `pip3.6`.  

### Customizing your search
There is no single tool which fits for everyone's needs and the DumpsterDiver is not an exception here. There are 3 ways to customize your search:

* using levels
* using command line parameters
* using `config.yaml` file

#### Customization via levels
By setting up  a level you can limit your findings (e.g. only to long keys, like SSH keys) and in the same way limit false positives. The level can be set from command line and below you can find the detailed description of each choice:

* `--level 0` - searches for short (20-40 bytes long) keys, e.g. AWS Access Key ID. 
* `--level 1` - (default) searches for typical (40-70 bytes long) keys, e.g. AWS Secret Access Key or Azure Shared Key. 
* `--level 2` - searches for long (1000-1800 bytes long) keys, e.g. SSH private key
* `--level 3` - searches for any key (20-1800 bytes long). Be careful with this setting, because it may generate lots of false positives.

#### Customization via command line parameters

* `--min-key MIN_KEY` - specifies the minimum key length to be analyzed (default is 20).
* `--max-key MAX_KEY` - specifies the maximum key length to be analyzed (default is 80).
* `--entropy ENTROPY` - specifies the edge of high entropy (default is 4.3).
* `--grep-words GREP_WORDS [GREP_WORDS ...]` - specifies the grep words to look for. Multiple words should be separated by space. Wildcards are supported. Requires adding `-a` flag to the syntax.

There is also added a separate script which allows you to count an entropy of a character in a single word. It will help you to better customize the DumpsterDiver to your needs. You can check it using the following command:

```
$> python3 entropy.py f2441e3810794d37a34dd7f8f6995df4
```

This way is quite helpful when you know what you're looking for. Here are few examples:

* When you're looking for AWS Secret Access Key:

`$> python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 40 --max-key 40 --entropy 4.3` 

* When you're looking for Azure Shared Key:

`$> python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 66 --max-key 66 --entropy 5.1`

* When you're looking for SSH private key (by default RSA private key is written in 76 bytes long strings):

`$> python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 76 --max-key 76 --entropy 5.1`

* When you're looking for any occurence of `aws_access_key_id` or `aws_secret_access_key`:

`$> python3 DumpsterDiver.py -p ./test/ --grep-words *aws_access_key_id* *aws_secret_access_key* -a`  

> Please note that wildcards before and after a grep word is used on purpose. This way expressions like `"aws_access_key_id"` or `aws_access_key_id=` will be also reported. 

##### Finding hardcoded passwords
Using entropy for finding passwords isn't very effective as it generates a lot of false positives. This is why the DumpsterDiver uses a different attitude to find hardcoded passwords - it verifies the password complexity using [passwordmeter]('https://pypi.org/project/passwordmeter/'). To customize this search you can use the following commands:

* `--min-pass MIN_PASS` - specifies the minimum password length to be analyzed (default is 8). Requires adding `-s` flag to the syntax.
* `--max-pass MAX_PASS` - specifies the maximum password length to be analyzed (default is 12). Requires adding `-s` flag to the syntax.
* `--pass-complex {1,2,3,4,5,6,7,8,9}` - specifies the edge of password complexity between 1 (trivial passwords) to 9 (very complex passwords) (default is 8). Requires adding `-s` flag to the syntax.

For example if you want to find complex passwords (which contains uppercase, lowercase, special character, digit and is 10 to 15 characters long), then you can do it using the following command:

`$> python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-pass 10 --max-pass 15 --pass-complex 8`


#####  Limiting scan 

You may want to skip scanning certain files. For that purpose you can use the following parameters:

* `--exclude-files` - specifies file names or extensions which shouldn't be analyzed. File extension should contain `.` character (e.g. `.pdf`). Multiple file names and extensions should be separated by space.

* `--bad-expressions` - specifies bad expressions. If the DumpsterDiver find such expression in a file, then this file won't be
analyzed. Multiple bad expressions should be separated by space.

> If you want to specify multiple file names, bad expressions or grep words using a separated file you can do it via the following bash trick:
> ```
> $> python3 DumpsterDiver.py -p ./test/ --exclude-files `while read -r line; do echo $line; done < blacklisted_files.txt`
> ```

#### Customization via config.yaml file
Instead of using multiple command line parameters you can specify values for all the above-mentioned parameters at once in `config.yaml` file.

### Advanced search:
The DumpsterDiver supports also an advanced search. Beyond a simple grepping with wildcards this tool allows you to create conditions. Let's assume you're searching for a leak of corporate emails. Additionaly, you're interested only in a big leaks, which contain at least 100 email addresses. For this purpose you should edit a `rules.yaml` file in the following way:

```
filetype: [".*"]
filetype_weight: 0
grep_words: ["*@example.com"]
grep_words_weight: 10
grep_word_occurrence: 100
```

Let's assume a different scenario, you're looking for terms "pass",  "password", "haslo", "hasło" (if you're analyzing polish company repository) in a `.db` or `.sql` file. Then you can achieve this by modifying a 'rules.yaml' file in the following way:

```
filetype: [".db", ".sql"]
filetype_weight: 5
grep_words: ["*pass*", "*haslo*", "*hasło*"]
grep_words_weight: 5
grep_word_occurrence: 1
```

Note that the rule will be triggered only when the total weight (`filetype_weight + grep_words_weight`) is `>=10`.

### Using Docker
A docker image is available for DumpsterDiver. Run it using:
```
$> docker run -v /path/to/my/files:/files --rm rzepsky/dumpsterdiver -p /files
```
If you want to override one of the configuration files (`config.yaml` or `rules.yaml`):
```
$> docker run -v /path/to/my/config/config.yaml:/config.yaml /path/to/my/config/rules.yaml:/rules.yaml -v /path/to/my/files:/files --rm rzepsky/dumpsterdiver -p /files
```

### Contribution

Do you have better ideas? Wanna help in this project? Please contact me via twitter [@Rzepsky](https://twitter.com/Rzepsky). I would be more than happy to see here any contributors!

### Special thanks
Here I'd like to thank so much all those who helped develop this project:

* [Stephen Sorriaux](https://github.com/StephenSorriaux)
* [Andres Riancho](https://twitter.com/w3af)
* [Damian Stygar](https://github.com/DahDev)
* [Disconnect3d](https://twitter.com/disconnect3d_pl)
* [johann](https://github.com/raztus)

### License

See the [LICENSE](./LICENSE) file.
