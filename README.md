DumpsterDiver (by @Rzepsky)
========================================

DumpsterDiver is a tool used to analyze big volumes of various file types in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. Additionally, it allows creating a simple search rules with basic conditions (e.g. reports only csv file including at least 10 email addresses).
The main idea of this tool is to detect any potential secret leaks. You can watch it in action in the [demo video](https://vimeo.com/272944858).

### Key features:
* it uses Shannon Entropy to find private keys.
* it supports multiprocessing for analyzing files.
* it unpacks compressed archives (e.g. zip, tar.gz etc.)
* it supports advanced search using simple rules (details below)
* it searches for hardcoded passwords
* it is fully customizable

### Usage

```
usage: DumpsterDiver.py [-h] -p LOCAL_PATH [-r] [-a]
```

### Basic command line options


* `-p LOCAL_PATH` - path to the folder containing files to be analyzed.
* `-r, --remove` - when this flag is set, then files which don't contain any secret (or anything interesting if `-a` flag is set) will be removed.
* `-a, --advance` - when this flag is set, then all files will be additionally analyzed using rules specified in 'rules.yaml' file.
*  `-s, --secret` - when this flag is set, then all files will be additionally analyzed in search of hardcoded passwords.
* `-o OUTFILE` -  output file in JSON format.

### Pre-requisites
To run the DumpsterDiver you have to install python  libraries. You can do this by running the following command:

```
pip install -r requirements.txt
```
If you have installed separately Python 2 and 3 then you should use `pip3` or `pip3.6`.  

### Customizing your search
There is no single tool which fits for everyone's needs and the DumpsterDiver is not an exception here. There are 3 ways to customize your search:

* using levels
* using command line parameters
* using `config.yaml` file

#### Customization via levels
By setting up  a level you can limit your findings (e.g. only to long keys, like SSH private keys) and in the same way limit the false positives. The level can be set from command line and below you cand find the detailed description of each choice:

* `--level 0` - searches for short (20-40 bytes long) keys, e.g. AWS Access Key ID. 
* `--level 1` - (default) searches for typical (40-70 bytes long) keys, e.g. AWS Secret Access Key or Azure Shared Key. 
* `--level 2` - searches for long (1000-1800 bytes long) keys, e.g. SSH private key
* `--level 3` - searches for any key (20-1800 bytes long), careful as it generates lots of false positives

#### Customization via command line parameters

* `--min-key MIN_KEY` - specifies the minimum key length to be analyzed (default is 20).
* `--max-key MAX_KEY` - specifies the maximum key length to be analyzed (default is 80).
* `--entropy ENTROPY` - specifies the edge of high entropy (default is 4.3).

This way is quite helpful when you know what you're looking for. Here are few examples:

* When you're looking for AWS Secret Access Key:

`python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 40 --max-key 40 --entropy 4.3` 

* When you're looking for Azure Shared Key:

`python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 66 --max-key 66 --entropy 5.1`

* When you're looking for SSH private key (by default RSA provate key is written in 76 bytes long strings):

`python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-key 76 --max-key 76 --entropy 5.1`

### Understanding config.yaml file
In `config.yaml` file you can custom the program to search exactly what you want. Below you can find a description of each setting.

* `logfile` - specifies a file where logs should be saved.
* `excluded` - specifies file extensions which you don't want to omit during a scan. There is no point in searching for hardcoded secrets in picture or video files, right?
* `min_key_length` and `min_key_length` - specifies minimum and maximum length of the secret you're looking for. Depending on your needs this setting can greatly limit the amount of false positives. For example, the AWS secret has a length of 40 bytes so if you set `min_key_length` and `min_key_length` to 40 then the DumpsterDiver will analyze only 40 bytes strings. However, it won't take into account longer strings like Azure shared key or private SSH key. Default values are `min_key_length = 40` and `min_key_length = 80` what is quite general and can generate false positives.
* `high_entropy_edge` - if the entropy of analyzed string equals or is higher than `high_entropy_edge`, then this string will be reported as a representation of high entropy. The default value `high_entropy_edge = 4.3` should work in most cases, however if you're getting too many false positives it is also worth trying increase this value.

### Advanced search:
The DumpsterDiver supports also an advanced search. Beyond a simple grepping with wildcards this tool allows you to create conditions. Let's assume you're searching for a leak of corporate emails. Additionaly, you're interested only in a big leaks, which contain at least 100 email addresses. For this purpose you should edit a 'rules.yaml' file in the following way:

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

### Finding hardcoded passwords
Using entropy for finding passwords isn't very effective as it generates a lot of false positives. This is why the DumpsterDiver uses a different attitude to find hardcoded passwords - it verifies the password complexity using [passwordmeter]('https://pypi.org/project/passwordmeter/'). To customize this search you can use the following commands:

* `--min-pass MIN_PASS` - specifies the minimum password length to be analyzed (default is 8). Requires adding `'-s'` flag to the syntax.
* `--max-pass MAX_PASS` - specifies the maximum password length to be analyzed (default is 12). Requires adding `'-s'` flag to the syntax.
* `--pass-complex {1,2,3,4,5,6,7,8,9}` - specifies the edge of password complexity between 1 (trivial passwords) to 9 (very complex passwords) (default is 8). Requires adding `'-s'` flag to the syntax.

For example if you want to find complex passwords (which contains uppercase, lowercase, special character, digit and is 10 to 15 characters long), then you can do it using the following command:
```
python3 DumpsterDiver.py -p [PATH_TO_FOLDER] --min-pass 10 --max-pass 15 --pass-complex 8
```

### Using Docker
A docker image is available for DumpsterDiver. Run it using:
```
docker run -v /path/to/my/files:/files --rm rzepsky/dumpsterdiver -p /files
```
If you want to override one of the configuration files (**config.yaml** or **rules.yaml**):
```
docker run -v /path/to/my/config/config.yaml:/config.yaml /path/to/my/config/rules.yaml:/rules.yaml -v /path/to/my/files:/files --rm rzepsky/dumpsterdiver -p /files
```
### Future plans
The future of this project depends on you! I released it with just a basic functionality. However, if I receive a positive feedback from you (give a star to this repo, write me on twitter or just drop a mail) then I'll work further on this project (I just don't want to sit on it, if there gonna 3 people use this tool... hope you understand it). Some features which can be added (of course, feel free to let me know what features you're missing):

- add more false positive filters
- create an AWS Lambda or Azure Functions
- directly downloading files from URLS or storage providers (e.g. AWS, Azure, GCP, dropbox etc.)
- scan specific file/archive types
- add more advanced rules

### Contribution

Do you have better ideas? Wanna help in this project? Please contact me via twitter [@Rzepsky](https://twitter.com/Rzepsky) or drop me a message at pawel.rzepa@outlook.com and I would be more than happy to see here any contributors!

### Special thanks
Here I'd like to thank so much all those who helped develop this project:

* [Stephen Sorriaux](https://github.com/StephenSorriaux)
* [Andres Riancho](https://twitter.com/w3af)
* [Damian Stygar](https://github.com/DahDev)

### License

See the LICENSE file.
