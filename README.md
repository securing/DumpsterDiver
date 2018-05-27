DumpsterDiver (by @Rzepsky)
========================================

DumpsterDiver is a tool used to analyze big volumes of various file types in search of hardcoded secret keys (e.g. AWS Access Key, Azure Share Key or SSH keys). Additionally, it allows creating a simple search rules with basic conditions (e.g. reports only csv file including at least 10 email addresses). 
The main idea of this tool is to detect any potential secret leaks.

### Key features:
* it uses Shannon Entropy to find private keys.
* it supports multiprocessing for analyzing files.
* it unpacks compressed archives (e.g. zip, tar.gz etc.)
* it supports advanced search using simple rules (details below)

### Usage

```
usage: DumpsterDiver.py [-h] -p LOCAL_PATH [-r] [-a]
```

### Command line options


* `-p LOCAL_PATH` - path to the folder containing files to be analyzed.
* `-r, --remove` - when this flag is set, then files which don't contain any secret (or anything interesting if `-a` flag is set) will be removed.
* `-a, --advance` - when this flag is set, then all files will be additionally analyzed using rules specified in 'rules.yaml' file.

### Pre-requisites
To run the DumpsterDiver you have to install python  libraries. You can do this by running the following command:

```
pip install -r requirements.txt
```
### Understanding config.yaml file
There is no single tool which fits for everyone's needs and the DumpsterDiver is not an exception here. So, in `config.yaml` file you can custom the program to search exactly what you want. Below you can find a description of each setting.

* `logfile` - specifies a file where logs should be saved.
* `excluded` - specifies file extensions which you don't want to omit during a scan. There is no point in searching for hardcoded secrets in picture or video files, right?
* `min_key_length` and `min_key_length` - specifies minimum and maximum length of the secret you're looking for. Depending on your needs this setting can greatly limit the amount of false positives. For example, the AWS secret has a length of 40 bytes so if you set `min_key_length` and `min_key_length` to 40 then the DumpsterDiver will analyze only 40 bytes strings. However, it won't take into account longer strings like Azure shared key or private SSH key.

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

### Future plans
The future of this project depends on you! I released it with just a basic functionality. However, if I receive a positive feedback from you (give a star to this repo, write me on twitter or just drop a mail) then I'll work further on this project (I just don't want to sit on it, if there gonna 3 people use this tool... hope you understand it). Some features which can be added (of course, feel free to let me know what features you're missing):
- create an AWS Lambda or Azure Functions 
- directly downloading files from URLS or storage providers (e.g. AWS, Azure, GCP, dropbox etc.)
- scan specific file/archive types
- add more advanced rules

### Contribution

Do you have better ideas? Wanna help in this project? Please contact me via twitter [@Rzepsky] ('https://twitter.com/Rzepsky') or drop me a message at pawel.rzepa@outlook.com and I would be more than happy to see here any contributors!


### License

See the LICENSE file.