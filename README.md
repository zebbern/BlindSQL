<div align="center">

## Fast, and accurate blind SQL injection scanner! 

![prevent-sql-exploit-icon](https://github.com/user-attachments/assets/1a346eb4-63c9-465c-b4a5-235a69bdfaa5)

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Status](https://img.shields.io/badge/Status-Active-green)
![License](https://img.shields.io/badge/License-MIT-brightgreen)


#### Automate the detection of blind SQL injection vulnerabilities with ease!
 **[Features](#features)**  | **[Installation](#installation)**  | **[Tool Usage](#usage)**  | **[Tool-Preview](#tool-preview)**

</div>
  
## Features
- `Dynamic Baseline Measurement:` **Automatically determines a response time baseline for each target and calculates dynamic thresholds.**
- `Concurrent Scanning:` **Supports multi-threaded scanning for faster results.**
- `Interactive Live UI:` **Live interface with progress tracking and clickable hyperlinks to Sucessfull URLs+Payloads.**


## Installation
**Clone the repository & install dependencies:**

   ```bash
   git clone https://github.com/zebbern/BlindSQL.git
   cd BlindSQL
   pip install -r requirements.txt
   ```

## Usage

```bash
python blindsql.py
```

**Can also be ran with `Multiple Threads` Like this:**

```bash
python blindsql.py -u https://example.com/vulnerable.php?id= -t 10 -v
```
**If no payload file is specified using the `-p` flag, the tool will list all `.txt` files in the `payload` directory and prompt you to select one.**

## Tool-Preview
![image](https://github.com/user-attachments/assets/50406995-4e36-4df6-aed4-cabc898a81ca)

![image](https://github.com/user-attachments/assets/747d8592-0fba-4da7-b6ca-b395eccb798d)

## Contributing

**Contributions are welcome! Please open issues or submit pull requests for improvements!**

> [!WARNING]  
> These is intended for educational and ethical hacking purposes only. It should only be used to test systems you own or have explicit permission to test. Unauthorized use of third-party websites or systems without consent is illegal and unethical.


