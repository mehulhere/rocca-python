# Rocca Cipher

An AES-based authenticated encryption scheme designed for ultra-fast performance in 6G systems. Rocca aims to achieve high-speed software implementations by fully leveraging AES-NI and SIMD instructions, providing 256-bit security and speeds exceeding 100 Gbps.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Implementation Details](#implementation-details)
- [Installation](#installation)
- [Usage](#usage)
  - [Running the Python Implementation](#running-the-python-implementation)
  - [Compiling and Running the C Implementation](#compiling-and-running-the-c-implementation)
- [Performance](#performance)
- [Project Report](#project-report)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## Introduction

The Rocca cipher is an AES-based authenticated encryption with associated data (AEAD) scheme that meets the stringent speed and security requirements of next-generation communication systems, such as 6G networks. It is designed to achieve ultra-fast software implementations by fully utilizing modern CPU features, including AES-NI and SIMD instructions.

## Features

- **High Performance**: Optimized for software implementations, capable of achieving speeds over 100 Gbps.
- **Strong Security**: Provides 256-bit security, suitable for applications requiring high levels of data protection.
- **Authenticated Encryption**: Supports AEAD, ensuring both confidentiality and integrity of the data.
- **Optimized Round Function**: Introduces a cost-free block permutation in its round function for enhanced efficiency.

## Implementation Details

This repository contains both Python and C implementations of the Rocca cipher:

- **Python Implementation**: Serves as a reference and educational tool, providing detailed comments and structure for understanding the cipher.
- **C Implementation**: Optimized for performance, capable of leveraging hardware features like AES-NI and SIMD instructions when compiled with appropriate flags.

## Installation

### Prerequisites

- **Python Implementation**:
  - Python 3.x
- **C Implementation**:
  - GCC or another C compiler supporting C99 standard.
  - CPU supporting AES-NI and SIMD instructions for optimal performance.

### Cloning the Repository

```bash
git clone https://github.com/your_username/rocca-cipher.git
cd rocca-cipher
```

## Usage

### Running the Python Implementation

1. **Navigate to the Python Directory**:

   ```bash
   cd python
   ```

2. **Install Required Packages** (if any):

   The Python implementation may require certain packages. Install them using:

   ```bash
   pip install -r requirements.txt
   ```

   *Note: The `requirements.txt` file should list any dependencies. If there are none, this step can be skipped.*

3. **Run the Rocca Cipher Script**:

   ```bash
   python RoccaCipher.py
   ```

   The script includes test vectors and can be modified to encrypt/decrypt custom data.

### Compiling and Running the C Implementation

1. **Navigate to the C Directory**:

   ```bash
   cd c
   ```

2. **Compile the Rocca Cipher Program**:

   ```bash
   gcc -o rocca_cipher rocca_cipher.c -O3 -maes -msse4.1
   ```

   - The `-O3` flag enables high-level optimizations.
   - The `-maes` and `-msse4.1` flags enable the use of AES-NI and SSE4.1 instructions.

3. **Run the Rocca Cipher Program**:

   ```bash
   ./rocca_cipher
   ```

   The program can be modified to encrypt/decrypt custom data and measure performance.

## Performance

The Rocca cipher is designed for high performance, especially when the C implementation is compiled with optimizations and hardware acceleration enabled.

Performance tests have shown:

- **Encryption Speed**: Sub-microsecond encryption times for data sizes up to several kilobytes.
- **Scalability**: Minimal increase in encryption time with larger data sizes, demonstrating excellent scalability.

Refer to the [Project Report](#project-report) for detailed performance analysis and benchmarking results.

## Project Report

A comprehensive project report is included in the `report` directory, covering:

- Detailed descriptions of the Rocca cipher's design and implementation.
- In-depth explanations of each function in the code.
- Performance comparison between Python and C implementations.
- Analysis and conclusions based on the results.

Access the report in PDF format: [Project_Report.pdf](report/Project_Report.pdf)

## Contributing

Contributions to the Rocca cipher implementation are welcome. If you have suggestions for improvements, optimizations, or bug fixes, please follow these steps:

1. **Fork the Repository**:

   Click the "Fork" button at the top right corner of this page to create a copy of the repository in your own GitHub account.

2. **Clone Your Fork**:

   ```bash
   git clone https://github.com/your_username/rocca-cipher.git
   cd rocca-cipher
   ```

3. **Create a New Branch**:

   ```bash
   git checkout -b feature/YourFeatureName
   ```

4. **Make Changes**:

   Implement your changes or additions.

5. **Commit Your Changes**:

   ```bash
   git commit -am 'Add new feature: YourFeatureName'
   ```

6. **Push to Your Fork**:

   ```bash
   git push origin feature/YourFeatureName
   ```

7. **Open a Pull Request**:

   Go to the original repository and open a pull request from your new branch.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## References

1. **Rocca Cipher Original Paper**:
   - Zhao, Z., Wang, X., & Hu, Y. (2022). Rocca: An AES-based Authenticated Encryption Scheme for 6G Systems. *IACR Cryptology ePrint Archive*, 2022/116. [Link](https://eprint.iacr.org/2022/116.pdf)

---

*Disclaimer: This implementation is provided for educational purposes only and should not be used in production environments without proper security evaluations.*
