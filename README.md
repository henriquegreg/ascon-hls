# High-Level Synthesis-Based Hardware Acceleration of Ascon Lightweight Cryptography

This repository contains the C source codes, benchmark scripts, and implementation guidelines for the paper *"High-Level Synthesis-Based Hardware Acceleration of Ascon Lightweight Cryptography for IoT Devices"*. 

The project implements and evaluates the Ascon cryptographic suite (AEAD, Hash256, and XOF128 variants) using High-Level Synthesis (HLS) on the PYNQ-Z2 FPGA board, focusing on the security of Internet of Things (IoT) devices.

## Repository Structure

* **`aead/`, `hash256/`, `xof128/`**: C source codes optimized with HLS directives for hardware synthesis. The implementations use pragmas such as `#pragma HLS PIPELINE` to increase throughput, `#pragma HLS ARRAY_PARTITION` for parallelism in state registers, and `#pragma HLS INLINE` to reduce latency in permutations.
* **`AEAD Benchmark Script.ipynb`, `Hash256 Benchmark Script.ipynb`, `XOF128 Benchmark Script.ipynb`**: Python Jupyter Notebook scripts used to validate functional correctness and extract time, cycles, and speedup metrics by automating the interaction between the Processing System (PS) and the Programmable Logic (PL).

## How to Reproduce the Architecture

The development and reproduction flow uses AMD Xilinx Vitis HLS and Vivado (version 2024.2).

### 1. High-Level Synthesis (Vitis HLS)
1. Create a new project in Vitis HLS and select the PYNQ-Z2 board.
2. Add the `.c` and `.h` files of the desired cryptographic variant (e.g., files inside the `aead/` folder) as Source Files.
3. Set the corresponding Top Function in the project.
4. The code already includes the interface directives (`#pragma HLS INTERFACE m_axi` and `s_axilite`). They ensure the master data channels and control channels for AXI communication.
5. Run the C Synthesis to convert the algorithm to a Register Transfer Level (RTL) design.
6. Export the packaged design as an IP core (Export RTL option).

### 2. System Integration (Vivado)
1. Create a new project in Vivado targeting the PYNQ-Z2 board.
2. In the IP Repository settings, point to the directory where Vitis HLS exported the IP in the previous step.
3. Create a Block Design and instantiate the Zynq Processing System (PS) block.
4. Add the generated Ascon accelerator IP.
5. Use the *Run Connection Automation* tool. Vivado will automatically create the AXI SmartConnect infrastructure, properly mapping the memory and control channels between the PS and PL.
6. Validate the block design, create the corresponding HDL Wrapper, and Generate the Bitstream.
7. Finally, export the hardware design, making sure to locate the generated `.bit` and `.hwh` files.

### 3. Execution and Benchmark on the PYNQ-Z2 Board
1. Transfer this repository to the local file system of the PYNQ-Z2 board.
2. Move the `.bit` and `.hwh` files created in Vivado to the same folder as the benchmark scripts. Ensure the names match the ones requested by the notebooks.
3. Open the Jupyter Notebook interface running natively on the PYNQ-Z2.
4. Open the `.ipynb` script corresponding to your design (e.g., `AEAD Benchmark Script.ipynb`).
5. Execute the first cells to compile the reference C code as a shared library using the embedded ARM Cortex-A9 processor.
6. Continue executing the cells. The Python script will load the bitstream onto the FPGA (configured at 100 MHz), allocate contiguous memory for DMA, and inject random test vectors.
7. After 1,000 iterations, the Notebook will automatically verify functional validation (reporting Pass/Fail by comparing hardware and software outputs) and print the average latency and speedup metrics comparing the physical FPGA architecture against the CPU.

## Authors
* Henrique Gregory Gimenez
* Felipe Valencia de Almeida
* Victor Takashi Hayashi

**University of São Paulo (PCS-EPUSP)**
