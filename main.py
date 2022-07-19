# -*- coding: utf-8 -*-
"""
Created on Sat Jan 15 12:06:15 2022

@author: anna
"""

#!/usr/bin/env python3
import logging
import util
import yao
from abc import ABC, abstractmethod

"""IMPORT RE and PANDAS"""
import re
import pandas as pd

logging.basicConfig(format="[%(levelname)s] %(message)s",
                    level=logging.WARNING)


class YaoGarbler(ABC):
    """An abstract class for Yao garblers (e.g. Alice)."""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass

class LocalTest(YaoGarbler):
    """A class for local tests.

    Print a circuit evaluation or garbled tables.

    Args:
        circuits: the JSON file containing circuits
        print_mode: Print a clear version of the garbled tables or
            the circuit evaluation (the default).
    """
    def __init__(self, circuits, print_mode="circuit"):
        super().__init__(circuits)
        self._print_mode = print_mode
        self.modes = {
            "circuit": self._print_evaluation,
            "table": self._print_tables,
        }
        logging.info(f"Print mode: {print_mode}")

    def start(self):
        """Start local Yao protocol."""
        for circuit in self.circuits:
            self.modes[self.print_mode](circuit)

    def _print_tables(self, entry):
        """Print garbled tables."""
        entry["garbled_circuit"].print_garbled_tables()

    def _print_evaluation(self, entry):
        """Print circuit evaluation."""
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        garbled_tables = entry["garbled_tables"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_inputs = {}  # map from Bob's wires to (key, encr_bit) inputs
        pbits_out = {w: pbits[w] for w in outputs}  # p-bits of outputs

        print(f"======== {circuit['id']} ========")
        
        print()

        # Read ALICE's input from a file .txt
        a = self.read_input('Alice')
        # Alice computes the sum of her inputs
        a = self.sum_bin(a)
        
        # Adapt Alice's inputs for the following code
        bits_a = [0 for i in range(5-len(a))]
        # NOTE: if the inputs aren't correct for some reasons, here the code will interrupt because of an error
        bits_a += [int(i) for i in a]
        
        # Map Alice's wires to (key, encr_bit)
        for i in range(len(a_wires)):
            a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                    pbits[a_wires[i]] ^ bits_a[i])
            
        # Alice sends her encrypted inputs to Bob:
        # save this message on a file .csv
        self.create_file(a_inputs)
        
        # Read BOB's input from a file .txt
        b = self.read_input('Bob')
        # Bob computes the sum of her inputs
        b = self.sum_bin(b)
        
        # Adapt Bob's inputs for the following code
        bits_b = [0 for i in range(4-len(b))]
        # NOTE: if the inputs aren't correct for some reasons, here the code will interrupt because of an error
        bits_b += [int(i) for i in b]
        
        # Map Bob's wires to (key, encr_bit)
        for i in range(len(b_wires)):
            b_inputs[b_wires[i]] = (keys[b_wires[i]][bits_b[i]],
                                    pbits[b_wires[i]] ^ bits_b[i])
        
        # Evaluate and send result to Alice
        result = yao.evaluate(circuit, garbled_tables, pbits_out, a_inputs,
                                  b_inputs)

        # Format output: convert from binary to decimal
        str_result = ' '.join([str(result[w]) for w in outputs])
        result_dec=self.bin_to_dec(str_result)
            
        print(f"sum = {result_dec}")
        print()
        
        # Save Bob's message to Alice on a file .txt
        file=open('output_result.txt', "w")
        file.write('Sum of Alice\'s and Bob\'s inputs: ' + str(result_dec))
        file.write('\n')
        
        # Verify the correctness of the MPC computation comparing that to a Non-MPC computation
        ver=self.verify(result_dec,a,b)
        print(f"Is the result correct? {ver}")
        print()
        
        # Write the output of the verification function on the file .txt
        file.write('Is the result correct? ' + ver)
        file.close()
    
    # read the input of each party from a file .txt
    def read_input(self, name):
        with open(name+'_inputs.txt') as f:
            lines=f.readlines()
        inp_list=re.split(' ', lines[0])
        try:
            inputs=[int(i) for i in inp_list]
            return inputs
        except:
            # If the inputs aren't integers, print error
            msg = "ERROR: inputs must be all integers"
            print(msg)
            return msg
    
    # computes the sum of the inputs of one party
    def sum_bin(self, inp):
        sum_dec=0
        for num in inp:
            sum_dec+=num
        sum_bin="{0:b}".format(sum_dec)
        if len(sum_bin)<=4:
            # Return the sum in binary format
            return sum_bin
        else:
            # If the inputs are too big, print error
            msg = "ERROR: inputs must be at most 4 byte"
            print(msg)
            return msg
        
    # Alice sends her encrypted inputs to Bob:
    # save this message on a file .csv
    def create_file(self, message):
        data=pd.DataFrame(message,index=['keys','encrypted bits'])
        data=data.T
        data.reset_index(inplace=True)
        data.drop('index',axis=1,inplace=True)
        data.to_csv('file_message_alice.csv',index=False)
    
    # convert the result from binary to decimal
    def bin_to_dec(self, result):
        li_re=re.split(' ',result)
        result_tmp=""
        for i in range(len(li_re)):
            result_tmp+=li_re[i]
        return int(result_tmp, 2)
    
    # Verify the correctness of the MPC computation comparing that to a Non-MPC computation
    def verify(self, result, a, b):
        sum_=int(b,2)+int(a,2)
        if sum_==result:
            return 'Yes'
        else:
            return 'No'
    
    @property
    def print_mode(self):
        return self._print_mode

    @print_mode.setter
    def print_mode(self, print_mode):
        if print_mode not in self.modes:
            logging.error(f"Unknown print mode '{print_mode}', "
                          f"must be in {list(self.modes.keys())}")
            return
        self._print_mode = print_mode


def main(
    party='local',
    circuit_path="circuits/sum.json",
    oblivious_transfer=True,
    print_mode="circuit",
    loglevel=logging.WARNING,
):
    if party == "local":
        local = LocalTest(circuit_path, print_mode=print_mode)
        local.start()
    else:
        logging.error(f"Unknown party '{party}'")
        
    logging.getLogger().setLevel(loglevel)


if __name__ == '__main__':
    import argparse

    def init():
        loglevels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["local"],
                            help="the yao party to run")
        parser.add_argument(
            "-c",
            "--circuit",
            metavar="circuit.json",
            default="circuits/sum.json",
            help=("the JSON circuit file for alice and local tests"),
        )
        parser.add_argument("--no-oblivious-transfer",
                            action="store_true",
                            help="disable oblivious transfer")
        parser.add_argument(
            "-m",
            metavar="mode",
            choices=["circuit", "table"],
            default="circuit",
            help="the print mode for local tests (default 'circuit')")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            circuit_path=parser.parse_args().circuit,
            oblivious_transfer=not parser.parse_args().no_oblivious_transfer,
            print_mode=parser.parse_args().m,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()