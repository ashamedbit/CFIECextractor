#!/usr/bin/env python
##
##  Aniruddhan Murali - 2020-03-01 - CFI target extractor
##
##

import ropgadget
import os
import re
import angr
import sys
import argparse

from bisect import bisect_left 



# Define each gadget
class Gadgets:
    idno = -1
    startaddr=-1
    endaddr=-1
    insnlist = []
    nextptr = []
    EC = []
    goestoallnodes=0

    def __init__(self,idno,insnlist,startaddr,endaddr,EC):
        self.idno=idno
        self.startaddr=startaddr
        self.endaddr=endaddr
        self.insnlist=insnlist
        self.EC=EC
        self.nextptr=[]

class GadgetExtractor:
    def __init__(self, binname):
        self.proj = angr.Project(binname)
        # Start of all valid addresses here
        self.alladdress=[]
        # List of all CFI Instrumented Indirect call gadgets start and end and also the register usied for the indirect jump
        self.ICstartlist=[]
        self.ICendlist=[]
        self.ICreg=[]

        # List of allowed targets according to LLVM-CFI for instrumented code
        self.simangrtargetaddr=[]

        # Allowed targets for each indirect jump in the same order as above
        self.targets=[]
        
        print("Calculating instrumented code regions boundary....")
        self._populateInstrumentedICList(binname)
        print("Finished calculating instrumented code regions boundary")
        print("Now simulate  instrumented regions with possible address....")
        self._allowedtargetsIC()
        print("Finished simulating all instrumented code regions with possible targets")
        self._analyzeGadgetList(binname,100)

    def _populateInstrumentedICList(self, bname):
        Address = os.popen('objdump -d '+bname).read().split('\n')
        state=0

        startinstrument=''
        for line in Address:
            length=len(line)
            if (length>19 and line[0]==' ' and line[1]==' '):

                self.alladdress += [line[2:8]]

                # To reduce number of targets for LLVM cfi we can look at functions with .cfi appended to them. 
                # This is a neat indicator of net pool of valid jump targets for instrumented code. 
                # All we have to do is find the mappings of instrumented gadgets to .cfi functions
                if ".cfi>" in line:
                    self.simangrtargetaddr+=[line[2:8]]

                if length >= 32:
                    if line[32:36] == 'mova':
                        if state==2:
                            continue
                         state=1
                        startinstrument=line[2:8]
 
                    if line[32:35] == 'ud2':
                        if state == 1:
                            state = 2
                        else:
                            state = 0

                    if line[32:35] == 'cal':
                        if state == 2:
                            [boolarr,insn,operands] = GetOperandsFromInstruction(line[32:])
                            if (not(len(operands)>=1 and IsRegister(operands[0]))):
                                continue
                            self.ICendlist += [int(line[2:8],16)]
                            self.ICstartlist += [int(startinstrument,16)]
                            self.ICreg += operands
                        
                        state = 0 

    # Simulate a set of instrumented instructions repetitively to see all valid jump targets.
    # The simulation is done via angr
    def _allowedtargetsIC (self):

        for i in range(len(self.ICreg)):
            allowedtargets=[]
            for a in self.simangrtargetaddr:
                state = self.proj.factory.entry_state();
                state.regs.rip=state.solver.BVV(self.ICstartlist[i], 64);
                testjmp=state.solver.BVV(int(a,16), 64);
                toexecute="state.regs."+self.ICreg[i]+"=testjmp"
                exec(toexecute)

                simgr = self.proj.factory.simulation_manager(state);
                x=state.regs.rcx;
                simgr.step();
                oldrip = simgr.active[0].regs.rip
                simgr.step();
                newrip = simgr.active[0].regs.rip

                if (state.solver.eval(oldrip) != state.solver.eval(newrip)):
                    allowedtargets+=[a]
            self.targets += [allowedtargets]

    def _analyzeGadgetList(self, bname,depth):
        RawGadget = os.popen('ROPgadget --depth '+str(depth)+' --dump --binary '+bname).read()
        ListGadget = RawGadget.split('\n');
        graph=[]
        labelmap={}
        label=0
        for g in ListGadget:
            EC=[]
            if len(g)>=2 and g[0]=='0' and g[1]=='x':
                Stmt =re.split(': | ; | //',g)
                [s1,s2] = Bound(Stmt)

                if len(self.ICstartlist) >=1:
                    index = BinarySearch(self.ICstartlist, s1)
                else:
                    index = -1

                if (index!=-1 and (self.ICstartlist[index] >= s1) and (self.ICstartlist[index] < s2)):
                    EC += self.targets[index]
                else:
                    EC = GetEC(Stmt)
                    tempEC=[]
                    for e in EC:
                        if (IsMemLocation(e)):
                            if ((int(e[2:],16) < s1) or (int(e[2:],16) > s2)):
                                tempEC += [e[2:]]
                        else:
                            tempEC += [e]
 
                    EC = tempEC


                labelmap[s1]=label
                graph.append(Gadgets(label,g[1:],s1,s2,EC))
                label=label+1


        for g in graph:
            for e in g.EC:
                if e =='*':
                    g.goestoallnodes=1
                    g.nextptr=[]
                    continue
                if IsRegister(e):
                    g.nextptr=[]
                    g.goestoallnodes=1
                    continue
                if int(e,16) in labelmap.keys():
                    g.nextptr += [labelmap[int(e,16)]]
 

        #for g in graph:
            #print("Gadget no :",g.idno) 
            #print("Instructions are as follows:")
            #print(g.insnlist)
            #print("Can the gadget go to every location? ",g.goestoallnodes)
            #if (g.goestoallnodes == 0):
                #print("Gadgets we can jump to with label no:")
                #print(g.nextptr)
                #print("Absolute addresses this gadget can jump to: ")
                #print(g.EC)
            #print('\n')

        graph.sort(key= lambda d: d.startaddr)
        self.gadgetgraph = graph
        

    # This asks for a gadget starting at startaddr what are valid jump targets. The start address is enough but vital
    def __call__(self, startaddr):
        graph = self.gadgetgraph
        search=int(int(startaddr,16))
        #print(search)
        idx = GadgetBinarySearch(graph, search)
        #print(graph[idx].startaddr)

        if idx ==-1:
            print("Address given not part of any gadget")
            return []

        if graph[idx].goestoallnodes == 1:
            return ["*"]

        return graph[idx].EC


    # This returns Bounds of all instrumented binary code in program
    # as array of starting address and array of ending address
    def __GetInstrumentationBoundary__(self):
        # Convert array of integers to array of hex values manually
        A=[]
        B=[]
        for i in self.ICstartlist:
            A+=[hex(i)]

        for i in self.ICendlist:
            B+=[hex(i)]
 
        return [A,B]

    # We labeled each gadget returned by ROPGadget in the same order ROPGadget prints it
    # We assume ROPGadget returns gadgets in a stable deterministic order
    # If it can jump to particular gadget label we return gadget label list here
    def __GadgetIdLinks__(self,label):
        graph=self.gadgetgraph

        for g in graph:
            if (g.idno ==label):
                if g.goestoallnodes == 1:
                    return ["*"]
                return g.nextptr

        return -1
 
 

def IsRegister(s):

    registers=["es","gs","cs","rip","rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","eax","ecx","edx","ebx","esp","ebp","esi","edi","ax","cx","dx","bx","sp","bp","si","di","ah","al","ch","cl","dh","dl","bh","bl","spl","bpl","sil","dil","r8","r8b","r8d","r9","r9b","r10","r10b","r11","r11b","r12","r12b","r13","r13b","r14","r14b","r15","r15b"]
    if s in registers:
        return 1
    return 0

def IsMemLocation(s):
    if len(s)>=2 and s[0]=='0' and s[1]=='x':
        return 1
    if len(s)==1 and s[0]>='0' and s[0]<='9':
        return 1
    if len(s)>=2 and s[0]=='-' and s[1]>='0' and s[1]<='9':
        return 1
    return 0

def GadgetBinarySearch(graph, target):
    start = 0
    end = len(graph)-1

    while start < (end-1):
        middle = (start + end)// 2
        midpoint = graph[middle].startaddr
        if midpoint > target:
            end = middle
        elif midpoint < target:
            start = middle
        else:
            return middle

    if graph[start].startaddr == target:
        return start

    if graph[end].startaddr == target:
        return end

    return -1



def BinarySearch(L, target):
    start = 0
    end = len(L)-1

    while start < (end-1):
        middle = (start + end)// 2
        midpoint = L[middle]
        if midpoint > target:
            end = middle
        elif midpoint < target:
            start = middle
        else:
            return middle

    if L[start] == target:
        return start

    if L[end] == target:
        return end

    return start

def hasNumbers(inputString):
    return any(char.isdigit() for char in inputString)

# Find start and end of an arbitrary gadget from ROPgadget output
def Bound(Gadget):
    length = (len(Gadget[-1])-1)//2
    end = int(Gadget[0][12:18],16)+length-1
    return int(Gadget[0][12:18],16),end


# Given an instruction from ROPgadget output retrieve it's operands
def GetOperandsFromInstruction(I):
    instruction=re.split(' ',I)[0]

    splitwords=re.split(',',I[len(instruction):])
    operands=[]
    operandsmembool=[]

    for y in splitwords:
        z = re.split("\*|\%|\(|\)",y)
        for x in z: 
            if len(x) == 0:
                continue

            if '[' in x:
                operandsmembool += [1]
            else:
                operandsmembool += [0]

            y = re.split(" |\[|\]",x)

            if len(y)==1 and len(y[0])>=2 and y[0][0]=='0' and y[0][1]=='x':
                operands += [y[0]]
                continue
            if len(y)==1 and len(y[0])==1 and y[0][0]>='0' and y[0][0]<='9':
                operands += [y[0]]
                continue

            for k in y:
                if IsRegister(k):
                    operands += [k]
                    break

                if IsMemLocation(k):
                    operands += [k]

    return [operandsmembool,instruction,operands]

# We do not need to do simulation for non CFI instrumented gadgets as it is a waste od time
# Do a static analysis on gadgets that are not subsequences of CFI instrumented gadgets
# Return the Equivalence class
def GetEC(Gadget):
    fixedregisters={}
    EC=[]
    jumped=0
    #lastcomparedregs=[]

    for s in Gadget:
        [operandsmembool,instruction,operands] = GetOperandsFromInstruction(s)
        #print(operands)
        #print(operandsmembool)
        #print(fixedregisters)

        if len(instruction)==0:
            continue

        if instruction == "jmp":
            if operandsmembool[0]==0 and (operands[0] in fixedregisters.keys()):
                EC += [fixedregisters[operands[0]]]
                return EC

            if operands[0] not in EC:
                EC += [operands[0]]
                return EC

        if instruction == "movabs":
            fixedregisters[operands[0]] = operands[1]

        if instruction == "mov":
            if operandsmembool[0]==0 and IsRegister(operands[0]):
                if operandsmembool[1]==0 and IsMemLocation(operands[1]):
                    fixedregisters[operands[0]] = operands[1]

        if instruction == "call":
            if (operands[0] in fixedregisters.keys()):
                EC += [fixedregisters[operands[0]]]
                return EC

            EC += [operands[0]]
            return EC

        if instruction[0] == 'l' and instruction[1] == 'o' and instruction[2] == 'o' and instruction[3] == 'p':
            if operands[0] not in EC:
                EC += [operands[0]]

        if instruction == "ud2":
            if (jumped == 0):
                return EC

        if instruction[0] == 'r' and instruction[1] == 'e' and instruction[2] == 't':
            EC += ["*"]
            return EC

        if instruction[0] == 'j':
            if operandsmembool[0]==0 and (operands[0] in fixedregisters.keys()):
                EC += [fixedregisters[operands[0]]]
            if operands[0] not in EC:
                EC += [operands[0]]
            jumped=1
            continue


        jumped=0
    return EC
 

if __name__ == "__main__":
    binname=sys.argv[1]
    ge = GadgetExtractor(binname)

    print("*********Instrumented code targets*******")
    print('\n')
    print("Instrumented code starts at these list of addresses")
    print(ge.ICstartlist)
    print('\n')
    print("Indirect calls jump through values on these registers")
    print(ge.ICreg)
    print('\n')
    print("All allowed targets in hexadecimal per indirect jmp listed below:")
    print(ge.targets)
    print('\n')
    #[x,y] = ge.__GetInstrumentationBoundary__()
    #x= ge.__GadgetIdLinks__(186)
    #print(x)

    print("********Start of Querying******")

    while (1):
        startaddr=input("Enter the start address in hex:  ")
        if startaddr=='':
            print("You have supplied an empty string. Please enter a start address. ")
            continue
        jmptargets = ge(startaddr)
        print(jmptargets)
