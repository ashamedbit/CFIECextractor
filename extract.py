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
  
# Start of all valid addresses here
alladdress=[]
# List of all CFI Instrumented Indirect call gadgets start and end and also the register usied for the indirect jump
ICstartlist=[]
ICendlist=[]
ICreg=[]

# Allowed targets for each indirect jump in the same order as above
targets=[]

#These are allowed registers in current architecture. Can add registers of other architecture here
registers=["rip","rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","eax","ecx","edx","ebx","esp","ebp","esi","edi","ax","cx","dx","bx","sp","bp","si","di","ah","al","ch","cl","dh","dl","bh","bl","spl","bpl","sil","dil"]
gadgetgraph=[]

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

# This asks for a gadget starting at startaddr what are valid jump targets. The start address is enough but vital
def oracle (startaddr):
    graph=globals()['gadgetgraph']
    search=int(int(startaddr,16))
    #print(search)
    idx = GadgetBinarySearch(graph,search)
    #print(graph[idx].startaddr)

    if idx ==-1:
        print("Address given not part of any gadget")
        return []

    if graph[idx].goestoallnodes == 1:
        return ["*"]

    return graph[idx].EC
    

def IsRegister(s):
    if s in registers:
        return 1
    return 0

def IsMemLocation(s):
    if len(s)>=2 and s[0]=='0' and s[1]=='x':
        return 1
    if len(s)==1 and s[0]=='0':
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
            if len(y)==1 and len(y[0])==1 and y[0][0]=='0':
                operands += [y[0]]
                continue

            for k in y:
                if IsRegister(k):
                    operands += [k]
                    break

                if IsMemLocation(k):
                    operands += [k]

    return [operandsmembool,instruction,operands]

# Simulate a set of instrumented instructions repetitively to see all valid jump targets.
# The simulation is done via angr
def allowedtargetsIC ():
    Icallreg=globals()['ICreg']
    for i in range(len(ICstartlist)):
        allowedtargets=[]
        for a in alladdress:
            state = proj.factory.entry_state();
            #state.regs.rip=state.solver.BVV(0x401203, 64);
            state.regs.rip=state.solver.BVV(ICstartlist[i], 64);
            testjmp=state.solver.BVV(int(a,16), 64);
            toexecute="state.regs."+Icallreg[i]+"=testjmp"
            exec(toexecute)

            #state.regs.rcx=state.solver.BVV(int(a,16), 64);
            # state.regs.rax=state.solver.BVS('x', 64);
            simgr = proj.factory.simulation_manager(state);
            x=state.regs.rcx;
            #print(simgr.active[0].regs.rax);
            #print(simgr.active[0].regs.rip);
            simgr.step();
            #print(simgr.active[0].regs.rax);
            oldrip = simgr.active[0].regs.rip
            simgr.step();
            newrip = simgr.active[0].regs.rip

            if (state.solver.eval(oldrip) != state.solver.eval(newrip)):
                allowedtargets+=[a]
        globals()['targets']+=[allowedtargets]

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

        #if instruction == "cmp":
        #    lastcomparedregs = [operands[0]]
        #    lastcomparedregs += [operands[1]]

        if instruction[0] == 'l' and instruction[1] == 'o' and instruction[2] == 'o' and instruction[3] == 'p':
            if operands[0] not in EC:
                EC += [operands[0]]

        if instruction == "ud2":
            if (jumped == 0):
                return EC
        #    cmp1=0
        #    cmp2=0

        #    if len(lastcomparedregs) < 2:
        #        return EC

        #    if fixedregisters.has_key(lastcomparedregs[0]):
        #        cmp1=1
        #    if fixedregisters.has_key(lastcomparedregs[1]):
        #        cmp2=1
        #    if not(cmp1) and cmp2:
        #        fixedregisters[lastcomparedregs[0]] = fixedregisters[lastcomparedregs[1]]
        #    if cmp1 and not(cmp2):
        #        fixedregisters[lastcomparedregs[1]] = fixedregisters[lastcomparedregs[0]]

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


# First extract the gadget list from the binary
# Then if it is instrumented code we run simulations on it using angr
# If not we do a simple static analysis and output the equivalence classes
# Then we construct the graph based on these gadgets
def AnalyzeGadgetList(bname,depth):
    RawGadget = os.popen('ROPgadget --depth '+str(depth)+' --dump --binary '+bname).read()
    ListGadget = RawGadget.split('\n');
    graph=[]
    labelmap={}
    label=0
    for g in ListGadget:
        EC=[]
        if len(g)>=2 and g[0]=='0' and g[1]=='x':
            Stmt =re.split(': | ; | //',g)
            #print(Stmt)
            #EC = GetEC(Stmt)
            #print(EC)
            [s1,s2] = Bound(Stmt)

            if (len(globals()['ICstartlist']) >=1):
                index = BinarySearch(globals()['ICstartlist'],s1)
            else:
                index = -1

            if (index!=-1 and (ICstartlist[index] >= s1) and (ICstartlist[index] < s2)):
                    EC += targets[index]
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

            #print(EC)
            labelmap[s1]=label
            graph.append(Gadgets(label,g[1:],s1,s2,EC))
            label=label+1

    #print(labelmap)

    # Construct the graph
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
 

    for g in graph:
        print("Gadget no :",g.idno) 
        print("Instructions are as follows:")
        print(g.insnlist)
        print("Can the gadget go to every location? ",g.goestoallnodes)
        if (g.goestoallnodes == 0):
            print("Gadgets we can jump to with label no:")
            print(g.nextptr)
            print("Absolute addresses this gadget can jump to: ")
            print(g.EC)
        print('\n')

    graph.sort(key= lambda d: d.startaddr)
    globals()['gadgetgraph']=graph
 

# Identify regions of instrumented code so that we can run angr simulations to this code later
def PopulateInstrumentedICList(bname):
    Address = os.popen('objdump -d '+bname).read().split('\n')
    state=0
    length=0
    startinstrument=''
    for line in Address:
        length=len(line)
        if (length>19 and line[0]==' ' and line[1]==' '):

            globals()['alladdress']+=[line[2:8]]

            if (len(line)>=32 and line[32] == 'm' and line[33] == 'o' and line[34] == 'v' and line[35] == 'a'):
                if (state==0):
                    state=1
                    startinstrument=line[2:8]
                else:
                    state=0
 
            if (length>=32 and line[32] == 'u' and line[33] == 'd' and line[34] == '2'):
                if (state==1):
                    state=2
                else:
                    state=0
 
            if (length>=32 and line[32] == 'c' and line[33] == 'a' and line[34] == 'l'):
                if (state==2):
                    globals()['ICendlist']+=[int(line[2:8],16)]
                    globals()['ICstartlist']+=[int(startinstrument,16)]
                    [boolarr,insn,operands] = GetOperandsFromInstruction(line[32:])
                    globals()['ICreg']+=operands
                state=0

    #print(globals()['ICstartlist'])
    #print(globals()['ICendlist'])
    #print(globals()['alladdress'])
    
#binname="a.out"
binname=sys.argv[1]
proj = angr.Project(binname);
PopulateInstrumentedICList(binname)
allowedtargetsIC()

print("*********Instrumented code targets*******")
print('\n')
print("Instrumented code starts at these list of addresses")
print(ICstartlist)
print('\n')
print("Indirect calls jump through values on these registers")
print(ICreg)
print('\n')
print("All allowed targets in hexadecimal per indirect jmp listed below:")
print(targets)
print('\n')
print("********Start of Analysis of gadgets******")

# Second argument is depth for ROPgadget to extract gadgets
AnalyzeGadgetList(binname,100)

print("********Start of Querying******")

while (1):
    startaddr=input("Enter the start address in hex:  ")
    if startaddr=='':
        print("You have supplied an empty string. Please enter a start address. ")
        continue
    jmptargets = oracle(startaddr)
    print(jmptargets)
