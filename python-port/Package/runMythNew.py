from multiprocessing import Pool
import sys
import commands # NOTE: This is Python2 specific and allows us to carry the mythril output to a file. Thus, we need to run our program with python2
import time
import threading

all_contracts = list()

class Myth:
    def __init__(self):
        '''
        Set a lock. Read in contracts.
        '''
        self.lock = threading.Lock()
        self.thread_count = 0
        #with open('./0-1000000/contracts.txt', 'r') as f1:
        '''
        with open('/home/danc2/Desktop/addac', 'r') as f1:
            for line in f1:
                self.contracts.append(line.strip())
                print(line.strip())
        '''

    def thread_spawn(self):
        return
        threads = []
        #with open('/home/danc2/thesis/threading/contracts', 'r') as f1:
        with open('/home/danc2/thesis/threading/Contracts/redo.log', 'r') as f1:
            try:
                for line in f1:
                    contract = line.strip().split(",")[0]
                    print(contract)
                    #sys.exit()
                    t = threading.Thread(target=self.myth_analyze, args=(contract,))
                    threads.append(t)
                    #global threadCount
                    #threadCount +=1
                    self.thread_count += 1
                    time.sleep(3)
                    t.start()
                    while self.thread_count > 10:
                        time.sleep(2)
                    #if i % 4 == 0:
                    #    t.join()
            except Exception as error:
                print("Contract: " + str(contract) +"\n")
                print(str(error))
                with open('./Contracts/' + 'Caller.log', 'a+') as f4:
                    f4.write(str(contract) +"\n")
                    f4.write(str(error))

    def myth_analyze(self, contract):
        output = ""
        '''
        Run in Mythril
        '''
        try:
            print('sudo docker run --rm mythril/myth -v4 analyze -1 -a ' + str(contract) + ' --execution-timeout 3600')
            output = commands.getstatusoutput('sudo docker run --rm mythril/myth -v4 analyze -1 -a ' + str(contract) + ' --execution-timeout 3600')
            self.lock.acquire()
            if "ERROR" in str(output):
                with open('./Contracts/' + 'errors.log', 'a+') as f1:
                        f1.write(contract + "\n")
                        f1.write(str(output) + "\n")
                return
            if "Exception occurred" in str(output):
                with open('./Contracts/' + 'Exceptions.log', 'a+') as f4:
                        f4.write(contract + "\n")
                        f4.write(str(output) + "\n")
                return # to avoid messing up our parser, which doesn't handle Exceptions
            #with open('./Contracts/' + "mythrilOutput", 'a+') as f3:
            with open('./Contracts/exploited/' + str(contract), 'w') as f3:
                for line in output:
                    f3.write(str(line))
            with open('./Contracts/contractlist.txt', 'a+') as f2:
                f2.write(str(contract)+"\n")

        except Exception as error:
            print(str(error)+"\n")
            with open('./Contracts/UnexpectedExceptions.txt', 'a+') as f5:
                f5.write(str(contract)+"\n")
                f5.write(str(error)+"\n")

        finally:
            self.thread_count -= 1
            self.lock.release()

#MP implementation
def myth_analyze(contract):
    output = ""
    '''
    Run in Mythril
    '''
    try:
        print('sudo docker run mythril/myth -v4 analyze -1 -a ' + str(contract) + ' --execution-timeout 900')
        output = commands.getstatusoutput('sudo docker run mythril/myth -v4 analyze -1 -a ' + str(contract) + ' --execution-timeout 900')
#        self.lock.acquire()
        if "ERROR" in str(output):
            with open('./Contracts/' + 'errors.log', 'a+') as f1:
                    f1.write(contract + "\n")
                    f1.write(str(output) + "\n")
            return
        if "Exception occurred" in str(output):
            with open('./Contracts/' + 'Exceptions.log', 'a+') as f4:
                    f4.write(contract + "\n")
                    f4.write(str(output) + "\n")
            return # to avoid messing up our parser, which doesn't handle Exceptions
        with open('./Contracts/' + "mythrilOutput", 'a+') as f3:
            for line in output:
                f3.write(str(line))
        with open('./Contracts/contractlist.txt', 'a+') as f2:
            f2.write(str(contract)+"\n")

    except Exception as error:
        print(str(error)+"\n")
        with open('./Contracts/UnexpectedExceptions.txt', 'a+') as f5:
            f5.write(str(contract)+"\n")
            f5.write(str(error)+"\n")
    #finally: self.lock.release()

# generates all possible urls so as to process them via multiprocessing
def generate_urls_MP():
    with open('/home/acm/Desktop/addac', 'r') as f1:
        for line in f1:
            all_contracts.append(line.strip())
            print(line.strip())

#### Threaded ###
# our main
myth = Myth()
myth.thread_spawn()
'''
### Multi-processing ###
#myth = Myth_MP()
#myth.generate_urls_MP()
generate_urls_MP()
p = Pool(2)
p.map(myth_analyze, all_contracts)
p.terminate()
p.join()
'''
