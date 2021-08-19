/*
 * sbtAdaptor.cpp: command-line application to exercise sbtShim by emulating
 * either a manager or a worker.
 * If worker, reads the provided file into messages that are <= 10K and
 * can be converted into NDN objects put in Content field of each Data packet
 * which is a Publication to a Collection derived from the argument list
 * 
 *
 *  sbtAdaptor is not intended as production code. 
 * 
 */

#include <getopt.h>
#include <charconv>
#include <functional>
#include <iostream>
#include <fstream>
#include <chrono>

/*
 * The sbtShim object in sbtShim.hpp provides the API for
 * applications to the syncps protocol.
 */
#include "sbtShim.hpp"

using namespace std::chrono;
using std::to_string;

/* 
 * Command-line (all are optional except id.bundle file):
 *   sbtAdaptor -f filename -c count id.bundle
 */

// handles command line
static struct option opts[] = {
    {"file", required_argument, nullptr, 'f'},
    {"count", required_argument, nullptr, 'c'},
    {"debug", no_argument, nullptr, 'd'},
    {"help", no_argument, nullptr, 'h'}
};
static void usage(const char* cname)
{
    std::cerr << "usage: " << cname << " [flags] -f file_name id.bundle\n";
}
static void help(const char* cname)
{
    usage(cname);
    std::cerr << " flags:\n"
           "  -f |--file name    file with contents to be logged\n"
           "\n"
           "  -c |--count          number of messages to publish\n"
           "  -d |--debug          enable debugging output\n"
           "  -h |--help           print help then exit\n";
}

static int debug = 0;
static int Cnt = 10;
static std::string fname;
static std::string msgtype("logs");     //default
static std::string role{};
static std::string myId{};
static Timer timer;
static std::chrono::nanoseconds pubWait = std::chrono::seconds(1);



/*
 * processMsg handles each message received.
 * It's the callback passed to waitForMsg
 * pieceList is a vector (in order)  of pointers to the parts of the message
 * Use "toRawStr" to convert each part to a string and get entire message.
 * If mcoll has separators "|", they should be changed to "/"
 */

void processMsg(const pieceList& parts, const Arglist& a)
{
    try {
        std::cout << std::endl << role << myId << " received a " << a.at("target") << "/" << a.at("topic");
        if(a.at("args") != "-") //indicates args not used
            std::cout << "/" << a.at("args");
        std::cout << " msg from " << a.at("msrc") << " published " << a.at("mts").substr(9) << std::endl;
        for (auto p : parts) std::cout << std::string((char*)p.data(), p.size());
        std::cout << std::endl;
    } catch(const std::exception& e) {
        _LOG_INFO("processMsg got exception trying to receive message: " << e.what());
        exit(1);
    }
}

//topic from worker or proxy
const std::vector<std::string> logInt = {"Broker::LOG", "Cluster::LOG", "LoadedScripts::LOG", "Stats::LOG"};
const auto nInt = logInt.size();
//topic from worker
const std::vector<std::string> logTraf = {"CaptureLoss::LOG","Conn::LOG","DNS::LOG","Files::LOG","HTTP::LOG","NTP::LOG",
                 "PacketFilter::LOG","Reporter::LOG","SSH::LOG","SSL::LOG","Weird::LOG","X509::LOG"};
const auto nTraf = logTraf.size();
const std::string hexPrefix = "4947C1C8683F9745FECEDF7176CCDE5FB9288C00#";
const std::vector<std::string> hexSuffix = {"55545", "55594","55642"}; //mgr, prxy, wrkr local
Arglist defArgs = {{"args","-"}}; //most messages don't set this field

// expect to pass in arglist (change to const) but constructing it here
// constructing is very kludgy but expectation is this stuff gets passed in
void publish(sbtShim& shim, const std::vector<uint8_t>& m, Arglist& a = defArgs)
{ 
    a["args"] = "-";
    if(role == "manager") {
        auto k = randombytes_uniform(3);  //pick a target
        auto l = randombytes_uniform(2);  //pick a topic
        if(k <= 1) {
            a["target"] = "cluster";
            if(l == 0) {
                a["topic"] = "worker";
            } else {
                a["topic"] = "node";
                l = randombytes_uniform(4) + 1; //assuming 4 workers
                a["args"] = "worker" + to_string(l);
            }
        } else {
            a["target"] = "control";
            a["topic"] = hexPrefix + hexSuffix[l+1];
        }
    } else if(role == "worker") {
        auto k = randombytes_uniform(3);  //pick a target
        auto l = randombytes_uniform(2);  //pick a topic
        if(k == 0) {
            a["target"] = "cluster";
            if(l == 0) {
                a["topic"] = "manager";
            } else {
                a["topic"] = "node";
                a["args"] = "proxy0";
            }
        } else if(k == 1) {
            a["target"] = "control";
            l = randombytes_uniform(3);
            a["topic"] = hexPrefix + hexSuffix[l];
        } else {
            a["target"] = "logs";
            if(l==0) {
                l = randombytes_uniform(nInt);
                a["topic"] = logInt[l];
            } else {
                l = randombytes_uniform(nTraf);
                a["topic"] = logTraf[l];
            }
        }
    } else {    //proxy
        auto k = randombytes_uniform(3);  //pick a target
        auto l = randombytes_uniform(2);  //pick a topic
        if(k == 0) {
            a["target"] = "cluster";
            a["topic"] = "worker";
        } else if(k == 1) {
            a["target"] = "control";
            if(l==0)
                a["topic"] = hexPrefix + hexSuffix[0];
            else {
                a["topic"] = hexPrefix + hexSuffix[2];
            }
        } else {
            a["target"] = "logs";
            if(l==0) {
                l = randombytes_uniform(nInt);
                a["topic"] = logInt[l];
            } else {
                a["topic"] = "Software::LOG";
            }
        }
    }

    if(shim.publishMsg(m, a)) {
        throw error("Couldn't form publication. Exiting");
        exit(1);
    }

    if (--Cnt > 0) {
        // publish another message after pubWait
        timer = shim.schedule(pubWait, [&shim,m](){ publish(shim, m); });
    } else {
        shim.setTimeOut(2*pubWait, [](){ std::cout << "All done here.\n"; exit(0); });
    }
}

/*
 * Main for sbtAdaptor that reads the message from the given file
 * and uses a sbtShim to publish the message
 */
int main(int argc, char* argv[])
{
    INIT_LOGGERS();
    // parse input line
    for (int c;
         (c = getopt_long(argc, argv, "f:c:dh", opts, nullptr)) != -1;) {
        switch (c) {
            case 'f':
                fname = optarg;
                break;
            case 'c':
                Cnt = std::stoi(optarg);
                break;
            case 'd':
                ++debug;
                break;
            case 'h':
                help(argv[0]);
                exit(0);
        }
    }
    if (optind >= argc) {   //needs the bundle at the end
        usage(argv[0]);
        exit(1);
    }

    sbtShim s(argv[optind]);
    role.assign(s.myRole());
    myId.assign(s.myId());

    // set up the message content to publish (stays the same)
    std::vector<uint8_t>  mesg;
    if(!fname.empty()) {
        // open the input file and read into mesg
        std::ifstream inFile (fname, std::ios::in|std::ios::binary|std::ios::ate);
        std::streampos len;
        if(inFile.is_open())
        {
            len = inFile.tellg();
            inFile.seekg (0, std::ios::beg);
            mesg.resize(len);
            if (! inFile.read((char*)mesg.data(), mesg.size())) {
                   throw std::runtime_error(format("- error: couldn't read file {}\n", fname));
            }
            inFile.close();
            std::cout << "Read file " << fname << " of size " << len << std::endl;
        } else {
            std::cout << "Unable to open file " << fname << std::endl;
            exit(1);
        }
    } else {
        std::string cs (role + ":" + myId + " approved this message.");
        mesg.assign(cs.begin(), cs.end());
    }

    /*
     * This is a prototype for invoking shim from Zeek adaptor code.
     * Shims provide an interface with a SyncPubsub object that
     * manages Collections on a single face and for a single target
     * Here target default is the SBT enclave, or all the devices on
     * this broadcast network.
     *
     * Set up shim and set the zeek type. To publish, pass the message to
     * be published, its size, and an argument list that MUST include
     * the target (message type): logs, cluster, or control and the topic.
     * May include some additional arguments
     *
     * Schedules a timeout after an appropriate wait time for the publication
     * of the message. This can be skipped or used to schedule more publication
     */

    try {
        s.init([&s,mesg]() {
                publish(s, mesg);
                s.waitForMsg(processMsg);
            });
        s.run();
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        exit(1);
    }
}
