#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8> UDP_PROTOCOL = 8w0x11;
/* Table Sizes */
const int IPV4_HOST_SIZE = 65536;

#ifdef USE_ALPM
const int IPV4_LPM_SIZE  = 400*1024;
#else
const int IPV4_LPM_SIZE  = 12288;
#endif


//192.168.101.8    Server1
#define Server1_ip 0xc0a86508
#define Server1_mac 0x0002c93185a0
#define Server1_p4_port 1 // 交换机端口号
#define Server1_udp_port 30001

//192.168.101.40    Server2
#define Server2_ip 0xc0a86528
#define Server2_mac 0x0002c93185a0
#define Server2_p4_port 2 // 交换机端口号
#define Server2_udp_port 30002

//192.168.101.48    Server3
#define Server3_ip 0xc0a86530
#define Server3_mac 0x0002c93185a0
#define Server3_p4_port 3 // 交换机端口号
#define Server3_udp_port 30003

//192.168.101.64    控制面
#define Controller_ip 0xc0a86540
#define Controller_mac 0x0090fb73e33f
#define Controller_p4_port 64
#define Controller_udp_port 30000

//192.168.101.24    客户端
#define Client_ip 0xc0a86518
#define Client_mac 0x3cfdfe15d4ea
#define Client_p4_port 0 // 交换机端口号

#define Switch_mac 0x112233445566

/* Harmonia MsgType*/
#define WFIRST 8w1
#define WREST 8w2
#define READ  8w0
#define WRITECOMPLETION  8w3



/* define read behavior*/
#define SKIP_IPV4_HOST 2w1
#define USE_IPV4_HOST 2w0

#define MAX_KEY_DIR_ENTRY 64*1024
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/* Standard ethernet header */
header ethernet_t {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Harmonia header */
header harmonia_h {
    bit<8> MsgType;
    bit<40> none;
    bit<32> seq_index;
    bit<32> last_commit_seq;
    bit<32> obj_id;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    harmonia_h harmonia_hdr;
}


struct entry_t {
    bit<32> obj_id;
    bit<32> seq_index;
}
    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32> obj_index;
    bit<32> obj_id;
    bit<8>  random_num;
    bit<2>  behavior;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
        
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            UDP_PROTOCOL : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            Controller_udp_port : parse_harmonia;
            Server1_udp_port : parse_harmonia;
            Server2_udp_port : parse_harmonia;
            Server3_udp_port : parse_harmonia;
            default : parse_udp2;
        }
    }

    state parse_udp2{
        transition select(hdr.udp.srcPort){
            Controller_udp_port : parse_harmonia;
            Server1_udp_port : parse_harmonia;
            Server2_udp_port : parse_harmonia;
            Server3_udp_port : parse_harmonia;
            default : accept;
        }
    }

    state parse_harmonia {
        pkt.extract(hdr.harmonia_hdr);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      ig_md,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    /****************** Hash *************************/
    Hash<bit<16>>(HashAlgorithm_t.CRC32) c_hash;

    action hash_action() {
        ig_md.obj_index[15:0] = c_hash.get(hdr.harmonia_hdr.obj_id)[15:0];
    }

    @stage(0)
    table hash_table{
        actions = {
            hash_action;
        }
        size = 1;
        const default_action = hash_action;
    }

    /****************** last_commit_seq *************************/
    Register<bit<32>, bit<32>>(32w1,32w3) reg_commit_seq; 
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_commit_seq) Commit_seq_write = {
        void apply(inout bit<32> index, out bit<32> ret){
            index = hdr.harmonia_hdr.seq_index;
            ret = index;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_commit_seq) Commit_seq_update = {
        void apply(inout bit<32> index, out bit<32> ret){
            // last_commit_seq = max(last_commit_seq, harm_hdr->seq_index);
            if (hdr.harmonia_hdr.seq_index > index){
                index = hdr.harmonia_hdr.seq_index;
                ret = index;
            }
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_commit_seq) Commit_seq_get = {
        void apply(inout bit<32> index, out bit<32> ret){
            ret = index;
        }
    };

    // update last_commit_seq = max(last_commit_seq, harm_hdr->seq_index);
    action Commit_seq_update_action() {
        Commit_seq_update.execute(32w0);
    }

    table Commit_seq_update_table {
        actions = {
            Commit_seq_update_action;
        }
        size = 1;
        const default_action = Commit_seq_update_action;
    }

    // write last_commit_seq
    action Commit_seq_write_action() {
        Commit_seq_write.execute(32w0);
    }

    table Commit_seq_write_table {
        actions = {
            Commit_seq_write_action;
        }
        size = 1;
        const default_action = Commit_seq_write_action;
    }

    // get last_commit_seq
    action Commit_seq_get_action() {
        hdr.harmonia_hdr.last_commit_seq = Commit_seq_get.execute(32w0);
    }

    table Commit_seq_get_table {
        actions = {
            Commit_seq_get_action;
        }
        size = 1;
        const default_action = Commit_seq_get_action;
    }


    /***************  current_seq  ******************/
    Register<bit<32>, bit<32>>(32w1,32w3) reg_cur_seq; //3follower，需要初始化为3
    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_cur_seq) Cur_seq_append = {
        void apply(inout bit<32> index, out bit<32> ret){
            index = index+1;
            ret = index;
        }
    };

    RegisterAction<bit<32>, bit<32>, bit<32>>(reg_cur_seq) Cur_seq_get = {
        void apply(inout bit<32> index, out bit<32> ret){
            ret = index;
        }
    };

    action cur_seq_append_action() {
        hdr.harmonia_hdr.seq_index = Cur_seq_append.execute(32w0);//index++  
    }

    table Cur_seq_append_table {
        actions = {
            cur_seq_append_action;
        }
        size = 1;
        const default_action = cur_seq_append_action;
    }

    /***************  obj_index -> entry<obj_id, seq_index>  ******************/
    Register<entry_t, bit<32>>(MAX_KEY_DIR_ENTRY,{0,0}) idx_entry_reg_array;

    RegisterAction<entry_t, bit<32>, bit<32>>(idx_entry_reg_array) Insert_entry = {
        void apply(inout entry_t entry, out bit<32> ret){
            //if (entry.obj_id==0 || entry.obj_id == hdr.harmonia_hdr.obj_id){
            // 无论是否冲突，都覆盖成新条目
            // 覆盖其它obj不会影响一致性，因为read检查dirty set时不会判断obj_id
            entry.obj_id=hdr.harmonia_hdr.obj_id;
            entry.seq_index=hdr.harmonia_hdr.seq_index;
            //}
            ret = entry.obj_id;
        }
    };

    RegisterAction<entry_t, bit<32>, bit<32>>(idx_entry_reg_array) Get_entry = {
        void apply(inout entry_t entry, out bit<32> ret){
            ret = entry.obj_id;
        }
    };

    RegisterAction<entry_t, bit<32>, bit<32>>(idx_entry_reg_array) Delete_entry = {
        void apply(inout entry_t entry, out bit<32> ret){
            if (hdr.harmonia_hdr.seq_index >= entry.seq_index){
                // 只能删除比当前seq_index小的
                if (hdr.harmonia_hdr.obj_id == entry.obj_id){
                    // 只有在obj_id相同的情况下才删除，否则有可能误删其它obj
                    entry = {0,0};
                }
            }
            ret = entry.obj_id;
        }
    };

    // insert: idx_entry_reg_array[obj_index] = <obj_id, seq_index>
    action idx_entry_insert_action(){
        Insert_entry.execute(ig_md.obj_index);
    }

    table idx_entry_insert_table {
        actions = {
            idx_entry_insert_action;
        }
        size = 1;
        const default_action = idx_entry_insert_action;
    }

    // delete: 
    // if (hdr.seq_index >= idx_entry_reg_array[obj_index].seq_index) 
    //      idx_entry_reg_array[obj_index] = 0
    action idx_entry_delete_action(){
        Delete_entry.execute(ig_md.obj_index);
    }

    table idx_entry_delete_table {
        actions = {
            idx_entry_delete_action;
        }
        size = 1;
        const default_action = idx_entry_delete_action;
    }

    // get: return idx_entry_reg_array[obj_index]
    action idx_entry_get_action(){
        ig_md.obj_id = Get_entry.execute(ig_md.obj_index);
    }

    table idx_entry_get_table {
        actions = {
            idx_entry_get_action;
        }
        size = 1;
        const default_action = idx_entry_get_action;
    }

    /****************** ipv4_host *************************/
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action ipv4_forward(bit<48> dst_mac, PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.ethernet.src_addr = Switch_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            ipv4_forward; drop;
        }
        const entries = {
            (Server1_ip):
            ipv4_forward(Server1_mac, Server1_p4_port);
            (Server2_ip):
            ipv4_forward(Server2_mac, Server2_p4_port);
            (Server3_ip):
            ipv4_forward(Server3_mac, Server3_p4_port);
            (Controller_ip):
            ipv4_forward(Controller_mac, Controller_p4_port);
            (Client_ip):
            ipv4_forward(Client_mac, Client_p4_port);
        }
        size = IPV4_HOST_SIZE;
        default_action = drop;
    }

    Random<bit<8>>() random_reg1;

    action send1() {
        ig_tm_md.ucast_egress_port = Server1_p4_port;
        hdr.udp.dstPort = Server1_udp_port;
        hdr.ipv4.dst_addr = Server1_ip;
        hdr.ethernet.src_addr = Switch_mac;
        hdr.ethernet.dst_addr = Server1_mac;
    }

    action send2() {
        ig_tm_md.ucast_egress_port = Server2_p4_port;
        hdr.udp.dstPort = Server2_udp_port;
        hdr.ipv4.dst_addr = Server2_ip;
        hdr.ethernet.src_addr = Switch_mac;
        hdr.ethernet.dst_addr = Server2_mac;
    }

    action send3() {
        ig_tm_md.ucast_egress_port = Server3_p4_port;
        hdr.udp.dstPort = Server3_udp_port;
        hdr.ipv4.dst_addr = Server3_ip;
        hdr.ethernet.src_addr = Switch_mac;
        hdr.ethernet.dst_addr = Server3_mac;
    }

    apply {
        if (hdr.ipv4.isValid()){
            ig_md.behavior=USE_IPV4_HOST;
            if (hdr.harmonia_hdr.isValid()) {
                hash_table.apply();
                if (hdr.harmonia_hdr.MsgType == WFIRST) {
                    Cur_seq_append_table.apply();
                    idx_entry_insert_table.apply();
                }
                else if (hdr.harmonia_hdr.MsgType == READ) {
                    ig_md.obj_id=32w0;
                    idx_entry_get_table.apply();
                    if(ig_md.obj_id == 32w0 ){ // not in the dirty set, random choose a replica
                        Commit_seq_get_table.apply();
                        // random choose a replica, skip ipv4_host
                        ig_md.behavior=SKIP_IPV4_HOST;
                        ig_md.random_num=random_reg1.get();
                        if (ig_md.random_num <= 85){
                            send3();
                        }else if (ig_md.random_num <= 170){
                            send2();
                        }else{
                            send1();
                        }
                    }
                }
                else if (hdr.harmonia_hdr.MsgType == WRITECOMPLETION) {
                    idx_entry_delete_table.apply();
                    Commit_seq_update_table.apply();
                }
                
            }
            if(ig_md.behavior!=SKIP_IPV4_HOST && hdr.ipv4.isValid()){
                ipv4_host.apply();
                if (hdr.ipv4.dst_addr == Client_ip){
                    hdr.ipv4.src_addr = Server1_ip;
                }
            }  
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    
    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr); // 这里hdr是空的
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
