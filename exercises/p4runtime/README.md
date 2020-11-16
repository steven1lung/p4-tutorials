Goal : packet fowarding with 2 hosts 2 switches







1. json file  

2. edit p4 file 


  (1)parser transition parse_ethernet
          add state parse_ethernet
         packet.extract(hdr.ethernet); //where can i find extract function
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
        state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
      }
      
   (2) finish the ingress logic (for forwarding)
        action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
   
   
   (3) add apply if ipv4 is valid in ingress process
        apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        
    (4)deparser logic
        
          control MyDeparser(packet_out packet, in headers hdr) {
          apply {
          packet.emit(hdr.ethernet);    //what does emit do
          packet.emit(hdr.ipv4);
              }
          }
 
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
