/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "includes/headers.p4"
#include "includes/parser.p4"

const int MCAST_GRP_ID = 1; // for ARP
const bit<10> MIRROR_SESSION_RDMA_ID_IG = 10w777;	// for mirror id

control SwitchIngress(
    inout header_t hdr,
    inout metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_md_from_prsr,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_md_for_tm){

    Hash<hash_t>(HashAlgorithm_t.CRC8) flowlet_hash;

	action forward(PortId_t port){
		ig_intr_md_for_tm.ucast_egress_port=port;
	}

	action miss(bit<3> drop_bits) {
		ig_intr_md_for_dprsr.drop_ctl = drop_bits;
	}

	table ecmp_forward{
		key = {
			hdr.ethernet.dst_addr: exact;
			meta.port_index: exact;
		}
		actions = {
			forward;
			@defaultonly miss;
		}
		const default_action = miss(0x1);
	}

	action mirror_to_collector(bit<10> ing_mir_ses){
        ig_intr_md_for_dprsr.mirror_type = IG_MIRROR_TYPE_1;
        meta.mirror_session = ing_mir_ses;
		meta.ig_mirror1.ingress_mac_timestamp = ig_intr_md.ingress_mac_tstamp;
		meta.ig_mirror1.opcode = hdr.bth.opcode;
		meta.ig_mirror1.mirrored = (bit<8>)IG_MIRROR_TYPE_1;
    }


	apply {
		if(hdr.ethernet.ether_type == (bit<16>) ether_type_t.ARP){
			// do the broadcast to all involved ports
			ig_intr_md_for_tm.mcast_grp_a = MCAST_GRP_ID;
			ig_intr_md_for_tm.rid = 0;
		} else { // non-arp packet	

			// mod 4
			meta.port_index=flowlet_hash.get({hdr.ethernet.src_addr,hdr.ethernet.dst_addr,hdr.bth.destination_qp})[1:0];
			ecmp_forward.apply();

			if (hdr.bth.isValid()){ // if RDMA
				#ifdef IG_MIRRORING_ENABLED
				mirror_to_collector(MIRROR_SESSION_RDMA_ID_IG); // ig_mirror all RDMA packets
				#endif
			}
		}
	}

}  // End of SwitchIngressControl





/*******************
 * Egress Pipeline *
 * *****************/

control SwitchEgress(
    inout header_t hdr,
    inout metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport){


	apply{
		#ifdef IG_MIRRORING_ENABLED
		if (meta.ig_mirror1.mirrored == (bit<8>)IG_MIRROR_TYPE_1) {
			/* Timestamp -> MAC Src Address*/
			hdr.ethernet.src_addr = meta.ig_mirror1.ingress_mac_timestamp; // 48 bits
			/* Sequence Number -> MAC Dst Address */
			hdr.ethernet.dst_addr = 48w0xe8ebd358a0bc;
        	hdr.udp.src_port=16w4791;
		}
		#endif

	}


} // End of SwitchEgress


Pipeline(SwitchIngressParser(),
		 SwitchIngress(),
		 SwitchIngressDeparser(),
		 SwitchEgressParser(),
		 SwitchEgress(),
		 SwitchEgressDeparser()
		 ) pipe;

Switch(pipe) main;
