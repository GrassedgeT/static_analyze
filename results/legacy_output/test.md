[32;1m[1;3m
Invoking: `read_sv_file` with `{'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_core.sv'}`
responded: I have analyzed the module dependencies and now have a clear understanding of the design's architecture. The top-level module is `hmac`, which includes instances of `hmac_core`, `hmac_reg_top`, `prim_fifo_sync`, and other primitive modules. The `hmac_core` module is responsible for the core HMAC logic, while `hmac_reg_top` handles the register interface.

Now, I will read the source code of the Verilog files, starting with `hmac_core.sv` and `hmac.sv`, as they seem to be the most relevant to the core functionality and potential vulnerabilities. I will then analyze `hmac_reg_top.sv` for register-related issues. I will also examine `hmac_reg_pkg.sv` as it defines the register package. 
I will start by reading `hmac_core.sv`.

[0m[33;1m[1;3m/*Line1*/: // Copyright lowRISC contributors (OpenTitan project).
/*Line2*/: // Licensed under the Apache License, Version 2.0, see LICENSE for details.
/*Line3*/: // SPDX-License-Identifier: Apache-2.0
/*Line4*/: //
/*Line5*/: // HMAC Core implementation
/*Line6*/:
/*Line7*/: module hmac_core import prim_sha2_pkg::*; (
/*Line8*/:   input clk_i,
/*Line9*/:   input rst_ni,
/*Line10*/:
/*Line11*/:   input [1023:0]      secret_key_i, // {word0, word1, ..., word7}
/*Line12*/:   input               hmac_en_i,
/*Line13*/:   input digest_mode_e digest_size_i,
/*Line14*/:   input key_length_e  key_length_i,
/*Line15*/:
/*Line16*/:   input        reg_hash_start_i,
/*Line17*/:   input        reg_hash_stop_i,
/*Line18*/:   input        reg_hash_continue_i,
/*Line19*/:   input        reg_hash_process_i,
/*Line20*/:   output logic hash_done_o,
/*Line21*/:   output logic sha_hash_start_o,
/*Line22*/:   output logic sha_hash_continue_o,
/*Line23*/:   output logic sha_hash_process_o,
/*Line24*/:   input        sha_hash_done_i,
/*Line25*/:
/*Line26*/:   // fifo
/*Line27*/:   output logic        sha_rvalid_o,
/*Line28*/:   output sha_fifo32_t sha_rdata_o,
/*Line29*/:   input               sha_rready_i,
/*Line30*/:
/*Line31*/:   input               fifo_rvalid_i,
/*Line32*/:   input  sha_fifo32_t fifo_rdata_i,
/*Line33*/:   output logic        fifo_rready_o,
/*Line34*/:
/*Line35*/:   // fifo control (select and fifo write data)
/*Line36*/:   output logic       fifo_wsel_o,      // 0: from reg, 1: from digest
/*Line37*/:   output logic       fifo_wvalid_o,
/*Line38*/:   // 0: digest[0][upper], 1:digest[0][lower] .. 14: digest[7][upper], 15: digest[7][lower]
/*Line39*/:   output logic [3:0] fifo_wdata_sel_o,
/*Line40*/:   input              fifo_wready_i,
/*Line41*/:
/*Line42*/:   input  [63:0] message_length_i,
/*Line43*/:   output [63:0] sha_message_length_o,
/*Line44*/:
/*Line45*/:   output logic idle_o
/*Line46*/: );
/*Line47*/:
/*Line48*/:   localparam int unsigned BlockSizeSHA256     = 512;
/*Line49*/:   localparam int unsigned BlockSizeSHA512     = 1024;
/*Line50*/:
/*Line51*/:   localparam int unsigned BlockSizeBitsSHA256 = $clog2(BlockSizeSHA256);
/*Line52*/:   localparam int unsigned BlockSizeBitsSHA512 = $clog2(BlockSizeSHA512);
/*Line53*/:
/*Line54*/:   localparam int unsigned HashWordBitsSHA256  = $clog2($bits(sha_word32_t));
/*Line55*/:
/*Line56*/:   localparam bit [63:0] BlockSizeSHA256in64  = 64'(BlockSizeSHA256);
/*Line57*/:   localparam bit [63:0] BlockSizeSHA512in64  = 64'(BlockSizeSHA512);
/*Line58*/:
/*Line59*/:   logic hash_start;    // generated from internal state machine
/*Line60*/:   logic hash_continue; // generated from internal state machine
/*Line61*/:   logic hash_process;  // generated from internal state machine to trigger hash
/*Line62*/:   logic hmac_hash_done;
/*Line63*/:
/*Line64*/:   logic [BlockSizeSHA256-1:0] i_pad_256;
/*Line65*/:   logic [BlockSizeSHA512-1:0] i_pad_512;
/*Line66*/:   logic [BlockSizeSHA256-1:0] o_pad_256;
/*Line67*/:   logic [BlockSizeSHA512-1:0] o_pad_512;
/*Line68*/:
/*Line69*/:   logic [63:0] txcount, txcount_d; // works for both digest lengths
/*Line70*/:
/*Line71*/:   logic [BlockSizeBitsSHA512-HashWordBitsSHA256-1:0] pad_index_512;
/*Line72*/:   logic [BlockSizeBitsSHA256-HashWordBitsSHA256-1:0] pad_index_256;
/*Line73*/:   logic clr_txcount, load_txcount, inc_txcount;
/*Line74*/:
/*Line75*/:   logic hmac_sha_rvalid;
/*Line76*/:
/*Line77*/:   logic idle_d, idle_q;
/*Line78*/:   logic reg_hash_stop_d, reg_hash_stop_q;
/*Line79*/:
/*Line80*/:   typedef enum logic [1:0] {
/*Line81*/:     SelIPad,
/*Line82*/:     SelOPad,
/*Line83*/:     SelFifo
/*Line84*/:   } sel_rdata_t;
/*Line85*/:
/*Line86*/:   sel_rdata_t sel_rdata;
/*Line87*/:
/*Line88*/:   typedef enum logic {
/*Line89*/:     SelIPadMsg,
/*Line90*/:     SelOPadMsg
/*Line91*/:   } sel_msglen_t;
/*Line92*/:
/*Line93*/:   sel_msglen_t sel_msglen;
/*Line94*/:
/*Line95*/:   typedef enum logic {
/*Line96*/:     Inner,  // Update when state goes to StIPad
/*Line97*/:     Outer   // Update when state enters StOPad
/*Line98*/:   } round_t ;
/*Line99*/:
/*Line100*/:   logic update_round ;
/*Line101*/:   round_t round_q, round_d;
/*Line102*/:
/*Line103*/:   typedef enum logic [2:0] {
/*Line104*/:     StIdle,
/*Line105*/:     StIPad,
/*Line106*/:     StMsg,              // Actual Msg, and Digest both
/*Line107*/:     StPushToMsgFifo,    // Digest --> Msg Fifo
/*Line108*/:     StWaitResp,         // Hash done( by checking processed_length? or hash_done)
/*Line109*/:     StOPad,
/*Line110*/:     StDone              // hmac_done
/*Line111*/:   } st_e ;
/*Line112*/:
/*Line113*/:   st_e st_q, st_d;
/*Line114*/:
/*Line115*/:   logic clr_fifo_wdata_sel;
/*Line116*/:   logic txcnt_eq_blksz;
/*Line117*/:
/*Line118*/:   logic reg_hash_process_flag;
/*Line119*/:
/*Line120*/:   assign sha_hash_start_o    = (hmac_en_i) ? hash_start    : reg_hash_start_i;
/*Line121*/:   assign sha_hash_continue_o = (hmac_en_i) ? hash_continue : reg_hash_continue_i;
/*Line122*/:
/*Line123*/:   assign sha_hash_process_o  = (hmac_en_i) ? reg_hash_process_i | hash_process : reg_hash_process_i;
/*Line124*/:   assign hash_done_o         = (hmac_en_i) ? hmac_hash_done                    : sha_hash_done_i;
/*Line125*/:
/*Line126*/:   assign pad_index_512 = txcount[BlockSizeBitsSHA512-1:HashWordBitsSHA256];
/*Line127*/:   assign pad_index_256 = txcount[BlockSizeBitsSHA256-1:HashWordBitsSHA256];
/*Line128*/:
/*Line129*/:   // adjust inner and outer padding depending on key length and block size
/*Line130*/:   always_comb begin : adjust_key_pad_length
/*Line131*/:     // set defaults
/*Line132*/:     i_pad_256 = '{default: '0};
/*Line133*/:     i_pad_512 = '{default: '0};
/*Line134*/:     o_pad_256 = '{default: '0};
/*Line135*/:     o_pad_512 = '{default: '0};
/*Line136*/:
/*Line137*/:     unique case (key_length_i)
/*Line138*/:       Key_128: begin
/*Line139*/:         i_pad_256 = {secret_key_i[1023:896],
/*Line140*/:                     {(BlockSizeSHA256-128){1'b0}}} ^ {(BlockSizeSHA256/8){8'h36}};
/*Line141*/:         i_pad_512 = {secret_key_i[1023:896],
/*Line142*/:                     {(BlockSizeSHA512-128){1'b0}}} ^ {(BlockSizeSHA512/8){8'h36}};
/*Line143*/:         o_pad_256 = {secret_key_i[1023:896],
/*Line144*/:                     {(BlockSizeSHA256-128){1'b0}}} ^ {(BlockSizeSHA256/8){8'h5c}};
/*Line145*/:         o_pad_512 = {secret_key_i[1023:896],
/*Line146*/:                     {(BlockSizeSHA512-128){1'b0}}} ^ {(BlockSizeSHA512/8){8'h5c}};
/*Line147*/:       end
/*Line148*/:       Key_256: begin
/*Line149*/:         i_pad_256 = {secret_key_i[1023:768],
/*Line150*/:                     {(BlockSizeSHA256-256){1'b0}}} ^ {(BlockSizeSHA256/8){8'h36}};
/*Line151*/:         i_pad_512 = {secret_key_i[1023:768],
/*Line152*/:                     {(BlockSizeSHA512-256){1'b0}}} ^ {(BlockSizeSHA512/8){8'h36}};
/*Line153*/:         o_pad_256 = {secret_key_i[1023:768],
/*Line154*/:                     {(BlockSizeSHA256-256){1'b0}}} ^ {(BlockSizeSHA256/8){8'h5c}};
/*Line155*/:         o_pad_512 = {secret_key_i[1023:768],
/*Line156*/:                     {(BlockSizeSHA512-256){1'b0}}} ^ {(BlockSizeSHA512/8){8'h5c}};
/*Line157*/:       end
/*Line158*/:       Key_384: begin
/*Line159*/:         i_pad_256 = {secret_key_i[1023:640],
/*Line160*/:                     {(BlockSizeSHA256-384){1'b0}}} ^ {(BlockSizeSHA256/8){8'h36}};
/*Line161*/:         i_pad_512 = {secret_key_i[1023:640],
/*Line162*/:                     {(BlockSizeSHA512-384){1'b0}}} ^ {(BlockSizeSHA512/8){8'h36}};
/*Line163*/:         o_pad_256 = {secret_key_i[1023:640],
/*Line164*/:                     {(BlockSizeSHA256-384){1'b0}}} ^ {(BlockSizeSHA256/8){8'h5c}};
/*Line165*/:         o_pad_512 = {secret_key_i[1023:640],
/*Line166*/:                     {(BlockSizeSHA512-384){1'b0}}} ^ {(BlockSizeSHA512/8){8'h5c}};
/*Line167*/:       end
/*Line168*/:       Key_512: begin
/*Line169*/:         i_pad_256 = secret_key_i[1023:512] ^ {(BlockSizeSHA256/8){8'h36}};
/*Line170*/:         i_pad_512 = {secret_key_i[1023:512],
/*Line171*/:                     {(BlockSizeSHA512-512){1'b0}}} ^ {(BlockSizeSHA512/8){8'h36}};
/*Line172*/:         o_pad_256 = secret_key_i[1023:512] ^ {(BlockSizeSHA256/8){8'h5c}};
/*Line173*/:         o_pad_512 = {secret_key_i[1023:512],
/*Line174*/:                     {(BlockSizeSHA512-512){1'b0}}} ^ {(BlockSizeSHA512/8){8'h5c}};
/*Line175*/:       end
/*Line176*/:       Key_1024: begin // not allowed to be configured for SHA-2 256
/*Line177*/:         // zero out for SHA-2 256
/*Line178*/:         i_pad_256 = '{default: '0};
/*Line179*/:         i_pad_512 = secret_key_i[1023:0]   ^ {(BlockSizeSHA512/8){8'h36}};
/*Line180*/:         // zero out for SHA-2 256
/*Line181*/:         o_pad_256 = '{default: '0};
/*Line182*/:         o_pad_512 = secret_key_i[1023:0]   ^ {(BlockSizeSHA512/8){8'h5c}};
/*Line183*/:       end
/*Line184*/:       default: begin
/*Line185*/:       end
/*Line186*/:     endcase
/*Line187*/:   end
/*Line188*/:
/*Line189*/:   assign fifo_rready_o = (hmac_en_i) ? (st_q == StMsg) & sha_rready_i : sha_rready_i ;
/*Line190*/:   // sha_rvalid is controlled by State Machine below.
/*Line191*/:   assign sha_rvalid_o  = (!hmac_en_i) ? fifo_rvalid_i : hmac_sha_rvalid ;
/*Line192*/:   assign sha_rdata_o =
/*Line193*/:     (!hmac_en_i)    ? fifo_rdata_i                                                             :
/*Line194*/:     (sel_rdata == SelIPad && digest_size_i == SHA2_256)
/*Line195*/:                   ? '{data: i_pad_256[(BlockSizeSHA256-1)-32*pad_index_256-:32], mask: '1} :
/*Line196*/:     (sel_rdata == SelIPad && ((digest_size_i == SHA2_384) || (digest_size_i == SHA2_512)))
/*Line197*/:                   ? '{data: i_pad_512[(BlockSizeSHA512-1)-32*pad_index_512-:32], mask: '1} :
/*Line198*/:     (sel_rdata == SelOPad && digest_size_i == SHA2_256)
/*Line199*/:                   ? '{data: o_pad_256[(BlockSizeSHA256-1)-32*pad_index_256-:32], mask: '1} :
/*Line200*/:     (sel_rdata == SelOPad && ((digest_size_i == SHA2_384) || (digest_size_i == SHA2_512)))
/*Line201*/:                   ? '{data: o_pad_512[(BlockSizeSHA512-1)-32*pad_index_512-:32], mask: '1} :
/*Line202*/:     (sel_rdata == SelFifo) ? fifo_rdata_i                                                    :
/*Line203*/:                   '{default: '0};
/*Line204*/:
/*Line205*/:   logic [63:0] sha_msg_len;
/*Line206*/:
/*Line207*/:   always_comb begin: assign_sha_message_length
/*Line208*/:     sha_msg_len = '0;
/*Line209*/:     if (!hmac_en_i) begin
/*Line210*/:       sha_msg_len = message_length_i;
/*Line211*/:     // HASH = (o_pad || HASH_INTERMEDIATE (i_pad || msg))
/*Line212*/:     // message length for HASH_INTERMEDIATE = block size (i_pad) + message length
/*Line213*/:     end else if (sel_msglen == SelIPadMsg) begin
/*Line214*/:       if (digest_size_i == SHA2_256) begin
/*Line215*/:         sha_msg_len = message_length_i + BlockSizeSHA256in64;
/*Line216*/:       end else if ((digest_size_i == SHA2_384) || (digest_size_i == SHA2_512)) begin
/*Line217*/:         sha_msg_len = message_length_i + BlockSizeSHA512in64;
/*Line218*/:       end
/*Line219*/:     end else if (sel_msglen == SelOPadMsg) begin
/*Line220*/:     // message length for HASH = block size (o_pad) + HASH_INTERMEDIATE digest length
/*Line221*/:       if (digest_size_i == SHA2_256) begin
/*Line222*/:         sha_msg_len = BlockSizeSHA256in64 + 64'd256;
/*Line223*/:       end else if (digest_size_i == SHA2_384) begin
/*Line224*/:         sha_msg_len = BlockSizeSHA512in64 + 64'd384;
/*Line225*/:       end else if (digest_size_i == SHA2_512) begin
/*Line226*/:         sha_msg_len = BlockSizeSHA512in64 + 64'd512;
/*Line227*/:       end
/*Line228*/:     end else
/*Line229*/:       sha_msg_len = '0;
/*Line230*/:   end
/*Line231*/:
/*Line232*/:   assign sha_message_length_o = sha_msg_len;
/*Line233*/:
/*Line234*/:   always_comb begin
/*Line235*/:     txcnt_eq_blksz = '0;
/*Line236*/:
/*Line237*/:     unique case (digest_size_i)
/*Line238*/:       SHA2_256: txcnt_eq_blksz = (txcount[BlockSizeBitsSHA256-1:0] == '0) && (txcount != '0);
/*Line239*/:       SHA2_384: txcnt_eq_blksz = (txcount[BlockSizeBitsSHA512-1:0] == '0) && (txcount != '0);
/*Line240*/:       SHA2_512: txcnt_eq_blksz = (txcount[BlockSizeBitsSHA512-1:0] == '0) && (txcount != '0);
/*Line241*/:       default;
/*Line242*/:     endcase
/*Line243*/:   end
/*Line244*/:
/*Line245*/:   assign inc_txcount = sha_rready_i && sha_rvalid_o;
/*Line246*/:
/*Line247*/:   // txcount
/*Line248*/:   //    Looks like txcount can be removed entirely here in hmac_core
/*Line249*/:   //    In the first round (InnerPaddedKey), it can just watch process and hash_done
/*Line250*/:   //    In the second round, it only needs count 256 bits for hash digest to trigger
/*Line251*/:   //    hash_process to SHA2
/*Line252*/:   always_comb begin
/*Line253*/:     txcount_d = txcount;
/*Line254*/:     if (clr_txcount) begin
/*Line255*/:       txcount_d = '0;
/*Line256*/:     end else if (load_txcount) begin
/*Line257*/:       // When loading, add block size to the message length because the SW-visible message length
/*Line258*/:       // does not include the block containing the key xor'ed with the inner pad.
/*Line259*/:       unique case (digest_size_i)
/*Line260*/:         SHA2_256: txcount_d = message_length_i + BlockSizeSHA256in64;
/*Line261*/:         SHA2_384: txcount_d = message_length_i + BlockSizeSHA512in64;
/*Line262*/:         SHA2_512: txcount_d = message_length_i + BlockSizeSHA512in64;
/*Line263*/:         default : txcount_d = message_length_i + '0;
/*Line264*/:       endcase
/*Line265*/:     end else if (inc_txcount) begin
/*Line266*/:       txcount_d[63:5] = txcount[63:5] + 1'b1; // increment by 32 (data word size)
/*Line267*/:     end
/*Line268*/:   end
/*Line269*/:
/*Line270*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line271*/:     if (!rst_ni) txcount <= '0;
/*Line272*/:     else         txcount <= txcount_d;
/*Line273*/:   end
/*Line274*/:
/*Line275*/:   // reg_hash_process_i trigger logic
/*Line276*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line277*/:     if (!rst_ni) begin
/*Line278*/:       reg_hash_process_flag <= 1'b0;
/*Line279*/:     end else if (reg_hash_process_i) begin
/*Line280*/:       reg_hash_process_flag <= 1'b1;
/*Line281*/:     end else if (hmac_hash_done || reg_hash_start_i || reg_hash_continue_i) begin
/*Line282*/:       reg_hash_process_flag <= 1'b0;
/*Line283*/:     end
/*Line284*/:   end
/*Line285*/:
/*Line286*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line287*/:     if (!rst_ni) begin
/*Line288*/:       round_q <= Inner;
/*Line289*/:     end else if (update_round) begin
/*Line290*/:       round_q <= round_d;
/*Line291*/:     end
/*Line292*/:   end
/*Line293*/:
/*Line294*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line295*/:     if (!rst_ni) begin
/*Line296*/:       fifo_wdata_sel_o <= 3'h 0;
/*Line297*/:     end else if (clr_fifo_wdata_sel) begin
/*Line298*/:       fifo_wdata_sel_o <= 3'h 0;
/*Line299*/:     end else if (fifo_wsel_o && fifo_wvalid_o) begin
/*Line300*/:       fifo_wdata_sel_o <= fifo_wdata_sel_o + 1'b1; // increment by 1
/*Line301*/:     end
/*Line302*/:   end
/*Line303*/:
/*Line304*/:   assign sel_msglen = (round_q == Inner) ? SelIPadMsg : SelOPadMsg ;
/*Line305*/:
/*Line306*/:   always_ff @(posedge clk_i or negedge rst_ni) begin : state_ff
/*Line307*/:     if (!rst_ni) st_q <= StIdle;
/*Line308*/:     else         st_q <= st_d;
/*Line309*/:   end
/*Line310*/:
/*Line311*/:   always_comb begin : next_state
/*Line312*/:     hmac_hash_done     = 1'b0;
/*Line313*/:     hmac_sha_rvalid    = 1'b0;
/*Line314*/:     clr_txcount        = 1'b0;
/*Line315*/:     load_txcount       = 1'b0;
/*Line316*/:     update_round       = 1'b0;
/*Line317*/:     round_d            = Inner;
/*Line318*/:     fifo_wsel_o        = 1'b0;   // from register
/*Line319*/:     fifo_wvalid_o      = 1'b0;
/*Line320*/:     clr_fifo_wdata_sel = 1'b1;
/*Line321*/:     sel_rdata          = SelFifo;
/*Line322*/:     hash_start         = 1'b0;
/*Line323*/:     hash_continue      = 1'b0;
/*Line324*/:     hash_process       = 1'b0;
/*Line325*/:     st_d               = st_q;
/*Line326*/:
/*Line327*/:     unique case (st_q)
/*Line328*/:       StIdle: begin
/*Line329*/:         // reset round to Inner
/*Line330*/:         // we always switch context into inner round since outer round computes once over
/*Line331*/:         // single block at the end (outer key pad + inner hash)
/*Line332*/:         update_round = 1'b1;
/*Line333*/:         round_d      = Inner;
/*Line334*/:         if (hmac_en_i && reg_hash_start_i) begin
/*Line335*/:           st_d = StIPad; // start at StIPad if told to start
/*Line336*/:
/*Line337*/:           clr_txcount  = 1'b1;
/*Line338*/:           hash_start   = 1'b1;
/*Line339*/:         end else if (hmac_en_i && reg_hash_continue_i) begin
/*Line340*/:           st_d = StMsg; // skip StIPad if told to continue - assumed it finished StIPad
/*Line341*/:
/*Line342*/:           load_txcount  = 1'b1;
/*Line343*/:           hash_continue = 1'b1;
/*Line344*/:         end else begin
/*Line345*/:           st_d = StIdle;
/*Line346*/:         end
/*Line347*/:       end
/*Line348*/:
/*Line349*/:       StIPad: begin
/*Line350*/:         sel_rdata = SelIPad;
/*Line351*/:
/*Line352*/:         if (txcnt_eq_blksz) begin
/*Line353*/:           st_d = StMsg;
/*Line354*/:
/*Line355*/:           hmac_sha_rvalid = 1'b0; // block new read request
/*Line356*/:         end else begin
/*Line357*/:           st_d = StIPad;
/*Line358*/:
/*Line359*/:           hmac_sha_rvalid = 1'b1;
/*Line360*/:         end
/*Line361*/:       end
/*Line362*/:
/*Line363*/:       StMsg: begin
/*Line364*/:         sel_rdata   = SelFifo;
/*Line365*/:         fifo_wsel_o = (round_q == Outer);
/*Line366*/:
/*Line367*/:         if ( (((round_q == Inner) && reg_hash_process_flag) || (round_q == Outer))
/*Line368*/:             && (txcount >= sha_message_length_o)) begin
/*Line369*/:           st_d    = StWaitResp;
/*Line370*/:
/*Line371*/:           hmac_sha_rvalid = 1'b0; // block reading words from MSG FIFO
/*Line372*/:           hash_process    = (round_q == Outer);
/*Line373*/:         end else if (txcnt_eq_blksz && (txcount >= sha_message_length_o)
/*Line374*/:                      && reg_hash_stop_q && (round_q == Inner)) begin
/*Line375*/:           // wait till all MSG words are pushed out from FIFO (txcount reaches msg length)
/*Line376*/:           // before transitioning to StWaitResp to wait on sha_hash_done_i and disabling
/*Line377*/:           // reading from MSG FIFO
/*Line378*/:           st_d =  StWaitResp;
/*Line379*/:
/*Line380*/:           hmac_sha_rvalid = 1'b0;
/*Line381*/:         end else begin
/*Line382*/:           st_d            = StMsg;
/*Line383*/:           hmac_sha_rvalid = fifo_rvalid_i;
/*Line384*/:         end
/*Line385*/:       end
/*Line386*/:
/*Line387*/:       StWaitResp: begin
/*Line388*/:         hmac_sha_rvalid = 1'b0;
/*Line389*/:
/*Line390*/:         if (sha_hash_done_i) begin
/*Line391*/:           if (round_q == Outer) begin
/*Line392*/:             st_d = StDone;
/*Line393*/:           end else begin // round_q == Inner
/*Line394*/:             if (reg_hash_stop_q) begin
/*Line395*/:               st_d = StDone;
/*Line396*/:             end else begin
/*Line397*/:               st_d = StPushToMsgFifo;
/*Line398*/:             end
/*Line399*/:           end
/*Line400*/:         end else begin
/*Line401*/:           st_d = StWaitResp;
/*Line402*/:         end
/*Line403*/:       end
/*Line404*/:
/*Line405*/:       StPushToMsgFifo: begin
/*Line406*/:         hmac_sha_rvalid    = 1'b0;
/*Line407*/:         fifo_wsel_o        = 1'b1;
/*Line408*/:         fifo_wvalid_o      = 1'b1;
/*Line409*/:         clr_fifo_wdata_sel = 1'b0;
/*Line410*/:
/*Line411*/:         if (fifo_wready_i && (((fifo_wdata_sel_o == 4'd7) && (digest_size_i == SHA2_256)) ||
/*Line412*/:                              ((fifo_wdata_sel_o == 4'd15) && (digest_size_i == SHA2_512)) ||
/*Line413*/:                              ((fifo_wdata_sel_o == 4'd11) && (digest_size_i == SHA2_384)))) begin
/*Line414*/:
/*Line415*/:           st_d = StOPad;
/*Line416*/:
/*Line417*/:           clr_txcount  = 1'b1;
/*Line418*/:           update_round = 1'b1;
/*Line419*/:           round_d      = Outer;
/*Line420*/:           hash_start   = 1'b1;
/*Line421*/:         end else begin
/*Line422*/:           st_d = StPushToMsgFifo;
/*Line423*/:
/*Line424*/:         end
/*Line425*/:       end
/*Line426*/:
/*Line427*/:       StOPad: begin
/*Line428*/:         sel_rdata   = SelOPad;
/*Line429*/:         fifo_wsel_o = 1'b1; // Remained HMAC select to indicate HMAC is in second stage
/*Line430*/:
/*Line431*/:         if (txcnt_eq_blksz) begin
/*Line432*/:           st_d = StMsg;
/*Line433*/:
/*Line434*/:           hmac_sha_rvalid = 1'b0; // block new read request
/*Line435*/:         end else begin
/*Line436*/:           st_d = StOPad;
/*Line437*/:
/*Line438*/:           hmac_sha_rvalid = 1'b1;
/*Line439*/:         end
/*Line440*/:       end
/*Line441*/:
/*Line442*/:       StDone: begin
/*Line443*/:         // raise interrupt (hash_done)
/*Line444*/:         st_d = StIdle;
/*Line445*/:
/*Line446*/:         hmac_hash_done = 1'b1;
/*Line447*/:       end
/*Line448*/:
/*Line449*/:       default: begin
/*Line450*/:         st_d = StIdle;
/*Line451*/:       end
/*Line452*/:
/*Line453*/:     endcase
/*Line454*/:   end
/*Line455*/:
/*Line456*/:   // raise reg_hash_stop_d flag at reg_hash_stop_i and keep it until sha_hash_done_i is asserted
/*Line457*/:   // to indicate the hashing operation on current block has completed
/*Line458*/:   assign reg_hash_stop_d = (reg_hash_stop_i == 1'b1)                            ? 1'b1 :
/*Line459*/:                            (sha_hash_done_i == 1'b1 && reg_hash_stop_q == 1'b1) ? 1'b0 :
/*Line460*/:                                                                                   reg_hash_stop_q;
/*Line461*/:
/*Line462*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line463*/:     if (!rst_ni) begin
/*Line464*/:       reg_hash_stop_q <= 1'b0;
/*Line465*/:     end else begin
/*Line466*/:       reg_hash_stop_q <= reg_hash_stop_d;
/*Line467*/:     end
/*Line468*/:   end
/*Line469*/:
/*Line470*/:   // Idle status signaling: This module ..
/*Line471*/:   assign idle_d =
/*Line472*/:       // .. is not idle when told to start or continue
/*Line473*/:       (reg_hash_start_i || reg_hash_continue_i) ? 1'b0 :
/*Line474*/:       // .. is idle when the FSM is in the Idle state
/*Line475*/:       (st_q == StIdle) ? 1'b1 :
/*Line476*/:       // .. is idle when it has processed a complete block of a message and is told to stop in any
/*Line477*/:       // FSM state
/*Line478*/:       (txcnt_eq_blksz && reg_hash_stop_d) ? 1'b1 :
/*Line479*/:       // .. and keeps the current idle state in all other cases.
/*Line480*/:       idle_q;
/*Line481*/:
/*Line482*/:   assign idle_o = idle_d;
/*Line483*/:
/*Line484*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line485*/:     if (!rst_ni) begin
/*Line486*/:       idle_q <= 1'b1;
/*Line487*/:     end else begin
/*Line488*/:       idle_q <= idle_d;
/*Line489*/:     end
/*Line490*/:   end
/*Line491*/: endmodule
/*Line492*/:[0mError in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_start callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
[32;1m[1;3m
Invoking: `read_sv_file` with `{'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac.sv'}`
responded: I have read the `hmac_core.sv` file. Now I will read `hmac.sv`.

[0m[33;1m[1;3m/*Line1*/: // Copyright lowRISC contributors (OpenTitan project).
/*Line2*/: // Licensed under the Apache License, Version 2.0, see LICENSE for details.
/*Line3*/: // SPDX-License-Identifier: Apache-2.0
/*Line4*/: //
/*Line5*/: // HMAC/SHA-2 256/384/512
/*Line6*/:
/*Line7*/: `include "prim_assert.sv"
/*Line8*/:
/*Line9*/: module hmac
/*Line10*/:   import prim_sha2_pkg::*;
/*Line11*/:   import hmac_reg_pkg::*;
/*Line12*/: #(
/*Line13*/:   parameter logic [NumAlerts-1:0] AlertAsyncOn = {NumAlerts{1'b1}}
/*Line14*/: ) (
/*Line15*/:   input clk_i,
/*Line16*/:   input rst_ni,
/*Line17*/:
/*Line18*/:   input  tlul_pkg::tl_h2d_t tl_i,
/*Line19*/:   output tlul_pkg::tl_d2h_t tl_o,
/*Line20*/:
/*Line21*/:   input  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx_i,
/*Line22*/:   output prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx_o,
/*Line23*/:
/*Line24*/:   output logic intr_hmac_done_o,
/*Line25*/:   output logic intr_fifo_empty_o,
/*Line26*/:   output logic intr_hmac_err_o,
/*Line27*/:
/*Line28*/:   output prim_mubi_pkg::mubi4_t idle_o
/*Line29*/: );
/*Line30*/:
/*Line31*/:
/*Line32*/:   /////////////////////////
/*Line33*/:   // Signal declarations //
/*Line34*/:   /////////////////////////
/*Line35*/:   hmac_reg2hw_t reg2hw;
/*Line36*/:   hmac_hw2reg_t hw2reg;
/*Line37*/:
/*Line38*/:   tlul_pkg::tl_h2d_t  tl_win_h2d;
/*Line39*/:   tlul_pkg::tl_d2h_t  tl_win_d2h;
/*Line40*/:
/*Line41*/:   logic [1023:0] secret_key, secret_key_d;
/*Line42*/:
/*Line43*/:   // Logic will support key length <= block size
/*Line44*/:   // Will default to key length = block size, if key length > block size or unsupported value
/*Line45*/:   key_length_e key_length_supplied, key_length;
/*Line46*/:
/*Line47*/:   logic        wipe_secret;
/*Line48*/:   logic [31:0] wipe_v;
/*Line49*/:
/*Line50*/:   logic        fifo_rvalid;
/*Line51*/:   logic        fifo_rready;
/*Line52*/:   sha_fifo32_t fifo_rdata;
/*Line53*/:
/*Line54*/:   logic        fifo_wvalid, fifo_wready;
/*Line55*/:   sha_fifo32_t fifo_wdata;
/*Line56*/:   logic        fifo_full;
/*Line57*/:   logic        fifo_empty;
/*Line58*/:   logic [5:0]  fifo_depth;
/*Line59*/:
/*Line60*/:   logic        msg_fifo_req;
/*Line61*/:   logic        msg_fifo_gnt;
/*Line62*/:   logic        msg_fifo_we;
/*Line63*/:   logic [31:0] msg_fifo_wdata;
/*Line64*/:   logic [31:0] msg_fifo_wmask;
/*Line65*/:   logic [31:0] msg_fifo_rdata;
/*Line66*/:   logic        msg_fifo_rvalid;
/*Line67*/:   logic [1:0]  msg_fifo_rerror;
/*Line68*/:   logic [31:0] msg_fifo_wdata_endian;
/*Line69*/:   logic [31:0] msg_fifo_wmask_endian;
/*Line70*/:
/*Line71*/:   logic        packer_ready;
/*Line72*/:   logic        packer_flush_done;
/*Line73*/:
/*Line74*/:   logic         reg_fifo_wvalid;
/*Line75*/:   sha_word32_t  reg_fifo_wdata;
/*Line76*/:   sha_word32_t  reg_fifo_wmask;
/*Line77*/:   logic         hmac_fifo_wsel;
/*Line78*/:   logic         hmac_fifo_wvalid;
/*Line79*/:   logic [3:0]   hmac_fifo_wdata_sel;
/*Line80*/:
/*Line81*/:   logic         shaf_rvalid;
/*Line82*/:   sha_fifo32_t  shaf_rdata;
/*Line83*/:   logic         shaf_rready;
/*Line84*/:
/*Line85*/:   logic        sha_en;
/*Line86*/:   logic        hmac_en;
/*Line87*/:   logic        endian_swap;
/*Line88*/:   logic        digest_swap;
/*Line89*/:   logic        key_swap;
/*Line90*/:
/*Line91*/:   logic        reg_hash_start;
/*Line92*/:   logic        sha_hash_start;
/*Line93*/:   logic        reg_hash_stop;
/*Line94*/:   logic        reg_hash_continue;
/*Line95*/:   logic        sha_hash_continue;
/*Line96*/:   logic        hash_start;     // hash_start is reg_hash_start gated with extra checks
/*Line97*/:   logic        hash_continue;  // hash_continue is reg_hash_continue gated with extra checks
/*Line98*/:   logic        hash_process;   // hash_process is reg_hash_process gated with extra checks
/*Line99*/:   logic        hash_start_or_continue;
/*Line100*/:   logic        hash_done_event;
/*Line101*/:   logic        reg_hash_process;
/*Line102*/:   logic        sha_hash_process;
/*Line103*/:   logic        digest_on_blk;
/*Line104*/:
/*Line105*/:   logic        reg_hash_done;
/*Line106*/:   logic        sha_hash_done;
/*Line107*/:
/*Line108*/:   logic [63:0] message_length, message_length_d;
/*Line109*/:   logic [63:0] sha_message_length;
/*Line110*/:
/*Line111*/:   err_code_e  err_code;
/*Line112*/:   logic       err_valid;
/*Line113*/:   logic       invalid_config; // HMAC/SHA-2 is configured with invalid digest size/key length
/*Line114*/:   logic       invalid_config_atstart;
/*Line115*/:
/*Line116*/:   sha_word64_t [7:0] digest, digest_sw;
/*Line117*/:   logic [7:0]        digest_sw_we;
/*Line118*/:
/*Line119*/:   digest_mode_e digest_size, digest_size_supplied;
/*Line120*/:   // this is the digest size captured into HMAC when it gets started
/*Line121*/:   digest_mode_e digest_size_started_d, digest_size_started_q;
/*Line122*/:
/*Line123*/:   hmac_reg2hw_cfg_reg_t cfg_reg;
/*Line124*/:   logic                 cfg_block;   // Prevents changing config
/*Line125*/:   logic                 msg_allowed; // MSG_FIFO from software is allowed
/*Line126*/:
/*Line127*/:   logic hmac_core_idle;
/*Line128*/:   logic sha_core_idle;
/*Line129*/:   logic hash_running;
/*Line130*/:   logic idle;
/*Line131*/:
/*Line132*/:   ///////////////////////
/*Line133*/:   // Connect registers //
/*Line134*/:   ///////////////////////
/*Line135*/:   assign hw2reg.status.fifo_full.d  = fifo_full;
/*Line136*/:   assign hw2reg.status.fifo_empty.d = fifo_empty;
/*Line137*/:   assign hw2reg.status.fifo_depth.d = fifo_depth;
/*Line138*/:   assign hw2reg.status.hmac_idle.d  = idle;
/*Line139*/:
/*Line140*/:   typedef enum logic [1:0] {
/*Line141*/:     DoneAwaitCmd,
/*Line142*/:     DoneAwaitHashDone,
/*Line143*/:     DoneAwaitMessageComplete,
/*Line144*/:     DoneAwaitHashComplete
/*Line145*/:   } done_state_e;
/*Line146*/:
/*Line147*/:   done_state_e done_state_d, done_state_q;
/*Line148*/:
/*Line149*/:   always_comb begin
/*Line150*/:     done_state_d    = done_state_q;
/*Line151*/:     hash_done_event = 1'b0;
/*Line152*/:
/*Line153*/:     unique case (done_state_q)
/*Line154*/:       DoneAwaitCmd: begin
/*Line155*/:         if (sha_hash_process) begin
/*Line156*/:           // SHA has been told to process the message, so signal *done* when the hash is done.
/*Line157*/:           done_state_d = DoneAwaitHashDone;
/*Line158*/:         end else if (reg_hash_stop) begin
/*Line159*/:           // SHA has been told to stop, so first wait for the current message block to be complete.
/*Line160*/:           done_state_d = DoneAwaitMessageComplete;
/*Line161*/:         end
/*Line162*/:       end
/*Line163*/:
/*Line164*/:       DoneAwaitHashDone: begin
/*Line165*/:         if (reg_hash_done) begin
/*Line166*/:           hash_done_event = 1'b1;
/*Line167*/:           done_state_d = DoneAwaitCmd;
/*Line168*/:         end
/*Line169*/:       end
/*Line170*/:
/*Line171*/:       DoneAwaitMessageComplete: begin
/*Line172*/:         if (digest_on_blk) begin
/*Line173*/:           // Once the digest is being computed for the complete message block, wait for the hash to
/*Line174*/:           // complete.
/*Line175*/:           // TODO (issue #21710): handle incomplete message size and check against 512 or 1024
/*Line176*/:           done_state_d = DoneAwaitHashComplete;
/*Line177*/:         end
/*Line178*/:       end
/*Line179*/:
/*Line180*/:       DoneAwaitHashComplete: begin
/*Line181*/:         if (!hash_running) begin
/*Line182*/:           hash_done_event = 1'b1;
/*Line183*/:           done_state_d = DoneAwaitCmd;
/*Line184*/:         end
/*Line185*/:       end
/*Line186*/:
/*Line187*/:       default: ;
/*Line188*/:     endcase
/*Line189*/:   end
/*Line190*/:
/*Line191*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line192*/:     if (!rst_ni) begin
/*Line193*/:       done_state_q <= DoneAwaitCmd;
/*Line194*/:     end else begin
/*Line195*/:       done_state_q <= done_state_d;
/*Line196*/:     end
/*Line197*/:   end
/*Line198*/:
/*Line199*/:   assign wipe_secret = reg2hw.wipe_secret.qe;
/*Line200*/:   assign wipe_v      = reg2hw.wipe_secret.q;
/*Line201*/:
/*Line202*/:   // update secret key
/*Line203*/:   always_comb begin : update_secret_key
/*Line204*/:     secret_key_d = secret_key;
/*Line205*/:     if (wipe_secret) begin
/*Line206*/:       secret_key_d = {32{wipe_v}};
/*Line207*/:     end else if (!cfg_block) begin
/*Line208*/:       // Allow updating secret key only when the engine is in Idle.
/*Line209*/:       for (int i = 0; i < 32; i++) begin
/*Line210*/:         if (reg2hw.key[31-i].qe) begin
/*Line211*/:           // swap byte endianness per secret key word if key_swap = 1
/*Line212*/:           secret_key_d[32*i+:32] = conv_endian32(reg2hw.key[31-i].q, key_swap);
/*Line213*/:         end
/*Line214*/:       end
/*Line215*/:     end
/*Line216*/:   end
/*Line217*/:
/*Line218*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line219*/:     if (!rst_ni) secret_key <= '0;
/*Line220*/:     else         secret_key <= secret_key_d;
/*Line221*/:   end
/*Line222*/:
/*Line223*/:   for (genvar i = 0; i < 32; i++) begin : gen_key
/*Line224*/:     assign hw2reg.key[31-i].d      = '0;
/*Line225*/:   end
/*Line226*/:
/*Line227*/:   // Retain the previous digest in CSRs until HMAC is actually started with a valid configuration
/*Line228*/:   always_comb begin : assign_digest_reg
/*Line229*/:     // default
/*Line230*/:     // digest SW -> HW
/*Line231*/:     digest_sw     = '0;
/*Line232*/:     digest_sw_we  = '0;
/*Line233*/:     // digest HW -> SW
/*Line234*/:     hw2reg.digest = '0;
/*Line235*/:
/*Line236*/:     for (int i = 0; i < 8; i++) begin
/*Line237*/:       // digest SW -> HW (depends on digest size configured even before starting/enabling)
/*Line238*/:       // capturing the intermediate digests written by SW when restoring context into the SHA-2
/*Line239*/:       // engine before it is started
/*Line240*/:       if (digest_size == SHA2_256) begin
/*Line241*/:         // digest SW -> HW
/*Line242*/:         digest_sw[i][31:0] = conv_endian32(reg2hw.digest[i].q, digest_swap);
/*Line243*/:         digest_sw_we[i]    = reg2hw.digest[i].qe;
/*Line244*/:       end else if ((digest_size == SHA2_384) || (digest_size == SHA2_512)) begin
/*Line245*/:         // digest SW -> HW
/*Line246*/:         digest_sw[i][63:32]    = reg2hw.digest[2*i].qe ?
/*Line247*/:                                  conv_endian32(reg2hw.digest[2*i].q, digest_swap) :
/*Line248*/:                                  digest[i][63:32];
/*Line249*/:         digest_sw[i][31:0]     = reg2hw.digest[2*i+1].qe ?
/*Line250*/:                                  conv_endian32(reg2hw.digest[2*i+1].q, digest_swap) :
/*Line251*/:                                  digest[i][31:0];
/*Line252*/:         digest_sw_we[i]        = reg2hw.digest[2*i].qe | reg2hw.digest[2*i+1].qe;
/*Line253*/:       end
/*Line254*/:
/*Line255*/:       // digest HW -> SW (depends on configuration that has been started)
/*Line256*/:       if (digest_size_started_q == SHA2_256) begin
/*Line257*/:         hw2reg.digest[i].d   = conv_endian32(digest[i][31:0], digest_swap);
/*Line258*/:         // replicate digest[0..7] into digest[8..15]. Digest[8...15] are irrelevant for SHA2_256,
/*Line259*/:         // but this ensures all digest CSRs are wiped out with random value (at wipe_secret)
/*Line260*/:         // across different configurations.
/*Line261*/:         hw2reg.digest[i+8].d = conv_endian32(digest[i][31:0], digest_swap);
/*Line262*/:       end else if ((digest_size_started_q == SHA2_384) || (digest_size_started_q == SHA2_512)) begin
/*Line263*/:         // digest HW -> SW
/*Line264*/:         // digest swap only within each 32-bit word of the 64-bit digest word, not digest swap
/*Line265*/:         // on the entire 64-bit digest word
/*Line266*/:         hw2reg.digest[2*i].d   = conv_endian32(digest[i][63:32], digest_swap);
/*Line267*/:         hw2reg.digest[2*i+1].d = conv_endian32(digest[i][31:0], digest_swap);
/*Line268*/:       end else begin // for SHA2_None
/*Line269*/:         // to ensure secret wiping is always passed to digest CSRs
/*Line270*/:         hw2reg.digest[i].d   = conv_endian32(digest[i][31:0], digest_swap);
/*Line271*/:         hw2reg.digest[i+8].d = conv_endian32(digest[i][31:0], digest_swap);
/*Line272*/:       end
/*Line273*/:     end
/*Line274*/:   end
/*Line275*/:
/*Line276*/:   logic unused_cfg_qe;
/*Line277*/:   assign unused_cfg_qe = ^{cfg_reg.sha_en.qe,      cfg_reg.hmac_en.qe,
/*Line278*/:                            cfg_reg.endian_swap.qe, cfg_reg.digest_swap.qe,
/*Line279*/:                            cfg_reg.key_swap.qe,    cfg_reg.digest_size.qe,
/*Line280*/:                            cfg_reg.key_length.qe };
/*Line281*/:
/*Line282*/:   assign sha_en               = cfg_reg.sha_en.q;
/*Line283*/:   assign hmac_en              = cfg_reg.hmac_en.q;
/*Line284*/:
/*Line285*/:   assign digest_size_supplied = digest_mode_e'(cfg_reg.digest_size.q);
/*Line286*/:   always_comb begin : cast_digest_size
/*Line287*/:     digest_size = SHA2_None;
/*Line288*/:
/*Line289*/:     unique case (digest_size_supplied)
/*Line290*/:       SHA2_256:  digest_size = SHA2_256;
/*Line291*/:       SHA2_384:  digest_size = SHA2_384;
/*Line292*/:       SHA2_512:  digest_size = SHA2_512;
/*Line293*/:       // unsupported digest size values are mapped to SHA2_None
/*Line294*/:       // if HMAC/SHA-2 is triggered to start with this digest size, it is blocked
/*Line295*/:       // and an error is signalled to SW
/*Line296*/:       default:   digest_size = SHA2_None;
/*Line297*/:     endcase
/*Line298*/:   end
/*Line299*/:
/*Line300*/:   // Hold the previous digest size till HMAC is started with the new digest size configured
/*Line301*/:   assign digest_size_started_d = (hash_start_or_continue) ? digest_size : digest_size_started_q;
/*Line302*/:
/*Line303*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line304*/:     if (!rst_ni) digest_size_started_q <= SHA2_None;
/*Line305*/:     else         digest_size_started_q <= digest_size_started_d;
/*Line306*/:   end
/*Line307*/:
/*Line308*/:   assign key_length_supplied  = key_length_e'(cfg_reg.key_length.q);
/*Line309*/:   always_comb begin : cast_key_length
/*Line310*/:     key_length = Key_None;
/*Line311*/:
/*Line312*/:     unique case (key_length_supplied)
/*Line313*/:       Key_128:  key_length = Key_128;
/*Line314*/:       Key_256:  key_length = Key_256;
/*Line315*/:       Key_384:  key_length = Key_384;
/*Line316*/:       Key_512:  key_length = Key_512;
/*Line317*/:       Key_1024: key_length = Key_1024;
/*Line318*/:       // unsupported key length values are mapped to Key_None
/*Line319*/:       // if HMAC (not SHA-2) is triggered to start with this key length, it is blocked
/*Line320*/:       // and an error is signalled to SW
/*Line321*/:       default:  key_length = Key_None;
/*Line322*/:     endcase
/*Line323*/:   end
/*Line324*/:
/*Line325*/:   assign endian_swap = cfg_reg.endian_swap.q;
/*Line326*/:   assign digest_swap = cfg_reg.digest_swap.q;
/*Line327*/:   assign key_swap    = cfg_reg.key_swap.q;
/*Line328*/:
/*Line329*/:   assign hw2reg.cfg.hmac_en.d     = cfg_reg.hmac_en.q;
/*Line330*/:   assign hw2reg.cfg.sha_en.d      = cfg_reg.sha_en.q;
/*Line331*/:   assign hw2reg.cfg.digest_size.d = digest_mode_e'(digest_size);
/*Line332*/:   assign hw2reg.cfg.key_length.d  = key_length_e'(key_length);
/*Line333*/:   assign hw2reg.cfg.endian_swap.d = cfg_reg.endian_swap.q;
/*Line334*/:   assign hw2reg.cfg.digest_swap.d = cfg_reg.digest_swap.q;
/*Line335*/:   assign hw2reg.cfg.key_swap.d    = cfg_reg.key_swap.q;
/*Line336*/:
/*Line337*/:   assign reg_hash_start    = reg2hw.cmd.hash_start.qe & reg2hw.cmd.hash_start.q;
/*Line338*/:   assign reg_hash_stop     = reg2hw.cmd.hash_stop.qe & reg2hw.cmd.hash_stop.q;
/*Line339*/:   assign reg_hash_continue = reg2hw.cmd.hash_continue.qe & reg2hw.cmd.hash_continue.q;
/*Line340*/:   assign reg_hash_process  = reg2hw.cmd.hash_process.qe & reg2hw.cmd.hash_process.q;
/*Line341*/:
/*Line342*/:   // Error code register
/*Line343*/:   assign hw2reg.err_code.de = err_valid;
/*Line344*/:   assign hw2reg.err_code.d  = err_code;
/*Line345*/:
/*Line346*/:   /////////////////////
/*Line347*/:   // Control signals //
/*Line348*/:   /////////////////////
/*Line349*/:   assign hash_start             = reg_hash_start    & sha_en & ~cfg_block & ~invalid_config;
/*Line350*/:   assign hash_continue          = reg_hash_continue & sha_en & ~cfg_block & ~invalid_config;
/*Line351*/:   assign hash_process           = reg_hash_process  & sha_en & cfg_block &  ~invalid_config;
/*Line352*/:   assign hash_start_or_continue = hash_start | hash_continue;
/*Line353*/:
/*Line354*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line355*/:     if (!rst_ni) begin
/*Line356*/:       cfg_block <= '0;
/*Line357*/:     end else if (hash_start_or_continue) begin
/*Line358*/:       cfg_block <= 1'b 1;
/*Line359*/:     end else if (reg_hash_done || reg_hash_stop) begin
/*Line360*/:       cfg_block <= 1'b 0;
/*Line361*/:     end
/*Line362*/:   end
/*Line363*/:   // Hold the configuration during the process
/*Line364*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line365*/:     if (!rst_ni) begin
/*Line366*/:       cfg_reg <= '{
/*Line367*/:         hmac_en: '{
/*Line368*/:           q: 1'b0,
/*Line369*/:           qe: 1'b0
/*Line370*/:         },
/*Line371*/:         sha_en: '{
/*Line372*/:           q: 1'b0,
/*Line373*/:           qe: 1'b0
/*Line374*/:         },
/*Line375*/:         endian_swap: '{
/*Line376*/:           q: HMAC_CFG_ENDIAN_SWAP_RESVAL,
/*Line377*/:           qe: 1'b0
/*Line378*/:         },
/*Line379*/:         digest_swap: '{
/*Line380*/:           q: HMAC_CFG_DIGEST_SWAP_RESVAL,
/*Line381*/:           qe: 1'b0
/*Line382*/:         },
/*Line383*/:         key_swap: '{
/*Line384*/:           q: HMAC_CFG_KEY_SWAP_RESVAL,
/*Line385*/:           qe: 1'b0
/*Line386*/:         },
/*Line387*/:         digest_size: '{
/*Line388*/:           q: HMAC_CFG_DIGEST_SIZE_RESVAL,
/*Line389*/:           qe: 1'b0
/*Line390*/:         },
/*Line391*/:         key_length: '{
/*Line392*/:           q: HMAC_CFG_KEY_LENGTH_RESVAL,
/*Line393*/:           qe: 1'b0
/*Line394*/:         },
/*Line395*/:         default:'0
/*Line396*/:       };
/*Line397*/:     end else if (!cfg_block && reg2hw.cfg.hmac_en.qe) begin
/*Line398*/:       cfg_reg <= reg2hw.cfg ;
/*Line399*/:     end
/*Line400*/:   end
/*Line401*/:
/*Line402*/:   // Open up the MSG_FIFO from the TL-UL port when it is ready
/*Line403*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line404*/:     if (!rst_ni) begin
/*Line405*/:       msg_allowed <= '0;
/*Line406*/:     end else if (hash_start_or_continue) begin
/*Line407*/:       msg_allowed <= 1'b 1;
/*Line408*/:     end else if (packer_flush_done) begin
/*Line409*/:       msg_allowed <= 1'b 0;
/*Line410*/:     end
/*Line411*/:   end
/*Line412*/:
/*Line413*/:   ////////////////
/*Line414*/:   // Interrupts //
/*Line415*/:   ////////////////
/*Line416*/:
/*Line417*/:   // instantiate interrupt hardware primitive
/*Line418*/:   prim_intr_hw #(.Width(1)) intr_hw_hmac_done (
/*Line419*/:     .clk_i,
/*Line420*/:     .rst_ni,
/*Line421*/:     .event_intr_i           (hash_done_event),
/*Line422*/:     .reg2hw_intr_enable_q_i (reg2hw.intr_enable.hmac_done.q),
/*Line423*/:     .reg2hw_intr_test_q_i   (reg2hw.intr_test.hmac_done.q),
/*Line424*/:     .reg2hw_intr_test_qe_i  (reg2hw.intr_test.hmac_done.qe),
/*Line425*/:     .reg2hw_intr_state_q_i  (reg2hw.intr_state.hmac_done.q),
/*Line426*/:     .hw2reg_intr_state_de_o (hw2reg.intr_state.hmac_done.de),
/*Line427*/:     .hw2reg_intr_state_d_o  (hw2reg.intr_state.hmac_done.d),
/*Line428*/:     .intr_o                 (intr_hmac_done_o)
/*Line429*/:   );
/*Line430*/:
/*Line431*/:   // FIFO empty interrupt
/*Line432*/:   //
/*Line433*/:   // The FIFO empty interrupt is **not useful** for software if:
/*Line434*/:   // - The HMAC block is running in HMAC mode and performing the second round of computing the
/*Line435*/:   //   final hash of the outer key as well as the result of the first round using the inner key.
/*Line436*/:   //   The FIFO is then managed entirely by the hardware.
/*Line437*/:   // - The FIFO is currently not writeable by software.
/*Line438*/:   // - Software has already written the Process command. The HMAC block will now empty the
/*Line439*/:   //   FIFO and load its content into the SHA2 core, add the padding and then perfom
/*Line440*/:   //   the final hashing operation. Software cannot append the message further.
/*Line441*/:   // - Software has written the Stop command. The HMAC block will not wait for further input from
/*Line442*/:   //   software after finishing the current block.
/*Line443*/:   //
/*Line444*/:   // The FIFO empty interrupt can be **useful** for software in particular if:
/*Line445*/:   // - The FIFO was completely full previously. However, unless the HMAC block is currently
/*Line446*/:   //   processing a block, it always empties the message FIFO faster than software can fill it up,
/*Line447*/:   //   meaning the message FIFO is empty most of the time. Note, the empty status is signaled only
/*Line448*/:   //   once after the FIFO was completely full. The FIFO needs to be full again for the empty
/*Line449*/:   //   status to be signaled again next time it's empty.
/*Line450*/:   logic status_fifo_empty, fifo_empty_gate;
/*Line451*/:   logic fifo_empty_negedge, fifo_empty_q;
/*Line452*/:   logic fifo_full_posedge, fifo_full_q;
/*Line453*/:   logic fifo_full_seen_d, fifo_full_seen_q;
/*Line454*/:   assign fifo_empty_negedge = fifo_empty_q & ~fifo_empty;
/*Line455*/:   assign fifo_full_posedge  = ~fifo_full_q & fifo_full;
/*Line456*/:
/*Line457*/:   // Track whether the FIFO was full after being empty. We clear the tracking:
/*Line458*/:   // - When receiving the Start, Continue, Process or Stop command. This is to start over for the
/*Line459*/:   //   next message.
/*Line460*/:   // - When seeing a negative edge on the empty signal. This signals that software has reacted to
/*Line461*/:   //   the interrupt and is filling up the FIFO again.
/*Line462*/:   assign fifo_full_seen_d =
/*Line463*/:       reg_hash_start   || reg_hash_continue ||
/*Line464*/:       reg_hash_process || reg_hash_stop     ? 1'b 0 :
/*Line465*/:       fifo_empty_negedge                    ? 1'b 0 :
/*Line466*/:       fifo_full_posedge                     ? 1'b 1 : fifo_full_seen_q;
/*Line467*/:
/*Line468*/:   // The interrupt is gated unless software is actually allowed to write the FIFO and the FIFO was
/*Line469*/:   // full before.
/*Line470*/:   assign fifo_empty_gate = ~msg_allowed || ~fifo_full_seen_q;
/*Line471*/:
/*Line472*/:   assign status_fifo_empty = fifo_empty_gate ? 1'b 0 : fifo_empty;
/*Line473*/:
/*Line474*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line475*/:     if (!rst_ni) begin
/*Line476*/:       fifo_empty_q     <= 1'b 0;
/*Line477*/:       fifo_full_q      <= 1'b 0;
/*Line478*/:       fifo_full_seen_q <= 1'b 0;
/*Line479*/:     end else begin
/*Line480*/:       fifo_empty_q     <= fifo_empty;
/*Line481*/:       fifo_full_q      <= fifo_full;
/*Line482*/:       fifo_full_seen_q <= fifo_full_seen_d;
/*Line483*/:     end
/*Line484*/:   end
/*Line485*/:
/*Line486*/:   prim_intr_hw #(
/*Line487*/:     .Width(1),
/*Line488*/:     .IntrT("Status")
/*Line489*/:   ) intr_hw_fifo_empty (
/*Line490*/:     .clk_i,
/*Line491*/:     .rst_ni,
/*Line492*/:     .event_intr_i           (status_fifo_empty),
/*Line493*/:     .reg2hw_intr_enable_q_i (reg2hw.intr_enable.fifo_empty.q),
/*Line494*/:     .reg2hw_intr_test_q_i   (reg2hw.intr_test.fifo_empty.q),
/*Line495*/:     .reg2hw_intr_test_qe_i  (reg2hw.intr_test.fifo_empty.qe),
/*Line496*/:     .reg2hw_intr_state_q_i  (reg2hw.intr_state.fifo_empty.q),
/*Line497*/:     .hw2reg_intr_state_de_o (hw2reg.intr_state.fifo_empty.de),
/*Line498*/:     .hw2reg_intr_state_d_o  (hw2reg.intr_state.fifo_empty.d),
/*Line499*/:     .intr_o                 (intr_fifo_empty_o)
/*Line500*/:   );
/*Line501*/:   prim_intr_hw #(.Width(1)) intr_hw_hmac_err (
/*Line502*/:     .clk_i,
/*Line503*/:     .rst_ni,
/*Line504*/:     .event_intr_i           (err_valid),
/*Line505*/:     .reg2hw_intr_enable_q_i (reg2hw.intr_enable.hmac_err.q),
/*Line506*/:     .reg2hw_intr_test_q_i   (reg2hw.intr_test.hmac_err.q),
/*Line507*/:     .reg2hw_intr_test_qe_i  (reg2hw.intr_test.hmac_err.qe),
/*Line508*/:     .reg2hw_intr_state_q_i  (reg2hw.intr_state.hmac_err.q),
/*Line509*/:     .hw2reg_intr_state_de_o (hw2reg.intr_state.hmac_err.de),
/*Line510*/:     .hw2reg_intr_state_d_o  (hw2reg.intr_state.hmac_err.d),
/*Line511*/:     .intr_o                 (intr_hmac_err_o)
/*Line512*/:   );
/*Line513*/:
/*Line514*/:   ///////////////
/*Line515*/:   // Instances //
/*Line516*/:   ///////////////
/*Line517*/:
/*Line518*/:   assign msg_fifo_rvalid = msg_fifo_req & ~msg_fifo_we;
/*Line519*/:   assign msg_fifo_rdata  = '1;  // Return all F
/*Line520*/:   assign msg_fifo_rerror = '1;  // Return error for read access
/*Line521*/:   assign msg_fifo_gnt    = msg_fifo_req & ~hmac_fifo_wsel & packer_ready;
/*Line522*/:
/*Line523*/:   /////////////////////
/*Line524*/:   // Unused Signals //
/*Line525*/:   /////////////////////
/*Line526*/:   logic unused_signals;
/*Line527*/:   assign unused_signals = ^{reg_fifo_wmask[7:1],   reg_fifo_wmask[15:9],
/*Line528*/:                             reg_fifo_wmask[23:17], reg_fifo_wmask[31:25]};
/*Line529*/:
/*Line530*/:   // FIFO control: from packer into message FIFO
/*Line531*/:   sha_fifo32_t reg_fifo_wentry;
/*Line532*/:   assign reg_fifo_wentry.data = conv_endian32(reg_fifo_wdata, 1'b1); // always convert
/*Line533*/:   assign reg_fifo_wentry.mask = {reg_fifo_wmask[0],  reg_fifo_wmask[8],
/*Line534*/:                                  reg_fifo_wmask[16], reg_fifo_wmask[24]};
/*Line535*/:   assign fifo_full   = ~fifo_wready;
/*Line536*/:   assign fifo_empty  = ~fifo_rvalid;
/*Line537*/:   assign fifo_wvalid = (hmac_fifo_wsel && fifo_wready) ? hmac_fifo_wvalid : reg_fifo_wvalid;
/*Line538*/:
/*Line539*/:   logic index;
/*Line540*/:   always_comb begin : select_fifo_wdata
/*Line541*/:     // default when !hmac_fifo_wsel
/*Line542*/:     index      = 1'b0;
/*Line543*/:     fifo_wdata = reg_fifo_wentry;
/*Line544*/:
/*Line545*/:     if (hmac_fifo_wsel) begin
/*Line546*/:       fifo_wdata = '0;
/*Line547*/:       if (digest_size == SHA2_256) begin
/*Line548*/:         // only reads out lower 32 bits of each digest word and discards upper 32-bit zero padding
/*Line549*/:         fifo_wdata = '{data: digest[hmac_fifo_wdata_sel[2:0]][31:0], mask: '1};
/*Line550*/:       end else if ((digest_size == SHA2_384) || (digest_size == SHA2_512)) begin
/*Line551*/:         // reads out first upper 32 bits then lower 32 bits of each digest word
/*Line552*/:         index = !hmac_fifo_wdata_sel[0];
/*Line553*/:         fifo_wdata = '{data: digest[hmac_fifo_wdata_sel >> 1][32*index+:32], mask: '1};
/*Line554*/:       end
/*Line555*/:     end
/*Line556*/:   end
/*Line557*/:
/*Line558*/:   // Extended for 1024-bit block
/*Line559*/:   localparam int MsgFifoDepth = 32;
/*Line560*/:   prim_fifo_sync #(
/*Line561*/:     .Width   ($bits(sha_fifo32_t)),
/*Line562*/:     .Pass    (1'b1),
/*Line563*/:     .Depth   (MsgFifoDepth)
/*Line564*/:   ) u_msg_fifo (
/*Line565*/:     .clk_i,
/*Line566*/:     .rst_ni,
/*Line567*/:     .clr_i   (1'b0),
/*Line568*/:
/*Line569*/:     .wvalid_i(fifo_wvalid & sha_en),
/*Line570*/:     .wready_o(fifo_wready),
/*Line571*/:     .wdata_i (fifo_wdata),
/*Line572*/:
/*Line573*/:     .depth_o (fifo_depth),
/*Line574*/:     .full_o  (),
/*Line575*/:
/*Line576*/:     .rvalid_o(fifo_rvalid),
/*Line577*/:     .rready_i(fifo_rready),
/*Line578*/:     .rdata_o (fifo_rdata),
/*Line579*/:     .err_o   ()
/*Line580*/:   );
/*Line581*/:
/*Line582*/:   // TL ADAPTER SRAM
/*Line583*/:   tlul_adapter_sram #(
/*Line584*/:     .SramAw (9),
/*Line585*/:     .SramDw (32),
/*Line586*/:     .Outstanding (1),
/*Line587*/:     .ByteAccess  (1),
/*Line588*/:     .ErrOnRead   (1)
/*Line589*/:   ) u_tlul_adapter (
/*Line590*/:     .clk_i,
/*Line591*/:     .rst_ni,
/*Line592*/:     .tl_i                       (tl_win_h2d),
/*Line593*/:     .tl_o                       (tl_win_d2h),
/*Line594*/:     .en_ifetch_i                (prim_mubi_pkg::MuBi4False),
/*Line595*/:     .req_o                      (msg_fifo_req   ),
/*Line596*/:     .req_type_o                 (               ),
/*Line597*/:     .gnt_i                      (msg_fifo_gnt   ),
/*Line598*/:     .we_o                       (msg_fifo_we    ),
/*Line599*/:     .addr_o                     (               ), // Doesn't care the address
/*Line600*/:                                                    // other than sub-word
/*Line601*/:     .wdata_o                    (msg_fifo_wdata ),
/*Line602*/:     .wmask_o                    (msg_fifo_wmask ),
/*Line603*/:     .intg_error_o               (               ),
/*Line604*/:     .rdata_i                    (msg_fifo_rdata ),
/*Line605*/:     .rvalid_i                   (msg_fifo_rvalid),
/*Line606*/:     .rerror_i                   (msg_fifo_rerror),
/*Line607*/:     .compound_txn_in_progress_o (),
/*Line608*/:     .readback_en_i              (prim_mubi_pkg::MuBi4False),
/*Line609*/:     .readback_error_o           (),
/*Line610*/:     .wr_collision_i             (1'b0),
/*Line611*/:     .write_pending_i            (1'b0)
/*Line612*/:   );
/*Line613*/:
/*Line614*/:   // TL-UL to MSG_FIFO byte write handling
/*Line615*/:   logic msg_write;
/*Line616*/:
/*Line617*/:   assign msg_write = msg_fifo_req & msg_fifo_we & ~hmac_fifo_wsel & msg_allowed;
/*Line618*/:
/*Line619*/:   logic [$clog2(32+1)-1:0] wmask_ones;
/*Line620*/:
/*Line621*/:   always_comb begin
/*Line622*/:     wmask_ones = '0;
/*Line623*/:     for (int i = 0 ; i < 32 ; i++) begin
/*Line624*/:       wmask_ones = wmask_ones + msg_fifo_wmask[i];
/*Line625*/:     end
/*Line626*/:   end
/*Line627*/:
/*Line628*/:   // Calculate written message
/*Line629*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line630*/:     if (!rst_ni) message_length <= '0;
/*Line631*/:     else         message_length <= message_length_d;
/*Line632*/:   end
/*Line633*/:
/*Line634*/:   always_comb begin
/*Line635*/:     message_length_d = message_length;
/*Line636*/:     if (!cfg_block) begin
/*Line637*/:       if (reg2hw.msg_length_lower.qe) begin
/*Line638*/:         message_length_d[31:0]  = reg2hw.msg_length_lower.q;
/*Line639*/:       end
/*Line640*/:       if (reg2hw.msg_length_upper.qe) begin
/*Line641*/:         message_length_d[63:32] = reg2hw.msg_length_upper.q;
/*Line642*/:       end
/*Line643*/:     end
/*Line644*/:
/*Line645*/:     if (hash_start) begin
/*Line646*/:       message_length_d = '0;
/*Line647*/:     end else if (msg_write && sha_en && packer_ready) begin
/*Line648*/:       message_length_d = message_length + 64'(wmask_ones);
/*Line649*/:     end
/*Line650*/:   end
/*Line651*/:
/*Line652*/:   assign hw2reg.msg_length_upper.d = message_length[63:32];
/*Line653*/:   assign hw2reg.msg_length_lower.d = message_length[31:0];
/*Line654*/:
/*Line655*/:   // Convert endian here
/*Line656*/:   //    prim_packer always packs to the right, but SHA engine assumes incoming
/*Line657*/:   //    to be big-endian, [31:24] comes first. So, the data is reverted after
/*Line658*/:   //    prim_packer before the message fifo. here to reverse if not big-endian
/*Line659*/:   //    before pushing to the packer.
/*Line660*/:   assign msg_fifo_wdata_endian = conv_endian32(msg_fifo_wdata, endian_swap);
/*Line661*/:   assign msg_fifo_wmask_endian = conv_endian32(msg_fifo_wmask, endian_swap);
/*Line662*/:
/*Line663*/:   prim_packer #(
/*Line664*/:     .InW          (32),
/*Line665*/:     .OutW         (32),
/*Line666*/:     .EnProtection (1'b 0)
/*Line667*/:   ) u_packer (
/*Line668*/:     .clk_i,
/*Line669*/:     .rst_ni,
/*Line670*/:
/*Line671*/:     .valid_i      (msg_write & sha_en),
/*Line672*/:     .data_i       (msg_fifo_wdata_endian),
/*Line673*/:     .mask_i       (msg_fifo_wmask_endian),
/*Line674*/:     .ready_o      (packer_ready),
/*Line675*/:
/*Line676*/:     .valid_o      (reg_fifo_wvalid),
/*Line677*/:     .data_o       (reg_fifo_wdata),
/*Line678*/:     .mask_o       (reg_fifo_wmask),
/*Line679*/:     .ready_i      (fifo_wready & ~hmac_fifo_wsel),
/*Line680*/:
/*Line681*/:     .flush_i      (hash_process),
/*Line682*/:     .flush_done_o (packer_flush_done), // ignore at this moment
/*Line683*/:
/*Line684*/:     .err_o  () // Not used
/*Line685*/:   );
/*Line686*/:
/*Line687*/:   hmac_core u_hmac (
/*Line688*/:     .clk_i,
/*Line689*/:     .rst_ni,
/*Line690*/:     .secret_key_i  (secret_key),
/*Line691*/:     .hmac_en_i     (hmac_en),
/*Line692*/:     .digest_size_i (digest_size),
/*Line693*/:     .key_length_i  (key_length),
/*Line694*/:
/*Line695*/:     .reg_hash_start_i    (hash_start),
/*Line696*/:     .reg_hash_stop_i     (reg_hash_stop),
/*Line697*/:     .reg_hash_continue_i (hash_continue),
/*Line698*/:     .reg_hash_process_i  (packer_flush_done), // Trigger after all msg written
/*Line699*/:     .hash_done_o         (reg_hash_done),
/*Line700*/:     .sha_hash_start_o    (sha_hash_start),
/*Line701*/:     .sha_hash_continue_o (sha_hash_continue),
/*Line702*/:     .sha_hash_process_o  (sha_hash_process),
/*Line703*/:     .sha_hash_done_i     (sha_hash_done),
/*Line704*/:
/*Line705*/:     .sha_rvalid_o     (shaf_rvalid),
/*Line706*/:     .sha_rdata_o      (shaf_rdata),
/*Line707*/:     .sha_rready_i     (shaf_rready),
/*Line708*/:
/*Line709*/:     .fifo_rvalid_i (fifo_rvalid),
/*Line710*/:     .fifo_rdata_i  (fifo_rdata),
/*Line711*/:     .fifo_rready_o (fifo_rready),
/*Line712*/:
/*Line713*/:     .fifo_wsel_o      (hmac_fifo_wsel),
/*Line714*/:     .fifo_wvalid_o    (hmac_fifo_wvalid),
/*Line715*/:     .fifo_wdata_sel_o (hmac_fifo_wdata_sel),
/*Line716*/:     .fifo_wready_i    (fifo_wready),
/*Line717*/:
/*Line718*/:     .message_length_i     (message_length),
/*Line719*/:     .sha_message_length_o (sha_message_length),
/*Line720*/:
/*Line721*/:     .idle_o           (hmac_core_idle)
/*Line722*/:   );
/*Line723*/:
/*Line724*/:   // Instantiate SHA-2 256/384/512 engine
/*Line725*/:   prim_sha2_32 #(
/*Line726*/:       .MultimodeEn(1)
/*Line727*/:   ) u_prim_sha2_512 (
/*Line728*/:     .clk_i,
/*Line729*/:     .rst_ni,
/*Line730*/:     .wipe_secret_i        (wipe_secret),
/*Line731*/:     .wipe_v_i             (wipe_v),
/*Line732*/:     .fifo_rvalid_i        (shaf_rvalid),
/*Line733*/:     .fifo_rdata_i         (shaf_rdata),
/*Line734*/:     .fifo_rready_o        (shaf_rready),
/*Line735*/:     .sha_en_i             (sha_en),
/*Line736*/:     .hash_start_i         (sha_hash_start),
/*Line737*/:     .hash_stop_i          (reg_hash_stop),
/*Line738*/:     .hash_continue_i      (sha_hash_continue),
/*Line739*/:     .digest_mode_i        (digest_size),
/*Line740*/:     .hash_process_i       (sha_hash_process),
/*Line741*/:     .message_length_i     (sha_message_length),
/*Line742*/:     .digest_i             (digest_sw),
/*Line743*/:     .digest_we_i          (digest_sw_we),
/*Line744*/:     .digest_o             (digest),
/*Line745*/:     .hash_running_o       (hash_running),
/*Line746*/:     .digest_on_blk_o      (digest_on_blk),
/*Line747*/:     .hash_done_o          (sha_hash_done),
/*Line748*/:     .idle_o               (sha_core_idle)
/*Line749*/:   );
/*Line750*/:
/*Line751*/:   // Register top
/*Line752*/:   logic [NumAlerts-1:0] alert_test, alerts;
/*Line753*/:   hmac_reg_top u_reg (
/*Line754*/:     .clk_i,
/*Line755*/:     .rst_ni,
/*Line756*/:
/*Line757*/:     .tl_i,
/*Line758*/:     .tl_o,
/*Line759*/:
/*Line760*/:     .tl_win_o   (tl_win_h2d),
/*Line761*/:     .tl_win_i   (tl_win_d2h),
/*Line762*/:
/*Line763*/:     .reg2hw,
/*Line764*/:     .hw2reg,
/*Line765*/:
/*Line766*/:     // SEC_CM: BUS.INTEGRITY
/*Line767*/:     .intg_err_o (alerts[0])
/*Line768*/:   );
/*Line769*/:
/*Line770*/:   // Alerts
/*Line771*/:   assign alert_test = {
/*Line772*/:     reg2hw.alert_test.q &
/*Line773*/:     reg2hw.alert_test.qe
/*Line774*/:   };
/*Line775*/:
/*Line776*/:   localparam logic [NumAlerts-1:0] AlertIsFatal = {1'b1};
/*Line777*/:   for (genvar i = 0; i < NumAlerts; i++) begin : gen_alert_tx
/*Line778*/:     prim_alert_sender #(
/*Line779*/:       .AsyncOn(AlertAsyncOn[i]),
/*Line780*/:       .IsFatal(AlertIsFatal[i])
/*Line781*/:     ) u_prim_alert_sender (
/*Line782*/:       .clk_i,
/*Line783*/:       .rst_ni,
/*Line784*/:       .alert_test_i  ( alert_test[i] ),
/*Line785*/:       .alert_req_i   ( alerts[0]     ),
/*Line786*/:       .alert_ack_o   (               ),
/*Line787*/:       .alert_state_o (               ),
/*Line788*/:       .alert_rx_i    ( alert_rx_i[i] ),
/*Line789*/:       .alert_tx_o    ( alert_tx_o[i] )
/*Line790*/:     );
/*Line791*/:   end
/*Line792*/:
/*Line793*/:   /////////////////////////
/*Line794*/:   // HMAC Error Handling //
/*Line795*/:   /////////////////////////
/*Line796*/:   logic hash_start_sha_disabled, update_seckey_inprocess;
/*Line797*/:   logic hash_start_active;  // `reg_hash_start` or `reg_hash_continue` set when hash already active
/*Line798*/:   logic msg_push_not_allowed; // Message is received when `hash_start_or_continue` isn't set
/*Line799*/:
/*Line800*/:   assign hash_start_sha_disabled = (reg_hash_start | reg_hash_continue) & ~sha_en;
/*Line801*/:   assign hash_start_active = (reg_hash_start | reg_hash_continue) & cfg_block;
/*Line802*/:   assign msg_push_not_allowed = msg_fifo_req & ~msg_allowed;
/*Line803*/:
/*Line804*/:   // Invalid/unconfigured HMAC/SHA-2: not configured/invalid digest size or
/*Line805*/:   // not configured/invalid key length for HMAC mode or
/*Line806*/:   // key_length = 1024-bit for digest_size = SHA2_256 (max 512-bit is supported for SHA-2 256)
/*Line807*/:   assign invalid_config = ((digest_size == SHA2_None)            |
/*Line808*/:                            ((key_length == Key_None) && hmac_en) |
/*Line809*/:                            ((key_length == Key_1024) && (digest_size == SHA2_256) && hmac_en));
/*Line810*/:
/*Line811*/:   // invalid_config at reg_hash_start or reg_hash_continue will signal an error to the SW
/*Line812*/:   assign invalid_config_atstart = (reg_hash_start || reg_hash_continue) & invalid_config;
/*Line813*/:
/*Line814*/:   always_comb begin
/*Line815*/:     update_seckey_inprocess = 1'b0;
/*Line816*/:     if (cfg_block) begin
/*Line817*/:       for (int i = 0 ; i < 32 ; i++) begin
/*Line818*/:         if (reg2hw.key[i].qe) begin
/*Line819*/:           update_seckey_inprocess = update_seckey_inprocess | 1'b1;
/*Line820*/:         end
/*Line821*/:       end
/*Line822*/:     end else begin
/*Line823*/:       update_seckey_inprocess = 1'b0;
/*Line824*/:     end
/*Line825*/:   end
/*Line826*/:
/*Line827*/:   // Update ERR_CODE register and interrupt only when no pending interrupt.
/*Line828*/:   // This ensures only the first event of the series of events can be seen to sw.
/*Line829*/:   // It is recommended that the software reads ERR_CODE register when interrupt
/*Line830*/:   // is pending to avoid any race conditions.
/*Line831*/:   assign err_valid = ~reg2hw.intr_state.hmac_err.q &
/*Line832*/:                    ( hash_start_sha_disabled | update_seckey_inprocess
/*Line833*/:                    | hash_start_active | msg_push_not_allowed | invalid_config_atstart);
/*Line834*/:
/*Line835*/:   always_comb begin
/*Line836*/:     // default
/*Line837*/:     err_code = NoError;
/*Line838*/:
/*Line839*/:     priority case (1'b1)
/*Line840*/:
/*Line841*/:       hash_start_sha_disabled: begin
/*Line842*/:         err_code = SwHashStartWhenShaDisabled;
/*Line843*/:       end
/*Line844*/:
/*Line845*/:       hash_start_active: begin
/*Line846*/:         err_code = SwHashStartWhenActive;
/*Line847*/:       end
/*Line848*/:
/*Line849*/:       msg_push_not_allowed: begin
/*Line850*/:         err_code = SwPushMsgWhenDisallowed;
/*Line851*/:       end
/*Line852*/:
/*Line853*/:       update_seckey_inprocess: begin
/*Line854*/:         err_code = SwUpdateSecretKeyInProcess;
/*Line855*/:       end
/*Line856*/:
/*Line857*/:       invalid_config_atstart: begin
/*Line858*/:         err_code = SwInvalidConfig;
/*Line859*/:       end
/*Line860*/:
/*Line861*/:
/*Line862*/:       default: begin
/*Line863*/:         err_code = NoError;
/*Line864*/:       end
/*Line865*/:     endcase
/*Line866*/:   end
/*Line867*/:
/*Line868*/:   /////////////////////
/*Line869*/:   // Idle output     //
/*Line870*/:   /////////////////////
/*Line871*/:   // TBD this should be connected later
/*Line872*/:   // Idle: AND condition of:
/*Line873*/:   //  - packer empty: Currently no way to guarantee the packer is empty.
/*Line874*/:   //    temporary, the logic uses packer output (reg_fifo_wvalid)
/*Line875*/:   //  - MSG_FIFO  --> fifo_rvalid
/*Line876*/:   //  - HMAC_CORE --> hmac_core_idle
/*Line877*/:   //  - SHA2_CORE --> sha_core_idle
/*Line878*/:   //  - Clean interrupt status
/*Line879*/:   // ICEBOX(#12958): Revise prim_packer and replace `reg_fifo_wvalid` to the
/*Line880*/:   // empty status.
/*Line881*/:   assign idle = !reg_fifo_wvalid && !fifo_rvalid
/*Line882*/:               && hmac_core_idle && sha_core_idle;
/*Line883*/:
/*Line884*/:   prim_mubi_pkg::mubi4_t idle_q, idle_d;
/*Line885*/:   assign idle_d = prim_mubi_pkg::mubi4_bool_to_mubi(idle);
/*Line886*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line887*/:     if (!rst_ni) begin
/*Line888*/:       idle_q <= prim_mubi_pkg::MuBi4False;
/*Line889*/:     end else begin
/*Line890*/:       idle_q <= idle_d;
/*Line891*/:     end
/*Line892*/:   end
/*Line893*/:   assign idle_o = idle_q;
/*Line894*/:
/*Line895*/:   //////////////////////////////////////////////
/*Line896*/:   // Assertions, Assumptions, and Coverpoints //
/*Line897*/:   //////////////////////////////////////////////
/*Line898*/:
/*Line899*/: `ifndef VERILATOR
/*Line900*/: `ifndef SYNTHESIS
/*Line901*/:   // HMAC assumes TL-UL mask is byte-aligned.
/*Line902*/:   property wmask_bytealign_p(wmask_byte, clk, rst_n);
/*Line903*/:     @(posedge clk) disable iff (rst_n == 0)
/*Line904*/:       msg_fifo_req & msg_fifo_we |-> wmask_byte inside {'0, '1};
/*Line905*/:   endproperty
/*Line906*/:
/*Line907*/:   for (genvar i = 0 ; i < 4; i++) begin: gen_assert_wmask_bytealign
/*Line908*/:     assert property (wmask_bytealign_p(msg_fifo_wmask[8*i+:8], clk_i, rst_ni));
/*Line909*/:   end
/*Line910*/:
/*Line911*/:   // To pass FPV, this shouldn't add pragma translate_off even these two signals
/*Line912*/:   // are used in Assertion only
/*Line913*/:   logic in_process;
/*Line914*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line915*/:     if (!rst_ni)                              in_process <= 1'b0;
/*Line916*/:     else if (hash_process || reg_hash_stop)   in_process <= 1'b1;
/*Line917*/:     else if (reg_hash_done)                   in_process <= 1'b0;
/*Line918*/:   end
/*Line919*/:
/*Line920*/:   logic initiated;
/*Line921*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line922*/:     if (!rst_ni)                              initiated <= 1'b0;
/*Line923*/:     else if (hash_start_or_continue)          initiated <= 1'b1;
/*Line924*/:     else if (hash_process || reg_hash_stop)   initiated <= 1'b0;
/*Line925*/:   end
/*Line926*/:
/*Line927*/:   // the host doesn't write data after hash_process until hash_start_or_continue.
/*Line928*/:   `ASSERT(ValidWriteAssert, msg_fifo_req |-> !in_process)
/*Line929*/:
/*Line930*/:   // Below condition is covered by the design (2020-02-19)
/*Line931*/:   //`ASSERT(ValidHashStartAssert, hash_start_or_continue |-> !initiated)
/*Line932*/:   // `hash_process` or `reg_hash_stop` should be toggled and paired with `hash_start_or_continue`
/*Line933*/:   `ASSERT(ValidHashProcessAssert, (hash_process || reg_hash_stop) |-> initiated)
/*Line934*/:
/*Line935*/:   // hmac_en should be modified only when the logic is Idle
/*Line936*/:   `ASSERT(ValidHmacEnConditionAssert,
/*Line937*/:           hmac_en != $past(hmac_en) |-> !in_process && !initiated)
/*Line938*/:
/*Line939*/:   // All outputs should be known value after reset
/*Line940*/:   `ASSERT_KNOWN(IntrHmacDoneOKnown, intr_hmac_done_o)
/*Line941*/:   `ASSERT_KNOWN(IntrFifoEmptyOKnown, intr_fifo_empty_o)
/*Line942*/:   `ASSERT_KNOWN(TlODValidKnown, tl_o.d_valid)
/*Line943*/:   `ASSERT_KNOWN(TlOAReadyKnown, tl_o.a_ready)
/*Line944*/:   `ASSERT_KNOWN(AlertKnownO_A, alert_tx_o)
/*Line945*/:
/*Line946*/: `endif // SYNTHESIS
/*Line947*/: `endif // VERILATOR
/*Line948*/:
/*Line949*/:   // Alert assertions for reg_we onehot check
/*Line950*/:   `ASSERT_PRIM_REG_WE_ONEHOT_ERROR_TRIGGER_ALERT(RegWeOnehotCheck_A, u_reg, alert_tx_o[0])
/*Line951*/: endmodule
/*Line952*/:[0mError in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_start callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
[32;1m[1;3m
Invoking: `read_sv_file` with `{'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_reg_top.sv'}`
responded: I have read the source code for `hmac_core.sv` and `hmac.sv`. Now, to get a complete understanding of the design, I will read the source code for `hmac_reg_top.sv` and `hmac_reg_pkg.sv`. This will allow me to analyze the register interface and the overall design for potential security vulnerabilities.

First, I will read `hmac_reg_top.sv`.

[0m[33;1m[1;3m/*Line1*/: // Copyright lowRISC contributors (OpenTitan project).
/*Line2*/: // Licensed under the Apache License, Version 2.0, see LICENSE for details.
/*Line3*/: // SPDX-License-Identifier: Apache-2.0
/*Line4*/: //
/*Line5*/: // Register Top module auto-generated by `reggen`
/*Line6*/:
/*Line7*/: `include "prim_assert.sv"
/*Line8*/:
/*Line9*/: module hmac_reg_top (
/*Line10*/:   input clk_i,
/*Line11*/:   input rst_ni,
/*Line12*/:   input  tlul_pkg::tl_h2d_t tl_i,
/*Line13*/:   output tlul_pkg::tl_d2h_t tl_o,
/*Line14*/:
/*Line15*/:   // Output port for window
/*Line16*/:   output tlul_pkg::tl_h2d_t tl_win_o,
/*Line17*/:   input  tlul_pkg::tl_d2h_t tl_win_i,
/*Line18*/:
/*Line19*/:   // To HW
/*Line20*/:   output hmac_reg_pkg::hmac_reg2hw_t reg2hw, // Write
/*Line21*/:   input  hmac_reg_pkg::hmac_hw2reg_t hw2reg, // Read
/*Line22*/:
/*Line23*/:   // Integrity check errors
/*Line24*/:   output logic intg_err_o
/*Line25*/: );
/*Line26*/:
/*Line27*/:   import hmac_reg_pkg::* ;
/*Line28*/:
/*Line29*/:   localparam int AW = 13;
/*Line30*/:   localparam int DW = 32;
/*Line31*/:   localparam int DBW = DW/8;                    // Byte Width
/*Line32*/:
/*Line33*/:   // register signals
/*Line34*/:   logic           reg_we;
/*Line35*/:   logic           reg_re;
/*Line36*/:   logic [AW-1:0]  reg_addr;
/*Line37*/:   logic [DW-1:0]  reg_wdata;
/*Line38*/:   logic [DBW-1:0] reg_be;
/*Line39*/:   logic [DW-1:0]  reg_rdata;
/*Line40*/:   logic           reg_error;
/*Line41*/:
/*Line42*/:   logic          addrmiss, wr_err;
/*Line43*/:
/*Line44*/:   logic [DW-1:0] reg_rdata_next;
/*Line45*/:   logic reg_busy;
/*Line46*/:
/*Line47*/:   tlul_pkg::tl_h2d_t tl_reg_h2d;
/*Line48*/:   tlul_pkg::tl_d2h_t tl_reg_d2h;
/*Line49*/:
/*Line50*/:
/*Line51*/:   // incoming payload check
/*Line52*/:   logic intg_err;
/*Line53*/:   tlul_cmd_intg_chk u_chk (
/*Line54*/:     .tl_i(tl_i),
/*Line55*/:     .err_o(intg_err)
/*Line56*/:   );
/*Line57*/:
/*Line58*/:   // also check for spurious write enables
/*Line59*/:   logic reg_we_err;
/*Line60*/:   logic [58:0] reg_we_check;
/*Line61*/:   prim_reg_we_check #(
/*Line62*/:     .OneHotWidth(59)
/*Line63*/:   ) u_prim_reg_we_check (
/*Line64*/:     .clk_i(clk_i),
/*Line65*/:     .rst_ni(rst_ni),
/*Line66*/:     .oh_i  (reg_we_check),
/*Line67*/:     .en_i  (reg_we && !addrmiss),
/*Line68*/:     .err_o (reg_we_err)
/*Line69*/:   );
/*Line70*/:
/*Line71*/:   logic err_q;
/*Line72*/:   always_ff @(posedge clk_i or negedge rst_ni) begin
/*Line73*/:     if (!rst_ni) begin
/*Line74*/:       err_q <= '0;
/*Line75*/:     end else if (intg_err || reg_we_err) begin
/*Line76*/:       err_q <= 1'b1;
/*Line77*/:     end
/*Line78*/:   end
/*Line79*/:
/*Line80*/:   // integrity error output is permanent and should be used for alert generation
/*Line81*/:   // register errors are transactional
/*Line82*/:   assign intg_err_o = err_q | intg_err | reg_we_err;
/*Line83*/:
/*Line84*/:   // outgoing integrity generation
/*Line85*/:   tlul_pkg::tl_d2h_t tl_o_pre;
/*Line86*/:   tlul_rsp_intg_gen #(
/*Line87*/:     .EnableRspIntgGen(1),
/*Line88*/:     .EnableDataIntgGen(1)
/*Line89*/:   ) u_rsp_intg_gen (
/*Line90*/:     .tl_i(tl_o_pre),
/*Line91*/:     .tl_o(tl_o)
/*Line92*/:   );
/*Line93*/:
/*Line94*/:   tlul_pkg::tl_h2d_t tl_socket_h2d [2];
/*Line95*/:   tlul_pkg::tl_d2h_t tl_socket_d2h [2];
/*Line96*/:
/*Line97*/:   logic [0:0] reg_steer;
/*Line98*/:
/*Line99*/:   // socket_1n connection
/*Line100*/:   assign tl_reg_h2d = tl_socket_h2d[1];
/*Line101*/:   assign tl_socket_d2h[1] = tl_reg_d2h;
/*Line102*/:
/*Line103*/:   assign tl_win_o = tl_socket_h2d[0];
/*Line104*/:   assign tl_socket_d2h[0] = tl_win_i;
/*Line105*/:
/*Line106*/:   // Create Socket_1n
/*Line107*/:   tlul_socket_1n #(
/*Line108*/:     .N            (2),
/*Line109*/:     .HReqPass     (1'b1),
/*Line110*/:     .HRspPass     (1'b1),
/*Line111*/:     .DReqPass     ({2{1'b1}}),
/*Line112*/:     .DRspPass     ({2{1'b1}}),
/*Line113*/:     .HReqDepth    (4'h0),
/*Line114*/:     .HRspDepth    (4'h0),
/*Line115*/:     .DReqDepth    ({2{4'h0}}),
/*Line116*/:     .DRspDepth    ({2{4'h0}}),
/*Line117*/:     .ExplicitErrs (1'b0)
/*Line118*/:   ) u_socket (
/*Line119*/:     .clk_i  (clk_i),
/*Line120*/:     .rst_ni (rst_ni),
/*Line121*/:     .tl_h_i (tl_i),
/*Line122*/:     .tl_h_o (tl_o_pre),
/*Line123*/:     .tl_d_o (tl_socket_h2d),
/*Line124*/:     .tl_d_i (tl_socket_d2h),
/*Line125*/:     .dev_select_i (reg_steer)
/*Line126*/:   );
/*Line127*/:
/*Line128*/:   // Create steering logic
/*Line129*/:   always_comb begin
/*Line130*/:     reg_steer =
/*Line131*/:         tl_i.a_address[AW-1:0] inside {[4096:8191]} ? 1'd0 :
/*Line132*/:         // Default set to register
/*Line133*/:         1'd1;
/*Line134*/:
/*Line135*/:     // Override this in case of an integrity error
/*Line136*/:     if (intg_err) begin
/*Line137*/:       reg_steer = 1'd1;
/*Line138*/:     end
/*Line139*/:   end
/*Line140*/:
/*Line141*/:   tlul_adapter_reg #(
/*Line142*/:     .RegAw(AW),
/*Line143*/:     .RegDw(DW),
/*Line144*/:     .EnableDataIntgGen(0)
/*Line145*/:   ) u_reg_if (
/*Line146*/:     .clk_i  (clk_i),
/*Line147*/:     .rst_ni (rst_ni),
/*Line148*/:
/*Line149*/:     .tl_i (tl_reg_h2d),
/*Line150*/:     .tl_o (tl_reg_d2h),
/*Line151*/:
/*Line152*/:     .en_ifetch_i(prim_mubi_pkg::MuBi4False),
/*Line153*/:     .intg_error_o(),
/*Line154*/:
/*Line155*/:     .we_o    (reg_we),
/*Line156*/:     .re_o    (reg_re),
/*Line157*/:     .addr_o  (reg_addr),
/*Line158*/:     .wdata_o (reg_wdata),
/*Line159*/:     .be_o    (reg_be),
/*Line160*/:     .busy_i  (reg_busy),
/*Line161*/:     .rdata_i (reg_rdata),
/*Line162*/:     .error_i (reg_error)
/*Line163*/:   );
/*Line164*/:
/*Line165*/:   // cdc oversampling signals
/*Line166*/:
/*Line167*/:   assign reg_rdata = reg_rdata_next ;
/*Line168*/:   assign reg_error = addrmiss | wr_err | intg_err;
/*Line169*/:
/*Line170*/:   // Define SW related signals
/*Line171*/:   // Format: <reg>_<field>_{wd|we|qs}
/*Line172*/:   //        or <reg>_{wd|we|qs} if field == 1 or 0
/*Line173*/:   logic intr_state_we;
/*Line174*/:   logic intr_state_hmac_done_qs;
/*Line175*/:   logic intr_state_hmac_done_wd;
/*Line176*/:   logic intr_state_fifo_empty_qs;
/*Line177*/:   logic intr_state_hmac_err_qs;
/*Line178*/:   logic intr_state_hmac_err_wd;
/*Line179*/:   logic intr_enable_we;
/*Line180*/:   logic intr_enable_hmac_done_qs;
/*Line181*/:   logic intr_enable_hmac_done_wd;
/*Line182*/:   logic intr_enable_fifo_empty_qs;
/*Line183*/:   logic intr_enable_fifo_empty_wd;
/*Line184*/:   logic intr_enable_hmac_err_qs;
/*Line185*/:   logic intr_enable_hmac_err_wd;
/*Line186*/:   logic intr_test_we;
/*Line187*/:   logic intr_test_hmac_done_wd;
/*Line188*/:   logic intr_test_fifo_empty_wd;
/*Line189*/:   logic intr_test_hmac_err_wd;
/*Line190*/:   logic alert_test_we;
/*Line191*/:   logic alert_test_wd;
/*Line192*/:   logic cfg_re;
/*Line193*/:   logic cfg_we;
/*Line194*/:   logic cfg_hmac_en_qs;
/*Line195*/:   logic cfg_hmac_en_wd;
/*Line196*/:   logic cfg_sha_en_qs;
/*Line197*/:   logic cfg_sha_en_wd;
/*Line198*/:   logic cfg_endian_swap_qs;
/*Line199*/:   logic cfg_endian_swap_wd;
/*Line200*/:   logic cfg_digest_swap_qs;
/*Line201*/:   logic cfg_digest_swap_wd;
/*Line202*/:   logic cfg_key_swap_qs;
/*Line203*/:   logic cfg_key_swap_wd;
/*Line204*/:   logic [3:0] cfg_digest_size_qs;
/*Line205*/:   logic [3:0] cfg_digest_size_wd;
/*Line206*/:   logic [5:0] cfg_key_length_qs;
/*Line207*/:   logic [5:0] cfg_key_length_wd;
/*Line208*/:   logic cmd_we;
/*Line209*/:   logic cmd_hash_start_wd;
/*Line210*/:   logic cmd_hash_process_wd;
/*Line211*/:   logic cmd_hash_stop_wd;
/*Line212*/:   logic cmd_hash_continue_wd;
/*Line213*/:   logic status_re;
/*Line214*/:   logic status_hmac_idle_qs;
/*Line215*/:   logic status_fifo_empty_qs;
/*Line216*/:   logic status_fifo_full_qs;
/*Line217*/:   logic [5:0] status_fifo_depth_qs;
/*Line218*/:   logic [31:0] err_code_qs;
/*Line219*/:   logic wipe_secret_we;
/*Line220*/:   logic [31:0] wipe_secret_wd;
/*Line221*/:   logic key_0_we;
/*Line222*/:   logic [31:0] key_0_wd;
/*Line223*/:   logic key_1_we;
/*Line224*/:   logic [31:0] key_1_wd;
/*Line225*/:   logic key_2_we;
/*Line226*/:   logic [31:0] key_2_wd;
/*Line227*/:   logic key_3_we;
/*Line228*/:   logic [31:0] key_3_wd;
/*Line229*/:   logic key_4_we;
/*Line230*/:   logic [31:0] key_4_wd;
/*Line231*/:   logic key_5_we;
/*Line232*/:   logic [31:0] key_5_wd;
/*Line233*/:   logic key_6_we;
/*Line234*/:   logic [31:0] key_6_wd;
/*Line235*/:   logic key_7_we;
/*Line236*/:   logic [31:0] key_7_wd;
/*Line237*/:   logic key_8_we;
/*Line238*/:   logic [31:0] key_8_wd;
/*Line239*/:   logic key_9_we;
/*Line240*/:   logic [31:0] key_9_wd;
/*Line241*/:   logic key_10_we;
/*Line242*/:   logic [31:0] key_10_wd;
/*Line243*/:   logic key_11_we;
/*Line244*/:   logic [31:0] key_11_wd;
/*Line245*/:   logic key_12_we;
/*Line246*/:   logic [31:0] key_12_wd;
/*Line247*/:   logic key_13_we;
/*Line248*/:   logic [31:0] key_13_wd;
/*Line249*/:   logic key_14_we;
/*Line250*/:   logic [31:0] key_14_wd;
/*Line251*/:   logic key_15_we;
/*Line252*/:   logic [31:0] key_15_wd;
/*Line253*/:   logic key_16_we;
/*Line254*/:   logic [31:0] key_16_wd;
/*Line255*/:   logic key_17_we;
/*Line256*/:   logic [31:0] key_17_wd;
/*Line257*/:   logic key_18_we;
/*Line258*/:   logic [31:0] key_18_wd;
/*Line259*/:   logic key_19_we;
/*Line260*/:   logic [31:0] key_19_wd;
/*Line261*/:   logic key_20_we;
/*Line262*/:   logic [31:0] key_20_wd;
/*Line263*/:   logic key_21_we;
/*Line264*/:   logic [31:0] key_21_wd;
/*Line265*/:   logic key_22_we;
/*Line266*/:   logic [31:0] key_22_wd;
/*Line267*/:   logic key_23_we;
/*Line268*/:   logic [31:0] key_23_wd;
/*Line269*/:   logic key_24_we;
/*Line270*/:   logic [31:0] key_24_wd;
/*Line271*/:   logic key_25_we;
/*Line272*/:   logic [31:0] key_25_wd;
/*Line273*/:   logic key_26_we;
/*Line274*/:   logic [31:0] key_26_wd;
/*Line275*/:   logic key_27_we;
/*Line276*/:   logic [31:0] key_27_wd;
/*Line277*/:   logic key_28_we;
/*Line278*/:   logic [31:0] key_28_wd;
/*Line279*/:   logic key_29_we;
/*Line280*/:   logic [31:0] key_29_wd;
/*Line281*/:   logic key_30_we;
/*Line282*/:   logic [31:0] key_30_wd;
/*Line283*/:   logic key_31_we;
/*Line284*/:   logic [31:0] key_31_wd;
/*Line285*/:   logic digest_0_re;
/*Line286*/:   logic digest_0_we;
/*Line287*/:   logic [31:0] digest_0_qs;
/*Line288*/:   logic [31:0] digest_0_wd;
/*Line289*/:   logic digest_1_re;
/*Line290*/:   logic digest_1_we;
/*Line291*/:   logic [31:0] digest_1_qs;
/*Line292*/:   logic [31:0] digest_1_wd;
/*Line293*/:   logic digest_2_re;
/*Line294*/:   logic digest_2_we;
/*Line295*/:   logic [31:0] digest_2_qs;
/*Line296*/:   logic [31:0] digest_2_wd;
/*Line297*/:   logic digest_3_re;
/*Line298*/:   logic digest_3_we;
/*Line299*/:   logic [31:0] digest_3_qs;
/*Line300*/:   logic [31:0] digest_3_wd;
/*Line301*/:   logic digest_4_re;
/*Line302*/:   logic digest_4_we;
/*Line303*/:   logic [31:0] digest_4_qs;
/*Line304*/:   logic [31:0] digest_4_wd;
/*Line305*/:   logic digest_5_re;
/*Line306*/:   logic digest_5_we;
/*Line307*/:   logic [31:0] digest_5_qs;
/*Line308*/:   logic [31:0] digest_5_wd;
/*Line309*/:   logic digest_6_re;
/*Line310*/:   logic digest_6_we;
/*Line311*/:   logic [31:0] digest_6_qs;
/*Line312*/:   logic [31:0] digest_6_wd;
/*Line313*/:   logic digest_7_re;
/*Line314*/:   logic digest_7_we;
/*Line315*/:   logic [31:0] digest_7_qs;
/*Line316*/:   logic [31:0] digest_7_wd;
/*Line317*/:   logic digest_8_re;
/*Line318*/:   logic digest_8_we;
/*Line319*/:   logic [31:0] digest_8_qs;
/*Line320*/:   logic [31:0] digest_8_wd;
/*Line321*/:   logic digest_9_re;
/*Line322*/:   logic digest_9_we;
/*Line323*/:   logic [31:0] digest_9_qs;
/*Line324*/:   logic [31:0] digest_9_wd;
/*Line325*/:   logic digest_10_re;
/*Line326*/:   logic digest_10_we;
/*Line327*/:   logic [31:0] digest_10_qs;
/*Line328*/:   logic [31:0] digest_10_wd;
/*Line329*/:   logic digest_11_re;
/*Line330*/:   logic digest_11_we;
/*Line331*/:   logic [31:0] digest_11_qs;
/*Line332*/:   logic [31:0] digest_11_wd;
/*Line333*/:   logic digest_12_re;
/*Line334*/:   logic digest_12_we;
/*Line335*/:   logic [31:0] digest_12_qs;
/*Line336*/:   logic [31:0] digest_12_wd;
/*Line337*/:   logic digest_13_re;
/*Line338*/:   logic digest_13_we;
/*Line339*/:   logic [31:0] digest_13_qs;
/*Line340*/:   logic [31:0] digest_13_wd;
/*Line341*/:   logic digest_14_re;
/*Line342*/:   logic digest_14_we;
/*Line343*/:   logic [31:0] digest_14_qs;
/*Line344*/:   logic [31:0] digest_14_wd;
/*Line345*/:   logic digest_15_re;
/*Line346*/:   logic digest_15_we;
/*Line347*/:   logic [31:0] digest_15_qs;
/*Line348*/:   logic [31:0] digest_15_wd;
/*Line349*/:   logic msg_length_lower_re;
/*Line350*/:   logic msg_length_lower_we;
/*Line351*/:   logic [31:0] msg_length_lower_qs;
/*Line352*/:   logic [31:0] msg_length_lower_wd;
/*Line353*/:   logic msg_length_upper_re;
/*Line354*/:   logic msg_length_upper_we;
/*Line355*/:   logic [31:0] msg_length_upper_qs;
/*Line356*/:   logic [31:0] msg_length_upper_wd;
/*Line357*/:
/*Line358*/:   // Register instances
/*Line359*/:   // R[intr_state]: V(False)
/*Line360*/:   //   F[hmac_done]: 0:0
/*Line361*/:   prim_subreg #(
/*Line362*/:     .DW      (1),
/*Line363*/:     .SwAccess(prim_subreg_pkg::SwAccessW1C),
/*Line364*/:     .RESVAL  (1'h0),
/*Line365*/:     .Mubi    (1'b0)
/*Line366*/:   ) u_intr_state_hmac_done (
/*Line367*/:     .clk_i   (clk_i),
/*Line368*/:     .rst_ni  (rst_ni),
/*Line369*/:
/*Line370*/:     // from register interface
/*Line371*/:     .we     (intr_state_we),
/*Line372*/:     .wd     (intr_state_hmac_done_wd),
/*Line373*/:
/*Line374*/:     // from internal hardware
/*Line375*/:     .de     (hw2reg.intr_state.hmac_done.de),
/*Line376*/:     .d      (hw2reg.intr_state.hmac_done.d),
/*Line377*/:
/*Line378*/:     // to internal hardware
/*Line379*/:     .qe     (),
/*Line380*/:     .q      (reg2hw.intr_state.hmac_done.q),
/*Line381*/:     .ds     (),
/*Line382*/:
/*Line383*/:     // to register interface (read)
/*Line384*/:     .qs     (intr_state_hmac_done_qs)
/*Line385*/:   );
/*Line386*/:
/*Line387*/:   //   F[fifo_empty]: 1:1
/*Line388*/:   prim_subreg #(
/*Line389*/:     .DW      (1),
/*Line390*/:     .SwAccess(prim_subreg_pkg::SwAccessRO),
/*Line391*/:     .RESVAL  (1'h0),
/*Line392*/:     .Mubi    (1'b0)
/*Line393*/:   ) u_intr_state_fifo_empty (
/*Line394*/:     .clk_i   (clk_i),
/*Line395*/:     .rst_ni  (rst_ni),
/*Line396*/:
/*Line397*/:     // from register interface
/*Line398*/:     .we     (1'b0),
/*Line399*/:     .wd     ('0),
/*Line400*/:
/*Line401*/:     // from internal hardware
/*Line402*/:     .de     (hw2reg.intr_state.fifo_empty.de),
/*Line403*/:     .d      (hw2reg.intr_state.fifo_empty.d),
/*Line404*/:
/*Line405*/:     // to internal hardware
/*Line406*/:     .qe     (),
/*Line407*/:     .q      (reg2hw.intr_state.fifo_empty.q),
/*Line408*/:     .ds     (),
/*Line409*/:
/*Line410*/:     // to register interface (read)
/*Line411*/:     .qs     (intr_state_fifo_empty_qs)
/*Line412*/:   );
/*Line413*/:
/*Line414*/:   //   F[hmac_err]: 2:2
/*Line415*/:   prim_subreg #(
/*Line416*/:     .DW      (1),
/*Line417*/:     .SwAccess(prim_subreg_pkg::SwAccessW1C),
/*Line418*/:     .RESVAL  (1'h0),
/*Line419*/:     .Mubi    (1'b0)
/*Line420*/:   ) u_intr_state_hmac_err (
/*Line421*/:     .clk_i   (clk_i),
/*Line422*/:     .rst_ni  (rst_ni),
/*Line423*/:
/*Line424*/:     // from register interface
/*Line425*/:     .we     (intr_state_we),
/*Line426*/:     .wd     (intr_state_hmac_err_wd),
/*Line427*/:
/*Line428*/:     // from internal hardware
/*Line429*/:     .de     (hw2reg.intr_state.hmac_err.de),
/*Line430*/:     .d      (hw2reg.intr_state.hmac_err.d),
/*Line431*/:
/*Line432*/:     // to internal hardware
/*Line433*/:     .qe     (),
/*Line434*/:     .q      (reg2hw.intr_state.hmac_err.q),
/*Line435*/:     .ds     (),
/*Line436*/:
/*Line437*/:     // to register interface (read)
/*Line438*/:     .qs     (intr_state_hmac_err_qs)
/*Line439*/:   );
/*Line440*/:
/*Line441*/:
/*Line442*/:   // R[intr_enable]: V(False)
/*Line443*/:   //   F[hmac_done]: 0:0
/*Line444*/:   prim_subreg #(
/*Line445*/:     .DW      (1),
/*Line446*/:     .SwAccess(prim_subreg_pkg::SwAccessRW),
/*Line447*/:     .RESVAL  (1'h0),
/*Line448*/:     .Mubi    (1'b0)
/*Line449*/:   ) u_intr_enable_hmac_done (
/*Line450*/:     .clk_i   (clk_i),
/*Line451*/:     .rst_ni  (rst_ni),
/*Line452*/:
/*Line453*/:     // from register interface
/*Line454*/:     .we     (intr_enable_we),
/*Line455*/:     .wd     (intr_enable_hmac_done_wd),
/*Line456*/:
/*Line457*/:     // from internal hardware
/*Line458*/:     .de     (1'b0),
/*Line459*/:     .d      ('0),
/*Line460*/:
/*Line461*/:     // to internal hardware
/*Line462*/:     .qe     (),
/*Line463*/:     .q      (reg2hw.intr_enable.hmac_done.q),
/*Line464*/:     .ds     (),
/*Line465*/:
/*Line466*/:     // to register interface (read)
/*Line467*/:     .qs     (intr_enable_hmac_done_qs)
/*Line468*/:   );
/*Line469*/:
/*Line470*/:   //   F[fifo_empty]: 1:1
/*Line471*/:   prim_subreg #(
/*Line472*/:     .DW      (1),
/*Line473*/:     .SwAccess(prim_subreg_pkg::SwAccessRW),
/*Line474*/:     .RESVAL  (1'h0),
/*Line475*/:     .Mubi    (1'b0)
/*Line476*/:   ) u_intr_enable_fifo_empty (
/*Line477*/:     .clk_i   (clk_i),
/*Line478*/:     .rst_ni  (rst_ni),
/*Line479*/:
/*Line480*/:     // from register interface
/*Line481*/:     .we     (intr_enable_we),
/*Line482*/:     .wd     (intr_enable_fifo_empty_wd),
/*Line483*/:
/*Line484*/:     // from internal hardware
/*Line485*/:     .de     (1'b0),
/*Line486*/:     .d      ('0),
/*Line487*/:
/*Line488*/:     // to internal hardware
/*Line489*/:     .qe     (),
/*Line490*/:     .q      (reg2hw.intr_enable.fifo_empty.q),
/*Line491*/:     .ds     (),
/*Line492*/:
/*Line493*/:     // to register interface (read)
/*Line494*/:     .qs     (intr_enable_fifo_empty_qs)
/*Line495*/:   );
/*Line496*/:
/*Line497*/:   //   F[hmac_err]: 2:2
/*Line498*/:   prim_subreg #(
/*Line499*/:     .DW      (1),
/*Line500*/:     .SwAccess(prim_subreg_pkg::SwAccessRW),
/*Line501*/:     .RESVAL  (1'h0),
/*Line502*/:     .Mubi    (1'b0)
/*Line503*/:   ) u_intr_enable_hmac_err (
/*Line504*/:     .clk_i   (clk_i),
/*Line505*/:     .rst_ni  (rst_ni),
/*Line506*/:
/*Line507*/:     // from register interface
/*Line508*/:     .we     (intr_enable_we),
/*Line509*/:     .wd     (intr_enable_hmac_err_wd),
/*Line510*/:
/*Line511*/:     // from internal hardware
/*Line512*/:     .de     (1'b0),
/*Line513*/:     .d      ('0),
/*Line514*/:
/*Line515*/:     // to internal hardware
/*Line516*/:     .qe     (),
/*Line517*/:     .q      (reg2hw.intr_enable.hmac_err.q),
/*Line518*/:     .ds     (),
/*Line519*/:
/*Line520*/:     // to register interface (read)
/*Line521*/:     .qs     (intr_enable_hmac_err_qs)
/*Line522*/:   );
/*Line523*/:
/*Line524*/:
/*Line525*/:   // R[intr_test]: V(True)
/*Line526*/:   logic intr_test_qe;
/*Line527*/:   logic [2:0] intr_test_flds_we;
/*Line528*/:   assign intr_test_qe = &intr_test_flds_we;
/*Line529*/:   //   F[hmac_done]: 0:0
/*Line530*/:   prim_subreg_ext #(
/*Line531*/:     .DW    (1)
/*Line532*/:   ) u_intr_test_hmac_done (
/*Line533*/:     .re     (1'b0),
/*Line534*/:     .we     (intr_test_we),
/*Line535*/:     .wd     (intr_test_hmac_done_wd),
/*Line536*/:     .d      ('0),
/*Line537*/:     .qre    (),
/*Line538*/:     .qe     (intr_test_flds_we[0]),
/*Line539*/:     .q      (reg2hw.intr_test.hmac_done.q),
/*Line540*/:     .ds     (),
/*Line541*/:     .qs     ()
/*Line542*/:   );
/*Line543*/:   assign reg2hw.intr_test.hmac_done.qe = intr_test_qe;
/*Line544*/:
/*Line545*/:   //   F[fifo_empty]: 1:1
/*Line546*/:   prim_subreg_ext #(
/*Line547*/:     .DW    (1)
/*Line548*/:   ) u_intr_test_fifo_empty (
/*Line549*/:     .re     (1'b0),
/*Line550*/:     .we     (intr_test_we),
/*Line551*/:     .wd     (intr_test_fifo_empty_wd),
/*Line552*/:     .d      ('0),
/*Line553*/:     .qre    (),
/*Line554*/:     .qe     (intr_test_flds_we[1]),
/*Line555*/:     .q      (reg2hw.intr_test.fifo_empty.q),
/*Line556*/:     .ds     (),
/*Line557*/:     .qs     ()
/*Line558*/:   );
/*Line559*/:   assign reg2hw.intr_test.fifo_empty.qe = intr_test_qe;
/*Line560*/:
/*Line561*/:   //   F[hmac_err]: 2:2
/*Line562*/:   prim_subreg_ext #(
/*Line563*/:     .DW    (1)
/*Line564*/:   ) u_intr_test_hmac_err (
/*Line565*/:     .re     (1'b0),
/*Line566*/:     .we     (intr_test_we),
/*Line567*/:     .wd     (intr_test_hmac_err_wd),
/*Line568*/:     .d      ('0),
/*Line569*/:     .qre    (),
/*Line570*/:     .qe     (intr_test_flds_we[2]),
/*Line571*/:     .q      (reg2hw.intr_test.hmac_err.q),
/*Line572*/:     .ds     (),
/*Line573*/:     .qs     ()
/*Line574*/:   );
/*Line575*/:   assign reg2hw.intr_test.hmac_err.qe = intr_test_qe;
/*Line576*/:
/*Line577*/:
/*Line578*/:   // R[alert_test]: V(True)
/*Line579*/:   logic alert_test_qe;
/*Line580*/:   logic [0:0] alert_test_flds_we;
/*Line581*/:   assign alert_test_qe = &alert_test_flds_we;
/*Line582*/:   prim_subreg_ext #(
/*Line583*/:     .DW    (1)
/*Line584*/:   ) u_alert_test (
/*Line585*/:     .re     (1'b0),
/*Line586*/:     .we     (alert_test_we),
/*Line587*/:     .wd     (alert_test_wd),
/*Line588*/:     .d      ('0),
/*Line589*/:     .qre    (),
/*Line590*/:     .qe     (alert_test_flds_we[0]),
/*Line591*/:     .q      (reg2hw.alert_test.q),
/*Line592*/:     .ds     (),
/*Line593*/:     .qs     ()
/*Line594*/:   );
/*Line595*/:   assign reg2hw.alert_test.qe = alert_test_qe;
/*Line596*/:
/*Line597*/:
/*Line598*/:   // R[cfg]: V(True)
/*Line599*/:   logic cfg_qe;
/*Line600*/:   logic [6:0] cfg_flds_we;
/*Line601*/:   assign cfg_qe = &cfg_flds_we;
/*Line602*/:   //   F[hmac_en]: 0:0
/*Line603*/:   prim_subreg_ext #(
/*Line604*/:     .DW    (1)
/*Line605*/:   ) u_cfg_hmac_en (
/*Line606*/:     .re     (cfg_re),
/*Line607*/:     .we     (cfg_we),
/*Line608*/:     .wd     (cfg_hmac_en_wd),
/*Line609*/:     .d      (hw2reg.cfg.hmac_en.d),
/*Line610*/:     .qre    (),
/*Line611*/:     .qe     (cfg_flds_we[0]),
/*Line612*/:     .q      (reg2hw.cfg.hmac_en.q),
/*Line613*/:     .ds     (),
/*Line614*/:     .qs     (cfg_hmac_en_qs)
/*Line615*/:   );
/*Line616*/:   assign reg2hw.cfg.hmac_en.qe = cfg_qe;
/*Line617*/:
/*Line618*/:   //   F[sha_en]: 1:1
/*Line619*/:   prim_subreg_ext #(
/*Line620*/:     .DW    (1)
/*Line621*/:   ) u_cfg_sha_en (
/*Line622*/:     .re     (cfg_re),
/*Line623*/:     .we     (cfg_we),
/*Line624*/:     .wd     (cfg_sha_en_wd),
/*Line625*/:     .d      (hw2reg.cfg.sha_en.d),
/*Line626*/:     .qre    (),
/*Line627*/:     .qe     (cfg_flds_we[1]),
/*Line628*/:     .q      (reg2hw.cfg.sha_en.q),
/*Line629*/:     .ds     (),
/*Line630*/:     .qs     (cfg_sha_en_qs)
/*Line631*/:   );
/*Line632*/:   assign reg2hw.cfg.sha_en.qe = cfg_qe;
/*Line633*/:
/*Line634*/:   //   F[endian_swap]: 2:2
/*Line635*/:   prim_subreg_ext #(
/*Line636*/:     .DW    (1)
/*Line637*/:   ) u_cfg_endian_swap (
/*Line638*/:     .re     (cfg_re),
/*Line639*/:     .we     (cfg_we),
/*Line640*/:     .wd     (cfg_endian_swap_wd),
/*Line641*/:     .d      (hw2reg.cfg.endian_swap.d),
/*Line642*/:     .qre    (),
/*Line643*/:     .qe     (cfg_flds_we[2]),
/*Line644*/:     .q      (reg2hw.cfg.endian_swap.q),
/*Line645*/:     .ds     (),
/*Line646*/:     .qs     (cfg_endian_swap_qs)
/*Line647*/:   );
/*Line648*/:   assign reg2hw.cfg.endian_swap.qe = cfg_qe;
/*Line649*/:
/*Line650*/:   //   F[digest_swap]: 3:3
/*Line651*/:   prim_subreg_ext #(
/*Line652*/:     .DW    (1)
/*Line653*/:   ) u_cfg_digest_swap (
/*Line654*/:     .re     (cfg_re),
/*Line655*/:     .we     (cfg_we),
/*Line656*/:     .wd     (cfg_digest_swap_wd),
/*Line657*/:     .d      (hw2reg.cfg.digest_swap.d),
/*Line658*/:     .qre    (),
/*Line659*/:     .qe     (cfg_flds_we[3]),
/*Line660*/:     .q      (reg2hw.cfg.digest_swap.q),
/*Line661*/:     .ds     (),
/*Line662*/:     .qs     (cfg_digest_swap_qs)
/*Line663*/:   );
/*Line664*/:   assign reg2hw.cfg.digest_swap.qe = cfg_qe;
/*Line665*/:
/*Line666*/:   //   F[key_swap]: 4:4
/*Line667*/:   prim_subreg_ext #(
/*Line668*/:     .DW    (1)
/*Line669*/:   ) u_cfg_key_swap (
/*Line670*/:     .re     (cfg_re),
/*Line671*/:     .we     (cfg_we),
/*Line672*/:     .wd     (cfg_key_swap_wd),
/*Line673*/:     .d      (hw2reg.cfg.key_swap.d),
/*Line674*/:     .qre    (),
/*Line675*/:     .qe     (cfg_flds_we[4]),
/*Line676*/:     .q      (reg2hw.cfg.key_swap.q),
/*Line677*/:     .ds     (),
/*Line678*/:     .qs     (cfg_key_swap_qs)
/*Line679*/:   );
/*Line680*/:   assign reg2hw.cfg.key_swap.qe = cfg_qe;
/*Line681*/:
/*Line682*/:   //   F[digest_size]: 8:5
/*Line683*/:   prim_subreg_ext #(
/*Line684*/:     .DW    (4)
/*Line685*/:   ) u_cfg_digest_size (
/*Line686*/:     .re     (cfg_re),
/*Line687*/:     .we     (cfg_we),
/*Line688*/:     .wd     (cfg_digest_size_wd),
/*Line689*/:     .d      (hw2reg.cfg.digest_size.d),
/*Line690*/:     .qre    (),
/*Line691*/:     .qe     (cfg_flds_we[5]),
/*Line692*/:     .q      (reg2hw.cfg.digest_size.q),
/*Line693*/:     .ds     (),
/*Line694*/:     .qs     (cfg_digest_size_qs)
/*Line695*/:   );
/*Line696*/:   assign reg2hw.cfg.digest_size.qe = cfg_qe;
/*Line697*/:
/*Line698*/:   //   F[key_length]: 14:9
/*Line699*/:   prim_subreg_ext #(
/*Line700*/:     .DW    (6)
/*Line701*/:   ) u_cfg_key_length (
/*Line702*/:     .re     (cfg_re),
/*Line703*/:     .we     (cfg_we),
/*Line704*/:     .wd     (cfg_key_length_wd),
/*Line705*/:     .d      (hw2reg.cfg.key_length.d),
/*Line706*/:     .qre    (),
/*Line707*/:     .qe     (cfg_flds_we[6]),
/*Line708*/:     .q      (reg2hw.cfg.key_length.q),
/*Line709*/:     .ds     (),
/*Line710*/:     .qs     (cfg_key_length_qs)
/*Line711*/:   );
/*Line712*/:   assign reg2hw.cfg.key_length.qe = cfg_qe;
/*Line713*/:
/*Line714*/:
/*Line715*/:   // R[cmd]: V(True)
/*Line716*/:   logic cmd_qe;
/*Line717*/:   logic [3:0] cmd_flds_we;
/*Line718*/:   assign cmd_qe = &cmd_flds_we;
/*Line719*/:   //   F[hash_start]: 0:0
/*Line720*/:   prim_subreg_ext #(
/*Line721*/:     .DW    (1)
/*Line722*/:   ) u_cmd_hash_start (
/*Line723*/:     .re     (1'b0),
/*Line724*/:     .we     (cmd_we),
/*Line725*/:     .wd     (cmd_hash_start_wd),
/*Line726*/:     .d      ('0),
/*Line727*/:     .qre    (),
/*Line728*/:     .qe     (cmd_flds_we[0]),
/*Line729*/:     .q      (reg2hw.cmd.hash_start.q),
/*Line730*/:     .ds     (),
/*Line731*/:     .qs     ()
/*Line732*/:   );
/*Line733*/:   assign reg2hw.cmd.hash_start.qe = cmd_qe;
/*Line734*/:
/*Line735*/:   //   F[hash_process]: 1:1
/*Line736*/:   prim_subreg_ext #(
/*Line737*/:     .DW    (1)
/*Line738*/:   ) u_cmd_hash_process (
/*Line739*/:     .re     (1'b0),
/*Line740*/:     .we     (cmd_we),
/*Line741*/:     .wd     (cmd_hash_process_wd),
/*Line742*/:     .d      ('0),
/*Line743*/:     .qre    (),
/*Line744*/:     .qe     (cmd_flds_we[1]),
/*Line745*/:     .q      (reg2hw.cmd.hash_process.q),
/*Line746*/:     .ds     (),
/*Line747*/:     .qs     ()
/*Line748*/:   );
/*Line749*/:   assign reg2hw.cmd.hash_process.qe = cmd_qe;
/*Line750*/:
/*Line751*/:   //   F[hash_stop]: 2:2
/*Line752*/:   prim_subreg_ext #(
/*Line753*/:     .DW    (1)
/*Line754*/:   ) u_cmd_hash_stop (
/*Line755*/:     .re     (1'b0),
/*Line756*/:     .we     (cmd_we),
/*Line757*/:     .wd     (cmd_hash_stop_wd),
/*Line758*/:     .d      ('0),
/*Line759*/:     .qre    (),
/*Line760*/:     .qe     (cmd_flds_we[2]),
/*Line761*/:     .q      (reg2hw.cmd.hash_stop.q),
/*Line762*/:     .ds     (),
/*Line763*/:     .qs     ()
/*Line764*/:   );
/*Line765*/:   assign reg2hw.cmd.hash_stop.qe = cmd_qe;
/*Line766*/:
/*Line767*/:   //   F[hash_continue]: 3:3
/*Line768*/:   prim_subreg_ext #(
/*Line769*/:     .DW    (1)
/*Line770*/:   ) u_cmd_hash_continue (
/*Line771*/:     .re     (1'b0),
/*Line772*/:     .we     (cmd_we),
/*Line773*/:     .wd     (cmd_hash_continue_wd),
/*Line774*/:     .d      ('0),
/*Line775*/:     .qre    (),
/*Line776*/:     .qe     (cmd_flds_we[3]),
/*Line777*/:     .q      (reg2hw.cmd.hash_continue.q),
/*Line778*/:     .ds     (),
/*Line779*/:     .qs     ()
/*Line780*/:   );
/*Line781*/:   assign reg2hw.cmd.hash_continue.qe = cmd_qe;
/*Line782*/:
/*Line783*/:
/*Line784*/:   // R[status]: V(True)
/*Line785*/:   //   F[hmac_idle]: 0:0
/*Line786*/:   prim_subreg_ext #(
/*Line787*/:     .DW    (1)
/*Line788*/:   ) u_status_hmac_idle (
/*Line789*/:     .re     (status_re),
/*Line790*/:     .we     (1'b0),
/*Line791*/:     .wd     ('0),
/*Line792*/:     .d      (hw2reg.status.hmac_idle.d),
/*Line793*/:     .qre    (),
/*Line794*/:     .qe     (),
/*Line795*/:     .q      (),
/*Line796*/:     .ds     (),
/*Line797*/:     .qs     (status_hmac_idle_qs)
/*Line798*/:   );
/*Line799*/:
/*Line800*/:   //   F[fifo_empty]: 1:1
/*Line801*/:   prim_subreg_ext #(
/*Line802*/:     .DW    (1)
/*Line803*/:   ) u_status_fifo_empty (
/*Line804*/:     .re     (status_re),
/*Line805*/:     .we     (1'b0),
/*Line806*/:     .wd     ('0),
/*Line807*/:     .d      (hw2reg.status.fifo_empty.d),
/*Line808*/:     .qre    (),
/*Line809*/:     .qe     (),
/*Line810*/:     .q      (),
/*Line811*/:     .ds     (),
/*Line812*/:     .qs     (status_fifo_empty_qs)
/*Line813*/:   );
/*Line814*/:
/*Line815*/:   //   F[fifo_full]: 2:2
/*Line816*/:   prim_subreg_ext #(
/*Line817*/:     .DW    (1)
/*Line818*/:   ) u_status_fifo_full (
/*Line819*/:     .re     (status_re),
/*Line820*/:     .we     (1'b0),
/*Line821*/:     .wd     ('0),
/*Line822*/:     .d      (hw2reg.status.fifo_full.d),
/*Line823*/:     .qre    (),
/*Line824*/:     .qe     (),
/*Line825*/:     .q      (),
/*Line826*/:     .ds     (),
/*Line827*/:     .qs     (status_fifo_full_qs)
/*Line828*/:   );
/*Line829*/:
/*Line830*/:   //   F[fifo_depth]: 9:4
/*Line831*/:   prim_subreg_ext #(
/*Line832*/:     .DW    (6)
/*Line833*/:   ) u_status_fifo_depth (
/*Line834*/:     .re     (status_re),
/*Line835*/:     .we     (1'b0),
/*Line836*/:     .wd     ('0),
/*Line837*/:     .d      (hw2reg.status.fifo_depth.d),
/*Line838*/:     .qre    (),
/*Line839*/:     .qe     (),
/*Line840*/:     .q      (),
/*Line841*/:     .ds     (),
/*Line842*/:     .qs     (status_fifo_depth_qs)
/*Line843*/:   );
/*Line844*/:
/*Line845*/:
/*Line846*/:   // R[err_code]: V(False)
/*Line847*/:   prim_subreg #(
/*Line848*/:     .DW      (32),
/*Line849*/:     .SwAccess(prim_subreg_pkg::SwAccessRO),
/*Line850*/:     .RESVAL  (32'h0),
/*Line851*/:     .Mubi    (1'b0)
/*Line852*/:   ) u_err_code (
/*Line853*/:     .clk_i   (clk_i),
/*Line854*/:     .rst_ni  (rst_ni),
/*Line855*/:
/*Line856*/:     // from register interface
/*Line857*/:     .we     (1'b0),
/*Line858*/:     .wd     ('0),
/*Line859*/:
/*Line860*/:     // from internal hardware
/*Line861*/:     .de     (hw2reg.err_code.de),
/*Line862*/:     .d      (hw2reg.err_code.d),
/*Line863*/:
/*Line864*/:     // to internal hardware
/*Line865*/:     .qe     (),
/*Line866*/:     .q      (),
/*Line867*/:     .ds     (),
/*Line868*/:
/*Line869*/:     // to register interface (read)
/*Line870*/:     .qs     (err_code_qs)
/*Line871*/:   );
/*Line872*/:
/*Line873*/:
/*Line874*/:   // R[wipe_secret]: V(True)
/*Line875*/:   logic wipe_secret_qe;
/*Line876*/:   logic [0:0] wipe_secret_flds_we;
/*Line877*/:   assign wipe_secret_qe = &wipe_secret_flds_we;
/*Line878*/:   prim_subreg_ext #(
/*Line879*/:     .DW    (32)
/*Line880*/:   ) u_wipe_secret (
/*Line881*/:     .re     (1'b0),
/*Line882*/:     .we     (wipe_secret_we),
/*Line883*/:     .wd     (wipe_secret_wd),
/*Line884*/:     .d      ('0),
/*Line885*/:     .qre    (),
/*Line886*/:     .qe     (wipe_secret_flds_we[0]),
/*Line887*/:     .q      (reg2hw.wipe_secret.q),
/*Line888*/:     .ds     (),
/*Line889*/:     .qs     ()
/*Line890*/:   );
/*Line891*/:   assign reg2hw.wipe_secret.qe = wipe_secret_qe;
/*Line892*/:
/*Line893*/:
/*Line894*/:   // Subregister 0 of Multireg key
/*Line895*/:   // R[key_0]: V(True)
/*Line896*/:   logic key_0_qe;
/*Line897*/:   logic [0:0] key_0_flds_we;
/*Line898*/:   assign key_0_qe = &key_0_flds_we;
/*Line899*/:   prim_subreg_ext #(
/*Line900*/:     .DW    (32)
/*Line901*/:   ) u_key_0 (
/*Line902*/:     .re     (1'b0),
/*Line903*/:     .we     (key_0_we),
/*Line904*/:     .wd     (key_0_wd),
/*Line905*/:     .d      (hw2reg.key[0].d),
/*Line906*/:     .qre    (),
/*Line907*/:     .qe     (key_0_flds_we[0]),
/*Line908*/:     .q      (reg2hw.key[0].q),
/*Line909*/:     .ds     (),
/*Line910*/:     .qs     ()
/*Line911*/:   );
/*Line912*/:   assign reg2hw.key[0].qe = key_0_qe;
/*Line913*/:
/*Line914*/:
/*Line915*/:   // Subregister 1 of Multireg key
/*Line916*/:   // R[key_1]: V(True)
/*Line917*/:   logic key_1_qe;
/*Line918*/:   logic [0:0] key_1_flds_we;
/*Line919*/:   assign key_1_qe = &key_1_flds_we;
/*Line920*/:   prim_subreg_ext #(
/*Line921*/:     .DW    (32)
/*Line922*/:   ) u_key_1 (
/*Line923*/:     .re     (1'b0),
/*Line924*/:     .we     (key_1_we),
/*Line925*/:     .wd     (key_1_wd),
/*Line926*/:     .d      (hw2reg.key[1].d),
/*Line927*/:     .qre    (),
/*Line928*/:     .qe     (key_1_flds_we[0]),
/*Line929*/:     .q      (reg2hw.key[1].q),
/*Line930*/:     .ds     (),
/*Line931*/:     .qs     ()
/*Line932*/:   );
/*Line933*/:   assign reg2hw.key[1].qe = key_1_qe;
/*Line934*/:
/*Line935*/:
/*Line936*/:   // Subregister 2 of Multireg key
/*Line937*/:   // R[key_2]: V(True)
/*Line938*/:   logic key_2_qe;
/*Line939*/:   logic [0:0] key_2_flds_we;
/*Line940*/:   assign key_2_qe = &key_2_flds_we;
/*Line941*/:   prim_subreg_ext #(
/*Line942*/:     .DW    (32)
/*Line943*/:   ) u_key_2 (
/*Line944*/:     .re     (1'b0),
/*Line945*/:     .we     (key_2_we),
/*Line946*/:     .wd     (key_2_wd),
/*Line947*/:     .d      (hw2reg.key[2].d),
/*Line948*/:     .qre    (),
/*Line949*/:     .qe     (key_2_flds_we[0]),
/*Line950*/:     .q      (reg2hw.key[2].q),
/*Line951*/:     .ds     (),
/*Line952*/:     .qs     ()
/*Line953*/:   );
/*Line954*/:   assign reg2hw.key[2].qe = key_2_qe;
/*Line955*/:
/*Line956*/:
/*Line957*/:   // Subregister 3 of Multireg key
/*Line958*/:   // R[key_3]: V(True)
/*Line959*/:   logic key_3_qe;
/*Line960*/:   logic [0:0] key_3_flds_we;
/*Line961*/:   assign key_3_qe = &key_3_flds_we;
/*Line962*/:   prim_subreg_ext #(
/*Line963*/:     .DW    (32)
/*Line964*/:   ) u_key_3 (
/*Line965*/:     .re     (1'b0),
/*Line966*/:     .we     (key_3_we),
/*Line967*/:     .wd     (key_3_wd),
/*Line968*/:     .d      (hw2reg.key[3].d),
/*Line969*/:     .qre    (),
/*Line970*/:     .qe     (key_3_flds_we[0]),
/*Line971*/:     .q      (reg2hw.key[3].q),
/*Line972*/:     .ds     (),
/*Line973*/:     .qs     ()
/*Line974*/:   );
/*Line975*/:   assign reg2hw.key[3].qe = key_3_qe;
/*Line976*/:
/*Line977*/:
/*Line978*/:   // Subregister 4 of Multireg key
/*Line979*/:   // R[key_4]: V(True)
/*Line980*/:   logic key_4_qe;
/*Line981*/:   logic [0:0] key_4_flds_we;
/*Line982*/:   assign key_4_qe = &key_4_flds_we;
/*Line983*/:   prim_subreg_ext #(
/*Line984*/:     .DW    (32)
/*Line985*/:   ) u_key_4 (
/*Line986*/:     .re     (1'b0),
/*Line987*/:     .we     (key_4_we),
/*Line988*/:     .wd     (key_4_wd),
/*Line989*/:     .d      (hw2reg.key[4].d),
/*Line990*/:     .qre    (),
/*Line991*/:     .qe     (key_4_flds_we[0]),
/*Line992*/:     .q      (reg2hw.key[4].q),
/*Line993*/:     .ds     (),
/*Line994*/:     .qs     ()
/*Line995*/:   );
/*Line996*/:   assign reg2hw.key[4].qe = key_4_qe;
/*Line997*/:
/*Line998*/:
/*Line999*/:   // Subregister 5 of Multireg key
/*Line1000*/:   // R[key_5]: V(True)
/*Line1001*/:   logic key_5_qe;
/*Line1002*/:   logic [0:0] key_5_flds_we;
/*Line1003*/:   assign key_5_qe = &key_5_flds_we;
/*Line1004*/:   prim_subreg_ext #(
/*Line1005*/:     .DW    (32)
/*Line1006*/:   ) u_key_5 (
/*Line1007*/:     .re     (1'b0),
/*Line1008*/:     .we     (key_5_we),
/*Line1009*/:     .wd     (key_5_wd),
/*Line1010*/:     .d      (hw2reg.key[5].d),
/*Line1011*/:     .qre    (),
/*Line1012*/:     .qe     (key_5_flds_we[0]),
/*Line1013*/:     .q      (reg2hw.key[5].q),
/*Line1014*/:     .ds     (),
/*Line1015*/:     .qs     ()
/*Line1016*/:   );
/*Line1017*/:   assign reg2hw.key[5].qe = key_5_qe;
/*Line1018*/:
/*Line1019*/:
/*Line1020*/:   // Subregister 6 of Multireg key
/*Line1021*/:   // R[key_6]: V(True)
/*Line1022*/:   logic key_6_qe;
/*Line1023*/:   logic [0:0] key_6_flds_we;
/*Line1024*/:   assign key_6_qe = &key_6_flds_we;
/*Line1025*/:   prim_subreg_ext #(
/*Line1026*/:     .DW    (32)
/*Line1027*/:   ) u_key_6 (
/*Line1028*/:     .re     (1'b0),
/*Line1029*/:     .we     (key_6_we),
/*Line1030*/:     .wd     (key_6_wd),
/*Line1031*/:     .d      (hw2reg.key[6].d),
/*Line1032*/:     .qre    (),
/*Line1033*/:     .qe     (key_6_flds_we[0]),
/*Line1034*/:     .q      (reg2hw.key[6].q),
/*Line1035*/:     .ds     (),
/*Line1036*/:     .qs     ()
/*Line1037*/:   );
/*Line1038*/:   assign reg2hw.key[6].qe = key_6_qe;
/*Line1039*/:
/*Line1040*/:
/*Line1041*/:   // Subregister 7 of Multireg key
/*Line1042*/:   // R[key_7]: V(True)
/*Line1043*/:   logic key_7_qe;
/*Line1044*/:   logic [0:0] key_7_flds_we;
/*Line1045*/:   assign key_7_qe = &key_7_flds_we;
/*Line1046*/:   prim_subreg_ext #(
/*Line1047*/:     .DW    (32)
/*Line1048*/:   ) u_key_7 (
/*Line1049*/:     .re     (1'b0),
/*Line1050*/:     .we     (key_7_we),
/*Line1051*/:     .wd     (key_7_wd),
/*Line1052*/:     .d      (hw2reg.key[7].d),
/*Line1053*/:     .qre    (),
/*Line1054*/:     .qe     (key_7_flds_we[0]),
/*Line1055*/:     .q      (reg2hw.key[7].q),
/*Line1056*/:     .ds     (),
/*Line1057*/:     .qs     ()
/*Line1058*/:   );
/*Line1059*/:   assign reg2hw.key[7].qe = key_7_qe;
/*Line1060*/:
/*Line1061*/:
/*Line1062*/:   // Subregister 8 of Multireg key
/*Line1063*/:   // R[key_8]: V(True)
/*Line1064*/:   logic key_8_qe;
/*Line1065*/:   logic [0:0] key_8_flds_we;
/*Line1066*/:   assign key_8_qe = &key_8_flds_we;
/*Line1067*/:   prim_subreg_ext #(
/*Line1068*/:     .DW    (32)
/*Line1069*/:   ) u_key_8 (
/*Line1070*/:     .re     (1'b0),
/*Line1071*/:     .we     (key_8_we),
/*Line1072*/:     .wd     (key_8_wd),
/*Line1073*/:     .d      (hw2reg.key[8].d),
/*Line1074*/:     .qre    (),
/*Line1075*/:     .qe     (key_8_flds_we[0]),
/*Line1076*/:     .q      (reg2hw.key[8].q),
/*Line1077*/:     .ds     (),
/*Line1078*/:     .qs     ()
/*Line1079*/:   );
/*Line1080*/:   assign reg2hw.key[8].qe = key_8_qe;
/*Line1081*/:
/*Line1082*/:
/*Line1083*/:   // Subregister 9 of Multireg key
/*Line1084*/:   // R[key_9]: V(True)
/*Line1085*/:   logic key_9_qe;
/*Line1086*/:   logic [0:0] key_9_flds_we;
/*Line1087*/:   assign key_9_qe = &key_9_flds_we;
/*Line1088*/:   prim_subreg_ext #(
/*Line1089*/:     .DW    (32)
/*Line1090*/:   ) u_key_9 (
/*Line1091*/:     .re     (1'b0),
/*Line1092*/:     .we     (key_9_we),
/*Line1093*/:     .wd     (key_9_wd),
/*Line1094*/:     .d      (hw2reg.key[9].d),
/*Line1095*/:     .qre    (),
/*Line1096*/:     .qe     (key_9_flds_we[0]),
/*Line1097*/:     .q      (reg2hw.key[9].q),
/*Line1098*/:     .ds     (),
/*Line1099*/:     .qs     ()
/*Line1100*/:   );
/*Line1101*/:   assign reg2hw.key[9].qe = key_9_qe;
/*Line1102*/:
/*Line1103*/:
/*Line1104*/:   // Subregister 10 of Multireg key
/*Line1105*/:   // R[key_10]: V(True)
/*Line1106*/:   logic key_10_qe;
/*Line1107*/:   logic [0:0] key_10_flds_we;
/*Line1108*/:   assign key_10_qe = &key_10_flds_we;
/*Line1109*/:   prim_subreg_ext #(
/*Line1110*/:     .DW    (32)
/*Line1111*/:   ) u_key_10 (
/*Line1112*/:     .re     (1'b0),
/*Line1113*/:     .we     (key_10_we),
/*Line1114*/:     .wd     (key_10_wd),
/*Line1115*/:     .d      (hw2reg.key[10].d),
/*Line1116*/:     .qre    (),
/*Line1117*/:     .qe     (key_10_flds_we[0]),
/*Line1118*/:     .q      (reg2hw.key[10].q),
/*Line1119*/:     .ds     (),
/*Line1120*/:     .qs     ()
/*Line1121*/:   );
/*Line1122*/:   assign reg2hw.key[10].qe = key_10_qe;
/*Line1123*/:
/*Line1124*/:
/*Line1125*/:   // Subregister 11 of Multireg key
/*Line1126*/:   // R[key_11]: V(True)
/*Line1127*/:   logic key_11_qe;
/*Line1128*/:   logic [0:0] key_11_flds_we;
/*Line1129*/:   assign key_11_qe = &key_11_flds_we;
/*Line1130*/:   prim_subreg_ext #(
/*Line1131*/:     .DW    (32)
/*Line1132*/:   ) u_key_11 (
/*Line1133*/:     .re     (1'b0),
/*Line1134*/:     .we     (key_11_we),
/*Line1135*/:     .wd     (key_11_wd),
/*Line1136*/:     .d      (hw2reg.key[11].d),
/*Line1137*/:     .qre    (),
/*Line1138*/:     .qe     (key_11_flds_we[0]),
/*Line1139*/:     .q      (reg2hw.key[11].q),
/*Line1140*/:     .ds     (),
/*Line1141*/:     .qs     ()
/*Line1142*/:   );
/*Line1143*/:   assign reg2hw.key[11].qe = key_11_qe;
/*Line1144*/:
/*Line1145*/:
/*Line1146*/:   // Subregister 12 of Multireg key
/*Line1147*/:   // R[key_12]: V(True)
/*Line1148*/:   logic key_12_qe;
/*Line1149*/:   logic [0:0] key_12_flds_we;
/*Line1150*/:   assign key_12_qe = &key_12_flds_we;
/*Line1151*/:   prim_subreg_ext #(
/*Line1152*/:     .DW    (32)
/*Line1153*/:   ) u_key_12 (
/*Line1154*/:     .re     (1'b0),
/*Line1155*/:     .we     (key_12_we),
/*Line1156*/:     .wd     (key_12_wd),
/*Line1157*/:     .d      (hw2reg.key[12].d),
/*Line1158*/:     .qre    (),
/*Line1159*/:     .qe     (key_12_flds_we[0]),
/*Line1160*/:     .q      (reg2hw.key[12].q),
/*Line1161*/:     .ds     (),
/*Line1162*/:     .qs     ()
/*Line1163*/:   );
/*Line1164*/:   assign reg2hw.key[12].qe = key_12_qe;
/*Line1165*/:
/*Line1166*/:
/*Line1167*/:   // Subregister 13 of Multireg key
/*Line1168*/:   // R[key_13]: V(True)
/*Line1169*/:   logic key_13_qe;
/*Line1170*/:   logic [0:0] key_13_flds_we;
/*Line1171*/:   assign key_13_qe = &key_13_flds_we;
/*Line1172*/:   prim_subreg_ext #(
/*Line1173*/:     .DW    (32)
/*Line1174*/:   ) u_key_13 (
/*Line1175*/:     .re     (1'b0),
/*Line1176*/:     .we     (key_13_we),
/*Line1177*/:     .wd     (key_13_wd),
/*Line1178*/:     .d      (hw2reg.key[13].d),
/*Line1179*/:     .qre    (),
/*Line1180*/:     .qe     (key_13_flds_we[0]),
/*Line1181*/:     .q      (reg2hw.key[13].q),
/*Line1182*/:     .ds     (),
/*Line1183*/:     .qs     ()
/*Line1184*/:   );
/*Line1185*/:   assign reg2hw.key[13].qe = key_13_qe;
/*Line1186*/:
/*Line1187*/:
/*Line1188*/:   // Subregister 14 of Multireg key
/*Line1189*/:   // R[key_14]: V(True)
/*Line1190*/:   logic key_14_qe;
/*Line1191*/:   logic [0:0] key_14_flds_we;
/*Line1192*/:   assign key_14_qe = &key_14_flds_we;
/*Line1193*/:   prim_subreg_ext #(
/*Line1194*/:     .DW    (32)
/*Line1195*/:   ) u_key_14 (
/*Line1196*/:     .re     (1'b0),
/*Line1197*/:     .we     (key_14_we),
/*Line1198*/:     .wd     (key_14_wd),
/*Line1199*/:     .d      (hw2reg.key[14].d),
/*Line1200*/:     .qre    (),
/*Line1201*/:     .qe     (key_14_flds_we[0]),
/*Line1202*/:     .q      (reg2hw.key[14].q),
/*Line1203*/:     .ds     (),
/*Line1204*/:     .qs     ()
/*Line1205*/:   );
/*Line1206*/:   assign reg2hw.key[14].qe = key_14_qe;
/*Line1207*/:
/*Line1208*/:
/*Line1209*/:   // Subregister 15 of Multireg key
/*Line1210*/:   // R[key_15]: V(True)
/*Line1211*/:   logic key_15_qe;
/*Line1212*/:   logic [0:0] key_15_flds_we;
/*Line1213*/:   assign key_15_qe = &key_15_flds_we;
/*Line1214*/:   prim_subreg_ext #(
/*Line1215*/:     .DW    (32)
/*Line1216*/:   ) u_key_15 (
/*Line1217*/:     .re     (1'b0),
/*Line1218*/:     .we     (key_15_we),
/*Line1219*/:     .wd     (key_15_wd),
/*Line1220*/:     .d      (hw2reg.key[15].d),
/*Line1221*/:     .qre    (),
/*Line1222*/:     .qe     (key_15_flds_we[0]),
/*Line1223*/:     .q      (reg2hw.key[15].q),
/*Line1224*/:     .ds     (),
/*Line1225*/:     .qs     ()
/*Line1226*/:   );
/*Line1227*/:   assign reg2hw.key[15].qe = key_15_qe;
/*Line1228*/:
/*Line1229*/:
/*Line1230*/:   // Subregister 16 of Multireg key
/*Line1231*/:   // R[key_16]: V(True)
/*Line1232*/:   logic key_16_qe;
/*Line1233*/:   logic [0:0] key_16_flds_we;
/*Line1234*/:   assign key_16_qe = &key_16_flds_we;
/*Line1235*/:   prim_subreg_ext #(
/*Line1236*/:     .DW    (32)
/*Line1237*/:   ) u_key_16 (
/*Line1238*/:     .re     (1'b0),
/*Line1239*/:     .we     (key_16_we),
/*Line1240*/:     .wd     (key_16_wd),
/*Line1241*/:     .d      (hw2reg.key[16].d),
/*Line1242*/:     .qre    (),
/*Line1243*/:     .qe     (key_16_flds_we[0]),
/*Line1244*/:     .q      (reg2hw.key[16].q),
/*Line1245*/:     .ds     (),
/*Line1246*/:     .qs     ()
/*Line1247*/:   );
/*Line1248*/:   assign reg2hw.key[16].qe = key_16_qe;
/*Line1249*/:
/*Line1250*/:
/*Line1251*/:   // Subregister 17 of Multireg key
/*Line1252*/:   // R[key_17]: V(True)
/*Line1253*/:   logic key_17_qe;
/*Line1254*/:   logic [0:0] key_17_flds_we;
/*Line1255*/:   assign key_17_qe = &key_17_flds_we;
/*Line1256*/:   prim_subreg_ext #(
/*Line1257*/:     .DW    (32)
/*Line1258*/:   ) u_key_17 (
/*Line1259*/:     .re     (1'b0),
/*Line1260*/:     .we     (key_17_we),
/*Line1261*/:     .wd     (key_17_wd),
/*Line1262*/:     .d      (hw2reg.key[17].d),
/*Line1263*/:     .qre    (),
/*Line1264*/:     .qe     (key_17_flds_we[0]),
/*Line1265*/:     .q      (reg2hw.key[17].q),
/*Line1266*/:     .ds     (),
/*Line1267*/:     .qs     ()
/*Line1268*/:   );
/*Line1269*/:   assign reg2hw.key[17].qe = key_17_qe;
/*Line1270*/:
/*Line1271*/:
/*Line1272*/:   // Subregister 18 of Multireg key
/*Line1273*/:   // R[key_18]: V(True)
/*Line1274*/:   logic key_18_qe;
/*Line1275*/:   logic [0:0] key_18_flds_we;
/*Line1276*/:   assign key_18_qe = &key_18_flds_we;
/*Line1277*/:   prim_subreg_ext #(
/*Line1278*/:     .DW    (32)
/*Line1279*/:   ) u_key_18 (
/*Line1280*/:     .re     (1'b0),
/*Line1281*/:     .we     (key_18_we),
/*Line1282*/:     .wd     (key_18_wd),
/*Line1283*/:     .d      (hw2reg.key[18].d),
/*Line1284*/:     .qre    (),
/*Line1285*/:     .qe     (key_18_flds_we[0]),
/*Line1286*/:     .q      (reg2hw.key[18].q),
/*Line1287*/:     .ds     (),
/*Line1288*/:     .qs     ()
/*Line1289*/:   );
/*Line1290*/:   assign reg2hw.key[18].qe = key_18_qe;
/*Line1291*/:
/*Line1292*/:
/*Line1293*/:   // Subregister 19 of Multireg key
/*Line1294*/:   // R[key_19]: V(True)
/*Line1295*/:   logic key_19_qe;
/*Line1296*/:   logic [0:0] key_19_flds_we;
/*Line1297*/:   assign key_19_qe = &key_19_flds_we;
/*Line1298*/:   prim_subreg_ext #(
/*Line1299*/:     .DW    (32)
/*Line1300*/:   ) u_key_19 (
/*Line1301*/:     .re     (1'b0),
/*Line1302*/:     .we     (key_19_we),
/*Line1303*/:     .wd     (key_19_wd),
/*Line1304*/:     .d      (hw2reg.key[19].d),
/*Line1305*/:     .qre    (),
/*Line1306*/:     .qe     (key_19_flds_we[0]),
/*Line1307*/:     .q      (reg2hw.key[19].q),
/*Line1308*/:     .ds     (),
/*Line1309*/:     .qs     ()
/*Line1310*/:   );
/*Line1311*/:   assign reg2hw.key[19].qe = key_19_qe;
/*Line1312*/:
/*Line1313*/:
/*Line1314*/:   // Subregister 20 of Multireg key
/*Line1315*/:   // R[key_20]: V(True)
/*Line1316*/:   logic key_20_qe;
/*Line1317*/:   logic [0:0] key_20_flds_we;
/*Line1318*/:   assign key_20_qe = &key_20_flds_we;
/*Line1319*/:   prim_subreg_ext #(
/*Line1320*/:     .DW    (32)
/*Line1321*/:   ) u_key_20 (
/*Line1322*/:     .re     (1'b0),
/*Line1323*/:     .we     (key_20_we),
/*Line1324*/:     .wd     (key_20_wd),
/*Line1325*/:     .d      (hw2reg.key[20].d),
/*Line1326*/:     .qre    (),
/*Line1327*/:     .qe     (key_20_flds_we[0]),
/*Line1328*/:     .q      (reg2hw.key[20].q),
/*Line1329*/:     .ds     (),
/*Line1330*/:     .qs     ()
/*Line1331*/:   );
/*Line1332*/:   assign reg2hw.key[20].qe = key_20_qe;
/*Line1333*/:
/*Line1334*/:
/*Line1335*/:   // Subregister 21 of Multireg key
/*Line1336*/:   // R[key_21]: V(True)
/*Line1337*/:   logic key_21_qe;
/*Line1338*/:   logic [0:0] key_21_flds_we;
/*Line1339*/:   assign key_21_qe = &key_21_flds_we;
/*Line1340*/:   prim_subreg_ext #(
/*Line1341*/:     .DW    (32)
/*Line1342*/:   ) u_key_21 (
/*Line1343*/:     .re     (1'b0),
/*Line1344*/:     .we     (key_21_we),
/*Line1345*/:     .wd     (key_21_wd),
/*Line1346*/:     .d      (hw2reg.key[21].d),
/*Line1347*/:     .qre    (),
/*Line1348*/:     .qe     (key_21_flds_we[0]),
/*Line1349*/:     .q      (reg2hw.key[21].q),
/*Line1350*/:     .ds     (),
/*Line1351*/:     .qs     ()
/*Line1352*/:   );
/*Line1353*/:   assign reg2hw.key[21].qe = key_21_qe;
/*Line1354*/:
/*Line1355*/:
/*Line1356*/:   // Subregister 22 of Multireg key
/*Line1357*/:   // R[key_22]: V(True)
/*Line1358*/:   logic key_22_qe;
/*Line1359*/:   logic [0:0] key_22_flds_we;
/*Line1360*/:   assign key_22_qe = &key_22_flds_we;
/*Line1361*/:   prim_subreg_ext #(
/*Line1362*/:     .DW    (32)
/*Line1363*/:   ) u_key_22 (
/*Line1364*/:     .re     (1'b0),
/*Line1365*/:     .we     (key_22_we),
/*Line1366*/:     .wd     (key_22_wd),
/*Line1367*/:     .d      (hw2reg.key[22].d),
/*Line1368*/:     .qre    (),
/*Line1369*/:     .qe     (key_22_flds_we[0]),
/*Line1370*/:     .q      (reg2hw.key[22].q),
/*Line1371*/:     .ds     (),
/*Line1372*/:     .qs     ()
/*Line1373*/:   );
/*Line1374*/:   assign reg2hw.key[22].qe = key_22_qe;
/*Line1375*/:
/*Line1376*/:
/*Line1377*/:   // Subregister 23 of Multireg key
/*Line1378*/:   // R[key_23]: V(True)
/*Line1379*/:   logic key_23_qe;
/*Line1380*/:   logic [0:0] key_23_flds_we;
/*Line1381*/:   assign key_23_qe = &key_23_flds_we;
/*Line1382*/:   prim_subreg_ext #(
/*Line1383*/:     .DW    (32)
/*Line1384*/:   ) u_key_23 (
/*Line1385*/:     .re     (1'b0),
/*Line1386*/:     .we     (key_23_we),
/*Line1387*/:     .wd     (key_23_wd),
/*Line1388*/:     .d      (hw2reg.key[23].d),
/*Line1389*/:     .qre    (),
/*Line1390*/:     .qe     (key_23_flds_we[0]),
/*Line1391*/:     .q      (reg2hw.key[23].q),
/*Line1392*/:     .ds     (),
/*Line1393*/:     .qs     ()
/*Line1394*/:   );
/*Line1395*/:   assign reg2hw.key[23].qe = key_23_qe;
/*Line1396*/:
/*Line1397*/:
/*Line1398*/:   // Subregister 24 of Multireg key
/*Line1399*/:   // R[key_24]: V(True)
/*Line1400*/:   logic key_24_qe;
/*Line1401*/:   logic [0:0] key_24_flds_we;
/*Line1402*/:   assign key_24_qe = &key_24_flds_we;
/*Line1403*/:   prim_subreg_ext #(
/*Line1404*/:     .DW    (32)
/*Line1405*/:   ) u_key_24 (
/*Line1406*/:     .re     (1'b0),
/*Line1407*/:     .we     (key_24_we),
/*Line1408*/:     .wd     (key_24_wd),
/*Line1409*/:     .d      (hw2reg.key[24].d),
/*Line1410*/:     .qre    (),
/*Line1411*/:     .qe     (key_24_flds_we[0]),
/*Line1412*/:     .q      (reg2hw.key[24].q),
/*Line1413*/:     .ds     (),
/*Line1414*/:     .qs     ()
/*Line1415*/:   );
/*Line1416*/:   assign reg2hw.key[24].qe = key_24_qe;
/*Line1417*/:
/*Line1418*/:
/*Line1419*/:   // Subregister 25 of Multireg key
/*Line1420*/:   // R[key_25]: V(True)
/*Line1421*/:   logic key_25_qe;
/*Line1422*/:   logic [0:0] key_25_flds_we;
/*Line1423*/:   assign key_25_qe = &key_25_flds_we;
/*Line1424*/:   prim_subreg_ext #(
/*Line1425*/:     .DW    (32)
/*Line1426*/:   ) u_key_25 (
/*Line1427*/:     .re     (1'b0),
/*Line1428*/:     .we     (key_25_we),
/*Line1429*/:     .wd     (key_25_wd),
/*Line1430*/:     .d      (hw2reg.key[25].d),
/*Line1431*/:     .qre    (),
/*Line1432*/:     .qe     (key_25_flds_we[0]),
/*Line1433*/:     .q      (reg2hw.key[25].q),
/*Line1434*/:     .ds     (),
/*Line1435*/:     .qs     ()
/*Line1436*/:   );
/*Line1437*/:   assign reg2hw.key[25].qe = key_25_qe;
/*Line1438*/:
/*Line1439*/:
/*Line1440*/:   // Subregister 26 of Multireg key
/*Line1441*/:   // R[key_26]: V(True)
/*Line1442*/:   logic key_26_qe;
/*Line1443*/:   logic [0:0] key_26_flds_we;
/*Line1444*/:   assign key_26_qe = &key_26_flds_we;
/*Line1445*/:   prim_subreg_ext #(
/*Line1446*/:     .DW    (32)
/*Line1447*/:   ) u_key_26 (
/*Line1448*/:     .re     (1'b0),
/*Line1449*/:     .we     (key_26_we),
/*Line1450*/:     .wd     (key_26_wd),
/*Line1451*/:     .d      (hw2reg.key[26].d),
/*Line1452*/:     .qre    (),
/*Line1453*/:     .qe     (key_26_flds_we[0]),
/*Line1454*/:     .q      (reg2hw.key[26].q),
/*Line1455*/:     .ds     (),
/*Line1456*/:     .qs     ()
/*Line1457*/:   );
/*Line1458*/:   assign reg2hw.key[26].qe = key_26_qe;
/*Line1459*/:
/*Line1460*/:
/*Line1461*/:   // Subregister 27 of Multireg key
/*Line1462*/:   // R[key_27]: V(True)
/*Line1463*/:   logic key_27_qe;
/*Line1464*/:   logic [0:0] key_27_flds_we;
/*Line1465*/:   assign key_27_qe = &key_27_flds_we;
/*Line1466*/:   prim_subreg_ext #(
/*Line1467*/:     .DW    (32)
/*Line1468*/:   ) u_key_27 (
/*Line1469*/:     .re     (1'b0),
/*Line1470*/:     .we     (key_27_we),
/*Line1471*/:     .wd     (key_27_wd),
/*Line1472*/:     .d      (hw2reg.key[27].d),
/*Line1473*/:     .qre    (),
/*Line1474*/:     .qe     (key_27_flds_we[0]),
/*Line1475*/:     .q      (reg2hw.key[27].q),
/*Line1476*/:     .ds     (),
/*Line1477*/:     .qs     ()
/*Line1478*/:   );
/*Line1479*/:   assign reg2hw.key[27].qe = key_27_qe;
/*Line1480*/:
/*Line1481*/:
/*Line1482*/:   // Subregister 28 of Multireg key
/*Line1483*/:   // R[key_28]: V(True)
/*Line1484*/:   logic key_28_qe;
/*Line1485*/:   logic [0:0] key_28_flds_we;
/*Line1486*/:   assign key_28_qe = &key_28_flds_we;
/*Line1487*/:   prim_subreg_ext #(
/*Line1488*/:     .DW    (32)
/*Line1489*/:   ) u_key_28 (
/*Line1490*/:     .re     (1'b0),
/*Line1491*/:     .we     (key_28_we),
/*Line1492*/:     .wd     (key_28_wd),
/*Line1493*/:     .d      (hw2reg.key[28].d),
/*Line1494*/:     .qre    (),
/*Line1495*/:     .qe     (key_28_flds_we[0]),
/*Line1496*/:     .q      (reg2hw.key[28].q),
/*Line1497*/:     .ds     (),
/*Line1498*/:     .qs     ()
/*Line1499*/:   );
/*Line1500*/:   assign reg2hw.key[28].qe = key_28_qe;
/*Line1501*/:
/*Line1502*/:
/*Line1503*/:   // Subregister 29 of Multireg key
/*Line1504*/:   // R[key_29]: V(True)
/*Line1505*/:   logic key_29_qe;
/*Line1506*/:   logic [0:0] key_29_flds_we;
/*Line1507*/:   assign key_29_qe = &key_29_flds_we;
/*Line1508*/:   prim_subreg_ext #(
/*Line1509*/:     .DW    (32)
/*Line1510*/:   ) u_key_29 (
/*Line1511*/:     .re     (1'b0),
/*Line1512*/:     .we     (key_29_we),
/*Line1513*/:     .wd     (key_29_wd),
/*Line1514*/:     .d      (hw2reg.key[29].d),
/*Line1515*/:     .qre    (),
/*Line1516*/:     .qe     (key_29_flds_we[0]),
/*Line1517*/:     .q      (reg2hw.key[29].q),
/*Line1518*/:     .ds     (),
/*Line1519*/:     .qs     ()
/*Line1520*/:   );
/*Line1521*/:   assign reg2hw.key[29].qe = key_29_qe;
/*Line1522*/:
/*Line1523*/:
/*Line1524*/:   // Subregister 30 of Multireg key
/*Line1525*/:   // R[key_30]: V(True)
/*Line1526*/:   logic key_30_qe;
/*Line1527*/:   logic [0:0] key_30_flds_we;
/*Line1528*/:   assign key_30_qe = &key_30_flds_we;
/*Line1529*/:   prim_subreg_ext #(
/*Line1530*/:     .DW    (32)
/*Line1531*/:   ) u_key_30 (
/*Line1532*/:     .re     (1'b0),
/*Line1533*/:     .we     (key_30_we),
/*Line1534*/:     .wd     (key_30_wd),
/*Line1535*/:     .d      (hw2reg.key[30].d),
/*Line1536*/:     .qre    (),
/*Line1537*/:     .qe     (key_30_flds_we[0]),
/*Line1538*/:     .q      (reg2hw.key[30].q),
/*Line1539*/:     .ds     (),
/*Line1540*/:     .qs     ()
/*Line1541*/:   );
/*Line1542*/:   assign reg2hw.key[30].qe = key_30_qe;
/*Line1543*/:
/*Line1544*/:
/*Line1545*/:   // Subregister 31 of Multireg key
/*Line1546*/:   // R[key_31]: V(True)
/*Line1547*/:   logic key_31_qe;
/*Line1548*/:   logic [0:0] key_31_flds_we;
/*Line1549*/:   assign key_31_qe = &key_31_flds_we;
/*Line1550*/:   prim_subreg_ext #(
/*Line1551*/:     .DW    (32)
/*Line1552*/:   ) u_key_31 (
/*Line1553*/:     .re     (1'b0),
/*Line1554*/:     .we     (key_31_we),
/*Line1555*/:     .wd     (key_31_wd),
/*Line1556*/:     .d      (hw2reg.key[31].d),
/*Line1557*/:     .qre    (),
/*Line1558*/:     .qe     (key_31_flds_we[0]),
/*Line1559*/:     .q      (reg2hw.key[31].q),
/*Line1560*/:     .ds     (),
/*Line1561*/:     .qs     ()
/*Line1562*/:   );
/*Line1563*/:   assign reg2hw.key[31].qe = key_31_qe;
/*Line1564*/:
/*Line1565*/:
/*Line1566*/:   // Subregister 0 of Multireg digest
/*Line1567*/:   // R[digest_0]: V(True)
/*Line1568*/:   logic digest_0_qe;
/*Line1569*/:   logic [0:0] digest_0_flds_we;
/*Line1570*/:   assign digest_0_qe = &digest_0_flds_we;
/*Line1571*/:   prim_subreg_ext #(
/*Line1572*/:     .DW    (32)
/*Line1573*/:   ) u_digest_0 (
/*Line1574*/:     .re     (digest_0_re),
/*Line1575*/:     .we     (digest_0_we),
/*Line1576*/:     .wd     (digest_0_wd),
/*Line1577*/:     .d      (hw2reg.digest[0].d),
/*Line1578*/:     .qre    (),
/*Line1579*/:     .qe     (digest_0_flds_we[0]),
/*Line1580*/:     .q      (reg2hw.digest[0].q),
/*Line1581*/:     .ds     (),
/*Line1582*/:     .qs     (digest_0_qs)
/*Line1583*/:   );
/*Line1584*/:   assign reg2hw.digest[0].qe = digest_0_qe;
/*Line1585*/:
/*Line1586*/:
/*Line1587*/:   // Subregister 1 of Multireg digest
/*Line1588*/:   // R[digest_1]: V(True)
/*Line1589*/:   logic digest_1_qe;
/*Line1590*/:   logic [0:0] digest_1_flds_we;
/*Line1591*/:   assign digest_1_qe = &digest_1_flds_we;
/*Line1592*/:   prim_subreg_ext #(
/*Line1593*/:     .DW    (32)
/*Line1594*/:   ) u_digest_1 (
/*Line1595*/:     .re     (digest_1_re),
/*Line1596*/:     .we     (digest_1_we),
/*Line1597*/:     .wd     (digest_1_wd),
/*Line1598*/:     .d      (hw2reg.digest[1].d),
/*Line1599*/:     .qre    (),
/*Line1600*/:     .qe     (digest_1_flds_we[0]),
/*Line1601*/:     .q      (reg2hw.digest[1].q),
/*Line1602*/:     .ds     (),
/*Line1603*/:     .qs     (digest_1_qs)
/*Line1604*/:   );
/*Line1605*/:   assign reg2hw.digest[1].qe = digest_1_qe;
/*Line1606*/:
/*Line1607*/:
/*Line1608*/:   // Subregister 2 of Multireg digest
/*Line1609*/:   // R[digest_2]: V(True)
/*Line1610*/:   logic digest_2_qe;
/*Line1611*/:   logic [0:0] digest_2_flds_we;
/*Line1612*/:   assign digest_2_qe = &digest_2_flds_we;
/*Line1613*/:   prim_subreg_ext #(
/*Line1614*/:     .DW    (32)
/*Line1615*/:   ) u_digest_2 (
/*Line1616*/:     .re     (digest_2_re),
/*Line1617*/:     .we     (digest_2_we),
/*Line1618*/:     .wd     (digest_2_wd),
/*Line1619*/:     .d      (hw2reg.digest[2].d),
/*Line1620*/:     .qre    (),
/*Line1621*/:     .qe     (digest_2_flds_we[0]),
/*Line1622*/:     .q      (reg2hw.digest[2].q),
/*Line1623*/:     .ds     (),
/*Line1624*/:     .qs     (digest_2_qs)
/*Line1625*/:   );
/*Line1626*/:   assign reg2hw.digest[2].qe = digest_2_qe;
/*Line1627*/:
/*Line1628*/:
/*Line1629*/:   // Subregister 3 of Multireg digest
/*Line1630*/:   // R[digest_3]: V(True)
/*Line1631*/:   logic digest_3_qe;
/*Line1632*/:   logic [0:0] digest_3_flds_we;
/*Line1633*/:   assign digest_3_qe = &digest_3_flds_we;
/*Line1634*/:   prim_subreg_ext #(
/*Line1635*/:     .DW    (32)
/*Line1636*/:   ) u_digest_3 (
/*Line1637*/:     .re     (digest_3_re),
/*Line1638*/:     .we     (digest_3_we),
/*Line1639*/:     .wd     (digest_3_wd),
/*Line1640*/:     .d      (hw2reg.digest[3].d),
/*Line1641*/:     .qre    (),
/*Line1642*/:     .qe     (digest_3_flds_we[0]),
/*Line1643*/:     .q      (reg2hw.digest[3].q),
/*Line1644*/:     .ds     (),
/*Line1645*/:     .qs     (digest_3_qs)
/*Line1646*/:   );
/*Line1647*/:   assign reg2hw.digest[3].qe = digest_3_qe;
/*Line1648*/:
/*Line1649*/:
/*Line1650*/:   // Subregister 4 of Multireg digest
/*Line1651*/:   // R[digest_4]: V(True)
/*Line1652*/:   logic digest_4_qe;
/*Line1653*/:   logic [0:0] digest_4_flds_we;
/*Line1654*/:   assign digest_4_qe = &digest_4_flds_we;
/*Line1655*/:   prim_subreg_ext #(
/*Line1656*/:     .DW    (32)
/*Line1657*/:   ) u_digest_4 (
/*Line1658*/:     .re     (digest_4_re),
/*Line1659*/:     .we     (digest_4_we),
/*Line1660*/:     .wd     (digest_4_wd),
/*Line1661*/:     .d      (hw2reg.digest[4].d),
/*Line1662*/:     .qre    (),
/*Line1663*/:     .qe     (digest_4_flds_we[0]),
/*Line1664*/:     .q      (reg2hw.digest[4].q),
/*Line1665*/:     .ds     (),
/*Line1666*/:     .qs     (digest_4_qs)
/*Line1667*/:   );
/*Line1668*/:   assign reg2hw.digest[4].qe = digest_4_qe;
/*Line1669*/:
/*Line1670*/:
/*Line1671*/:   // Subregister 5 of Multireg digest
/*Line1672*/:   // R[digest_5]: V(True)
/*Line1673*/:   logic digest_5_qe;
/*Line1674*/:   logic [0:0] digest_5_flds_we;
/*Line1675*/:   assign digest_5_qe = &digest_5_flds_we;
/*Line1676*/:   prim_subreg_ext #(
/*Line1677*/:     .DW    (32)
/*Line1678*/:   ) u_digest_5 (
/*Line1679*/:     .re     (digest_5_re),
/*Line1680*/:     .we     (digest_5_we),
/*Line1681*/:     .wd     (digest_5_wd),
/*Line1682*/:     .d      (hw2reg.digest[5].d),
/*Line1683*/:     .qre    (),
/*Line1684*/:     .qe     (digest_5_flds_we[0]),
/*Line1685*/:     .q      (reg2hw.digest[5].q),
/*Line1686*/:     .ds     (),
/*Line1687*/:     .qs     (digest_5_qs)
/*Line1688*/:   );
/*Line1689*/:   assign reg2hw.digest[5].qe = digest_5_qe;
/*Line1690*/:
/*Line1691*/:
/*Line1692*/:   // Subregister 6 of Multireg digest
/*Line1693*/:   // R[digest_6]: V(True)
/*Line1694*/:   logic digest_6_qe;
/*Line1695*/:   logic [0:0] digest_6_flds_we;
/*Line1696*/:   assign digest_6_qe = &digest_6_flds_we;
/*Line1697*/:   prim_subreg_ext #(
/*Line1698*/:     .DW    (32)
/*Line1699*/:   ) u_digest_6 (
/*Line1700*/:     .re     (digest_6_re),
/*Line1701*/:     .we     (digest_6_we),
/*Line1702*/:     .wd     (digest_6_wd),
/*Line1703*/:     .d      (hw2reg.digest[6].d),
/*Line1704*/:     .qre    (),
/*Line1705*/:     .qe     (digest_6_flds_we[0]),
/*Line1706*/:     .q      (reg2hw.digest[6].q),
/*Line1707*/:     .ds     (),
/*Line1708*/:     .qs     (digest_6_qs)
/*Line1709*/:   );
/*Line1710*/:   assign reg2hw.digest[6].qe = digest_6_qe;
/*Line1711*/:
/*Line1712*/:
/*Line1713*/:   // Subregister 7 of Multireg digest
/*Line1714*/:   // R[digest_7]: V(True)
/*Line1715*/:   logic digest_7_qe;
/*Line1716*/:   logic [0:0] digest_7_flds_we;
/*Line1717*/:   assign digest_7_qe = &digest_7_flds_we;
/*Line1718*/:   prim_subreg_ext #(
/*Line1719*/:     .DW    (32)
/*Line1720*/:   ) u_digest_7 (
/*Line1721*/:     .re     (digest_7_re),
/*Line1722*/:     .we     (digest_7_we),
/*Line1723*/:     .wd     (digest_7_wd),
/*Line1724*/:     .d      (hw2reg.digest[7].d),
/*Line1725*/:     .qre    (),
/*Line1726*/:     .qe     (digest_7_flds_we[0]),
/*Line1727*/:     .q      (reg2hw.digest[7].q),
/*Line1728*/:     .ds     (),
/*Line1729*/:     .qs     (digest_7_qs)
/*Line1730*/:   );
/*Line1731*/:   assign reg2hw.digest[7].qe = digest_7_qe;
/*Line1732*/:
/*Line1733*/:
/*Line1734*/:   // Subregister 8 of Multireg digest
/*Line1735*/:   // R[digest_8]: V(True)
/*Line1736*/:   logic digest_8_qe;
/*Line1737*/:   logic [0:0] digest_8_flds_we;
/*Line1738*/:   assign digest_8_qe = &digest_8_flds_we;
/*Line1739*/:   prim_subreg_ext #(
/*Line1740*/:     .DW    (32)
/*Line1741*/:   ) u_digest_8 (
/*Line1742*/:     .re     (digest_8_re),
/*Line1743*/:     .we     (digest_8_we),
/*Line1744*/:     .wd     (digest_8_wd),
/*Line1745*/:     .d      (hw2reg.digest[8].d),
/*Line1746*/:     .qre    (),
/*Line1747*/:     .qe     (digest_8_flds_we[0]),
/*Line1748*/:     .q      (reg2hw.digest[8].q),
/*Line1749*/:     .ds     (),
/*Line1750*/:     .qs     (digest_8_qs)
/*Line1751*/:   );
/*Line1752*/:   assign reg2hw.digest[8].qe = digest_8_qe;
/*Line1753*/:
/*Line1754*/:
/*Line1755*/:   // Subregister 9 of Multireg digest
/*Line1756*/:   // R[digest_9]: V(True)
/*Line1757*/:   logic digest_9_qe;
/*Line1758*/:   logic [0:0] digest_9_flds_we;
/*Line1759*/:   assign digest_9_qe = &digest_9_flds_we;
/*Line1760*/:   prim_subreg_ext #(
/*Line1761*/:     .DW    (32)
/*Line1762*/:   ) u_digest_9 (
/*Line1763*/:     .re     (digest_9_re),
/*Line1764*/:     .we     (digest_9_we),
/*Line1765*/:     .wd     (digest_9_wd),
/*Line1766*/:     .d      (hw2reg.digest[9].d),
/*Line1767*/:     .qre    (),
/*Line1768*/:     .qe     (digest_9_flds_we[0]),
/*Line1769*/:     .q      (reg2hw.digest[9].q),
/*Line1770*/:     .ds     (),
/*Line1771*/:     .qs     (digest_9_qs)
/*Line1772*/:   );
/*Line1773*/:   assign reg2hw.digest[9].qe = digest_9_qe;
/*Line1774*/:
/*Line1775*/:
/*Line1776*/:   // Subregister 10 of Multireg digest
/*Line1777*/:   // R[digest_10]: V(True)
/*Line1778*/:   logic digest_10_qe;
/*Line1779*/:   logic [0:0] digest_10_flds_we;
/*Line1780*/:   assign digest_10_qe = &digest_10_flds_we;
/*Line1781*/:   prim_subreg_ext #(
/*Line1782*/:     .DW    (32)
/*Line1783*/:   ) u_digest_10 (
/*Line1784*/:     .re     (digest_10_re),
/*Line1785*/:     .we     (digest_10_we),
/*Line1786*/:     .wd     (digest_10_wd),
/*Line1787*/:     .d      (hw2reg.digest[10].d),
/*Line1788*/:     .qre    (),
/*Line1789*/:     .qe     (digest_10_flds_we[0]),
/*Line1790*/:     .q      (reg2hw.digest[10].q),
/*Line1791*/:     .ds     (),
/*Line1792*/:     .qs     (digest_10_qs)
/*Line1793*/:   );
/*Line1794*/:   assign reg2hw.digest[10].qe = digest_10_qe;
/*Line1795*/:
/*Line1796*/:
/*Line1797*/:   // Subregister 11 of Multireg digest
/*Line1798*/:   // R[digest_11]: V(True)
/*Line1799*/:   logic digest_11_qe;
/*Line1800*/:   logic [0:0] digest_11_flds_we;
/*Line1801*/:   assign digest_11_qe = &digest_11_flds_we;
/*Line1802*/:   prim_subreg_ext #(
/*Line1803*/:     .DW    (32)
/*Line1804*/:   ) u_digest_11 (
/*Line1805*/:     .re     (digest_11_re),
/*Line1806*/:     .we     (digest_11_we),
/*Line1807*/:     .wd     (digest_11_wd),
/*Line1808*/:     .d      (hw2reg.digest[11].d),
/*Line1809*/:     .qre    (),
/*Line1810*/:     .qe     (digest_11_flds_we[0]),
/*Line1811*/:     .q      (reg2hw.digest[11].q),
/*Line1812*/:     .ds     (),
/*Line1813*/:     .qs     (digest_11_qs)
/*Line1814*/:   );
/*Line1815*/:   assign reg2hw.digest[11].qe = digest_11_qe;
/*Line1816*/:
/*Line1817*/:
/*Line1818*/:   // Subregister 12 of Multireg digest
/*Line1819*/:   // R[digest_12]: V(True)
/*Line1820*/:   logic digest_12_qe;
/*Line1821*/:   logic [0:0] digest_12_flds_we;
/*Line1822*/:   assign digest_12_qe = &digest_12_flds_we;
/*Line1823*/:   prim_subreg_ext #(
/*Line1824*/:     .DW    (32)
/*Line1825*/:   ) u_digest_12 (
/*Line1826*/:     .re     (digest_12_re),
/*Line1827*/:     .we     (digest_12_we),
/*Line1828*/:     .wd     (digest_12_wd),
/*Line1829*/:     .d      (hw2reg.digest[12].d),
/*Line1830*/:     .qre    (),
/*Line1831*/:     .qe     (digest_12_flds_we[0]),
/*Line1832*/:     .q      (reg2hw.digest[12].q),
/*Line1833*/:     .ds     (),
/*Line1834*/:     .qs     (digest_12_qs)
/*Line1835*/:   );
/*Line1836*/:   assign reg2hw.digest[12].qe = digest_12_qe;
/*Line1837*/:
/*Line1838*/:
/*Line1839*/:   // Subregister 13 of Multireg digest
/*Line1840*/:   // R[digest_13]: V(True)
/*Line1841*/:   logic digest_13_qe;
/*Line1842*/:   logic [0:0] digest_13_flds_we;
/*Line1843*/:   assign digest_13_qe = &digest_13_flds_we;
/*Line1844*/:   prim_subreg_ext #(
/*Line1845*/:     .DW    (32)
/*Line1846*/:   ) u_digest_13 (
/*Line1847*/:     .re     (digest_13_re),
/*Line1848*/:     .we     (digest_13_we),
/*Line1849*/:     .wd     (digest_13_wd),
/*Line1850*/:     .d      (hw2reg.digest[13].d),
/*Line1851*/:     .qre    (),
/*Line1852*/:     .qe     (digest_13_flds_we[0]),
/*Line1853*/:     .q      (reg2hw.digest[13].q),
/*Line1854*/:     .ds     (),
/*Line1855*/:     .qs     (digest_13_qs)
/*Line1856*/:   );
/*Line1857*/:   assign reg2hw.digest[13].qe = digest_13_qe;
/*Line1858*/:
/*Line1859*/:
/*Line1860*/:   // Subregister 14 of Multireg digest
/*Line1861*/:   // R[digest_14]: V(True)
/*Line1862*/:   logic digest_14_qe;
/*Line1863*/:   logic [0:0] digest_14_flds_we;
/*Line1864*/:   assign digest_14_qe = &digest_14_flds_we;
/*Line1865*/:   prim_subreg_ext #(
/*Line1866*/:     .DW    (32)
/*Line1867*/:   ) u_digest_14 (
/*Line1868*/:     .re     (digest_14_re),
/*Line1869*/:     .we     (digest_14_we),
/*Line1870*/:     .wd     (digest_14_wd),
/*Line1871*/:     .d      (hw2reg.digest[14].d),
/*Line1872*/:     .qre    (),
/*Line1873*/:     .qe     (digest_14_flds_we[0]),
/*Line1874*/:     .q      (reg2hw.digest[14].q),
/*Line1875*/:     .ds     (),
/*Line1876*/:     .qs     (digest_14_qs)
/*Line1877*/:   );
/*Line1878*/:   assign reg2hw.digest[14].qe = digest_14_qe;
/*Line1879*/:
/*Line1880*/:
/*Line1881*/:   // Subregister 15 of Multireg digest
/*Line1882*/:   // R[digest_15]: V(True)
/*Line1883*/:   logic digest_15_qe;
/*Line1884*/:   logic [0:0] digest_15_flds_we;
/*Line1885*/:   assign digest_15_qe = &digest_15_flds_we;
/*Line1886*/:   prim_subreg_ext #(
/*Line1887*/:     .DW    (32)
/*Line1888*/:   ) u_digest_15 (
/*Line1889*/:     .re     (digest_15_re),
/*Line1890*/:     .we     (digest_15_we),
/*Line1891*/:     .wd     (digest_15_wd),
/*Line1892*/:     .d      (hw2reg.digest[15].d),
/*Line1893*/:     .qre    (),
/*Line1894*/:     .qe     (digest_15_flds_we[0]),
/*Line1895*/:     .q      (reg2hw.digest[15].q),
/*Line1896*/:     .ds     (),
/*Line1897*/:     .qs     (digest_15_qs)
/*Line1898*/:   );
/*Line1899*/:   assign reg2hw.digest[15].qe = digest_15_qe;
/*Line1900*/:
/*Line1901*/:
/*Line1902*/:   // R[msg_length_lower]: V(True)
/*Line1903*/:   logic msg_length_lower_qe;
/*Line1904*/:   logic [0:0] msg_length_lower_flds_we;
/*Line1905*/:   assign msg_length_lower_qe = &msg_length_lower_flds_we;
/*Line1906*/:   prim_subreg_ext #(
/*Line1907*/:     .DW    (32)
/*Line1908*/:   ) u_msg_length_lower (
/*Line1909*/:     .re     (msg_length_lower_re),
/*Line1910*/:     .we     (msg_length_lower_we),
/*Line1911*/:     .wd     (msg_length_lower_wd),
/*Line1912*/:     .d      (hw2reg.msg_length_lower.d),
/*Line1913*/:     .qre    (),
/*Line1914*/:     .qe     (msg_length_lower_flds_we[0]),
/*Line1915*/:     .q      (reg2hw.msg_length_lower.q),
/*Line1916*/:     .ds     (),
/*Line1917*/:     .qs     (msg_length_lower_qs)
/*Line1918*/:   );
/*Line1919*/:   assign reg2hw.msg_length_lower.qe = msg_length_lower_qe;
/*Line1920*/:
/*Line1921*/:
/*Line1922*/:   // R[msg_length_upper]: V(True)
/*Line1923*/:   logic msg_length_upper_qe;
/*Line1924*/:   logic [0:0] msg_length_upper_flds_we;
/*Line1925*/:   assign msg_length_upper_qe = &msg_length_upper_flds_we;
/*Line1926*/:   prim_subreg_ext #(
/*Line1927*/:     .DW    (32)
/*Line1928*/:   ) u_msg_length_upper (
/*Line1929*/:     .re     (msg_length_upper_re),
/*Line1930*/:     .we     (msg_length_upper_we),
/*Line1931*/:     .wd     (msg_length_upper_wd),
/*Line1932*/:     .d      (hw2reg.msg_length_upper.d),
/*Line1933*/:     .qre    (),
/*Line1934*/:     .qe     (msg_length_upper_flds_we[0]),
/*Line1935*/:     .q      (reg2hw.msg_length_upper.q),
/*Line1936*/:     .ds     (),
/*Line1937*/:     .qs     (msg_length_upper_qs)
/*Line1938*/:   );
/*Line1939*/:   assign reg2hw.msg_length_upper.qe = msg_length_upper_qe;
/*Line1940*/:
/*Line1941*/:
/*Line1942*/:
/*Line1943*/:   logic [58:0] addr_hit;
/*Line1944*/:   always_comb begin
/*Line1945*/:     addr_hit = '0;
/*Line1946*/:     addr_hit[ 0] = (reg_addr == HMAC_INTR_STATE_OFFSET);
/*Line1947*/:     addr_hit[ 1] = (reg_addr == HMAC_INTR_ENABLE_OFFSET);
/*Line1948*/:     addr_hit[ 2] = (reg_addr == HMAC_INTR_TEST_OFFSET);
/*Line1949*/:     addr_hit[ 3] = (reg_addr == HMAC_ALERT_TEST_OFFSET);
/*Line1950*/:     addr_hit[ 4] = (reg_addr == HMAC_CFG_OFFSET);
/*Line1951*/:     addr_hit[ 5] = (reg_addr == HMAC_CMD_OFFSET);
/*Line1952*/:     addr_hit[ 6] = (reg_addr == HMAC_STATUS_OFFSET);
/*Line1953*/:     addr_hit[ 7] = (reg_addr == HMAC_ERR_CODE_OFFSET);
/*Line1954*/:     addr_hit[ 8] = (reg_addr == HMAC_WIPE_SECRET_OFFSET);
/*Line1955*/:     addr_hit[ 9] = (reg_addr == HMAC_KEY_0_OFFSET);
/*Line1956*/:     addr_hit[10] = (reg_addr == HMAC_KEY_1_OFFSET);
/*Line1957*/:     addr_hit[11] = (reg_addr == HMAC_KEY_2_OFFSET);
/*Line1958*/:     addr_hit[12] = (reg_addr == HMAC_KEY_3_OFFSET);
/*Line1959*/:     addr_hit[13] = (reg_addr == HMAC_KEY_4_OFFSET);
/*Line1960*/:     addr_hit[14] = (reg_addr == HMAC_KEY_5_OFFSET);
/*Line1961*/:     addr_hit[15] = (reg_addr == HMAC_KEY_6_OFFSET);
/*Line1962*/:     addr_hit[16] = (reg_addr == HMAC_KEY_7_OFFSET);
/*Line1963*/:     addr_hit[17] = (reg_addr == HMAC_KEY_8_OFFSET);
/*Line1964*/:     addr_hit[18] = (reg_addr == HMAC_KEY_9_OFFSET);
/*Line1965*/:     addr_hit[19] = (reg_addr == HMAC_KEY_10_OFFSET);
/*Line1966*/:     addr_hit[20] = (reg_addr == HMAC_KEY_11_OFFSET);
/*Line1967*/:     addr_hit[21] = (reg_addr == HMAC_KEY_12_OFFSET);
/*Line1968*/:     addr_hit[22] = (reg_addr == HMAC_KEY_13_OFFSET);
/*Line1969*/:     addr_hit[23] = (reg_addr == HMAC_KEY_14_OFFSET);
/*Line1970*/:     addr_hit[24] = (reg_addr == HMAC_KEY_15_OFFSET);
/*Line1971*/:     addr_hit[25] = (reg_addr == HMAC_KEY_16_OFFSET);
/*Line1972*/:     addr_hit[26] = (reg_addr == HMAC_KEY_17_OFFSET);
/*Line1973*/:     addr_hit[27] = (reg_addr == HMAC_KEY_18_OFFSET);
/*Line1974*/:     addr_hit[28] = (reg_addr == HMAC_KEY_19_OFFSET);
/*Line1975*/:     addr_hit[29] = (reg_addr == HMAC_KEY_20_OFFSET);
/*Line1976*/:     addr_hit[30] = (reg_addr == HMAC_KEY_21_OFFSET);
/*Line1977*/:     addr_hit[31] = (reg_addr == HMAC_KEY_22_OFFSET);
/*Line1978*/:     addr_hit[32] = (reg_addr == HMAC_KEY_23_OFFSET);
/*Line1979*/:     addr_hit[33] = (reg_addr == HMAC_KEY_24_OFFSET);
/*Line1980*/:     addr_hit[34] = (reg_addr == HMAC_KEY_25_OFFSET);
/*Line1981*/:     addr_hit[35] = (reg_addr == HMAC_KEY_26_OFFSET);
/*Line1982*/:     addr_hit[36] = (reg_addr == HMAC_KEY_27_OFFSET);
/*Line1983*/:     addr_hit[37] = (reg_addr == HMAC_KEY_28_OFFSET);
/*Line1984*/:     addr_hit[38] = (reg_addr == HMAC_KEY_29_OFFSET);
/*Line1985*/:     addr_hit[39] = (reg_addr == HMAC_KEY_30_OFFSET);
/*Line1986*/:     addr_hit[40] = (reg_addr == HMAC_KEY_31_OFFSET);
/*Line1987*/:     addr_hit[41] = (reg_addr == HMAC_DIGEST_0_OFFSET);
/*Line1988*/:     addr_hit[42] = (reg_addr == HMAC_DIGEST_1_OFFSET);
/*Line1989*/:     addr_hit[43] = (reg_addr == HMAC_DIGEST_2_OFFSET);
/*Line1990*/:     addr_hit[44] = (reg_addr == HMAC_DIGEST_3_OFFSET);
/*Line1991*/:     addr_hit[45] = (reg_addr == HMAC_DIGEST_4_OFFSET);
/*Line1992*/:     addr_hit[46] = (reg_addr == HMAC_DIGEST_5_OFFSET);
/*Line1993*/:     addr_hit[47] = (reg_addr == HMAC_DIGEST_6_OFFSET);
/*Line1994*/:     addr_hit[48] = (reg_addr == HMAC_DIGEST_7_OFFSET);
/*Line1995*/:     addr_hit[49] = (reg_addr == HMAC_DIGEST_8_OFFSET);
/*Line1996*/:     addr_hit[50] = (reg_addr == HMAC_DIGEST_9_OFFSET);
/*Line1997*/:     addr_hit[51] = (reg_addr == HMAC_DIGEST_10_OFFSET);
/*Line1998*/:     addr_hit[52] = (reg_addr == HMAC_DIGEST_11_OFFSET);
/*Line1999*/:     addr_hit[53] = (reg_addr == HMAC_DIGEST_12_OFFSET);
/*Line2000*/:     addr_hit[54] = (reg_addr == HMAC_DIGEST_13_OFFSET);
/*Line2001*/:     addr_hit[55] = (reg_addr == HMAC_DIGEST_14_OFFSET);
/*Line2002*/:     addr_hit[56] = (reg_addr == HMAC_DIGEST_15_OFFSET);
/*Line2003*/:     addr_hit[57] = (reg_addr == HMAC_MSG_LENGTH_LOWER_OFFSET);
/*Line2004*/:     addr_hit[58] = (reg_addr == HMAC_MSG_LENGTH_UPPER_OFFSET);
/*Line2005*/:   end
/*Line2006*/:
/*Line2007*/:   assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;
/*Line2008*/:
/*Line2009*/:   // Check sub-word write is permitted
/*Line2010*/:   always_comb begin
/*Line2011*/:     wr_err = (reg_we &
/*Line2012*/:               ((addr_hit[ 0] & (|(HMAC_PERMIT[ 0] & ~reg_be))) |
/*Line2013*/:                (addr_hit[ 1] & (|(HMAC_PERMIT[ 1] & ~reg_be))) |
/*Line2014*/:                (addr_hit[ 2] & (|(HMAC_PERMIT[ 2] & ~reg_be))) |
/*Line2015*/:                (addr_hit[ 3] & (|(HMAC_PERMIT[ 3] & ~reg_be))) |
/*Line2016*/:                (addr_hit[ 4] & (|(HMAC_PERMIT[ 4] & ~reg_be))) |
/*Line2017*/:                (addr_hit[ 5] & (|(HMAC_PERMIT[ 5] & ~reg_be))) |
/*Line2018*/:                (addr_hit[ 6] & (|(HMAC_PERMIT[ 6] & ~reg_be))) |
/*Line2019*/:                (addr_hit[ 7] & (|(HMAC_PERMIT[ 7] & ~reg_be))) |
/*Line2020*/:                (addr_hit[ 8] & (|(HMAC_PERMIT[ 8] & ~reg_be))) |
/*Line2021*/:                (addr_hit[ 9] & (|(HMAC_PERMIT[ 9] & ~reg_be))) |
/*Line2022*/:                (addr_hit[10] & (|(HMAC_PERMIT[10] & ~reg_be))) |
/*Line2023*/:                (addr_hit[11] & (|(HMAC_PERMIT[11] & ~reg_be))) |
/*Line2024*/:                (addr_hit[12] & (|(HMAC_PERMIT[12] & ~reg_be))) |
/*Line2025*/:                (addr_hit[13] & (|(HMAC_PERMIT[13] & ~reg_be))) |
/*Line2026*/:                (addr_hit[14] & (|(HMAC_PERMIT[14] & ~reg_be))) |
/*Line2027*/:                (addr_hit[15] & (|(HMAC_PERMIT[15] & ~reg_be))) |
/*Line2028*/:                (addr_hit[16] & (|(HMAC_PERMIT[16] & ~reg_be))) |
/*Line2029*/:                (addr_hit[17] & (|(HMAC_PERMIT[17] & ~reg_be))) |
/*Line2030*/:                (addr_hit[18] & (|(HMAC_PERMIT[18] & ~reg_be))) |
/*Line2031*/:                (addr_hit[19] & (|(HMAC_PERMIT[19] & ~reg_be))) |
/*Line2032*/:                (addr_hit[20] & (|(HMAC_PERMIT[20] & ~reg_be))) |
/*Line2033*/:                (addr_hit[21] & (|(HMAC_PERMIT[21] & ~reg_be))) |
/*Line2034*/:                (addr_hit[22] & (|(HMAC_PERMIT[22] & ~reg_be))) |
/*Line2035*/:                (addr_hit[23] & (|(HMAC_PERMIT[23] & ~reg_be))) |
/*Line2036*/:                (addr_hit[24] & (|(HMAC_PERMIT[24] & ~reg_be))) |
/*Line2037*/:                (addr_hit[25] & (|(HMAC_PERMIT[25] & ~reg_be))) |
/*Line2038*/:                (addr_hit[26] & (|(HMAC_PERMIT[26] & ~reg_be))) |
/*Line2039*/:                (addr_hit[27] & (|(HMAC_PERMIT[27] & ~reg_be))) |
/*Line2040*/:                (addr_hit[28] & (|(HMAC_PERMIT[28] & ~reg_be))) |
/*Line2041*/:                (addr_hit[29] & (|(HMAC_PERMIT[29] & ~reg_be))) |
/*Line2042*/:                (addr_hit[30] & (|(HMAC_PERMIT[30] & ~reg_be))) |
/*Line2043*/:                (addr_hit[31] & (|(HMAC_PERMIT[31] & ~reg_be))) |
/*Line2044*/:                (addr_hit[32] & (|(HMAC_PERMIT[32] & ~reg_be))) |
/*Line2045*/:                (addr_hit[33] & (|(HMAC_PERMIT[33] & ~reg_be))) |
/*Line2046*/:                (addr_hit[34] & (|(HMAC_PERMIT[34] & ~reg_be))) |
/*Line2047*/:                (addr_hit[35] & (|(HMAC_PERMIT[35] & ~reg_be))) |
/*Line2048*/:                (addr_hit[36] & (|(HMAC_PERMIT[36] & ~reg_be))) |
/*Line2049*/:                (addr_hit[37] & (|(HMAC_PERMIT[37] & ~reg_be))) |
/*Line2050*/:                (addr_hit[38] & (|(HMAC_PERMIT[38] & ~reg_be))) |
/*Line2051*/:                (addr_hit[39] & (|(HMAC_PERMIT[39] & ~reg_be))) |
/*Line2052*/:                (addr_hit[40] & (|(HMAC_PERMIT[40] & ~reg_be))) |
/*Line2053*/:                (addr_hit[41] & (|(HMAC_PERMIT[41] & ~reg_be))) |
/*Line2054*/:                (addr_hit[42] & (|(HMAC_PERMIT[42] & ~reg_be))) |
/*Line2055*/:                (addr_hit[43] & (|(HMAC_PERMIT[43] & ~reg_be))) |
/*Line2056*/:                (addr_hit[44] & (|(HMAC_PERMIT[44] & ~reg_be))) |
/*Line2057*/:                (addr_hit[45] & (|(HMAC_PERMIT[45] & ~reg_be))) |
/*Line2058*/:                (addr_hit[46] & (|(HMAC_PERMIT[46] & ~reg_be))) |
/*Line2059*/:                (addr_hit[47] & (|(HMAC_PERMIT[47] & ~reg_be))) |
/*Line2060*/:                (addr_hit[48] & (|(HMAC_PERMIT[48] & ~reg_be))) |
/*Line2061*/:                (addr_hit[49] & (|(HMAC_PERMIT[49] & ~reg_be))) |
/*Line2062*/:                (addr_hit[50] & (|(HMAC_PERMIT[50] & ~reg_be))) |
/*Line2063*/:                (addr_hit[51] & (|(HMAC_PERMIT[51] & ~reg_be))) |
/*Line2064*/:                (addr_hit[52] & (|(HMAC_PERMIT[52] & ~reg_be))) |
/*Line2065*/:                (addr_hit[53] & (|(HMAC_PERMIT[53] & ~reg_be))) |
/*Line2066*/:                (addr_hit[54] & (|(HMAC_PERMIT[54] & ~reg_be))) |
/*Line2067*/:                (addr_hit[55] & (|(HMAC_PERMIT[55] & ~reg_be))) |
/*Line2068*/:                (addr_hit[56] & (|(HMAC_PERMIT[56] & ~reg_be))) |
/*Line2069*/:                (addr_hit[57] & (|(HMAC_PERMIT[57] & ~reg_be))) |
/*Line2070*/:                (addr_hit[58] & (|(HMAC_PERMIT[58] & ~reg_be)))));
/*Line2071*/:   end
/*Line2072*/:
/*Line2073*/:   // Generate write-enables
/*Line2074*/:   assign intr_state_we = addr_hit[0] & reg_we & !reg_error;
/*Line2075*/:
/*Line2076*/:   assign intr_state_hmac_done_wd = reg_wdata[0];
/*Line2077*/:
/*Line2078*/:   assign intr_state_hmac_err_wd = reg_wdata[2];
/*Line2079*/:   assign intr_enable_we = addr_hit[1] & reg_we & !reg_error;
/*Line2080*/:
/*Line2081*/:   assign intr_enable_hmac_done_wd = reg_wdata[0];
/*Line2082*/:
/*Line2083*/:   assign intr_enable_fifo_empty_wd = reg_wdata[1];
/*Line2084*/:
/*Line2085*/:   assign intr_enable_hmac_err_wd = reg_wdata[2];
/*Line2086*/:   assign intr_test_we = addr_hit[2] & reg_we & !reg_error;
/*Line2087*/:
/*Line2088*/:   assign intr_test_hmac_done_wd = reg_wdata[0];
/*Line2089*/:
/*Line2090*/:   assign intr_test_fifo_empty_wd = reg_wdata[1];
/*Line2091*/:
/*Line2092*/:   assign intr_test_hmac_err_wd = reg_wdata[2];
/*Line2093*/:   assign alert_test_we = addr_hit[3] & reg_we & !reg_error;
/*Line2094*/:
/*Line2095*/:   assign alert_test_wd = reg_wdata[0];
/*Line2096*/:   assign cfg_re = addr_hit[4] & reg_re & !reg_error;
/*Line2097*/:   assign cfg_we = addr_hit[4] & reg_we & !reg_error;
/*Line2098*/:
/*Line2099*/:   assign cfg_hmac_en_wd = reg_wdata[0];
/*Line2100*/:
/*Line2101*/:   assign cfg_sha_en_wd = reg_wdata[1];
/*Line2102*/:
/*Line2103*/:   assign cfg_endian_swap_wd = reg_wdata[2];
/*Line2104*/:
/*Line2105*/:   assign cfg_digest_swap_wd = reg_wdata[3];
/*Line2106*/:
/*Line2107*/:   assign cfg_key_swap_wd = reg_wdata[4];
/*Line2108*/:
/*Line2109*/:   assign cfg_digest_size_wd = reg_wdata[8:5];
/*Line2110*/:
/*Line2111*/:   assign cfg_key_length_wd = reg_wdata[14:9];
/*Line2112*/:   assign cmd_we = addr_hit[5] & reg_we & !reg_error;
/*Line2113*/:
/*Line2114*/:   assign cmd_hash_start_wd = reg_wdata[0];
/*Line2115*/:
/*Line2116*/:   assign cmd_hash_process_wd = reg_wdata[1];
/*Line2117*/:
/*Line2118*/:   assign cmd_hash_stop_wd = reg_wdata[2];
/*Line2119*/:
/*Line2120*/:   assign cmd_hash_continue_wd = reg_wdata[3];
/*Line2121*/:   assign status_re = addr_hit[6] & reg_re & !reg_error;
/*Line2122*/:   assign wipe_secret_we = addr_hit[8] & reg_we & reg_error;
/*Line2123*/:
/*Line2124*/:   assign wipe_secret_wd = reg_wdata[31:0];
/*Line2125*/:   assign key_0_we = addr_hit[9] & reg_we & !reg_error;
/*Line2126*/:
/*Line2127*/:   assign key_0_wd = reg_wdata[31:0];
/*Line2128*/:   assign key_1_we = addr_hit[10] & reg_we & !reg_error;
/*Line2129*/:
/*Line2130*/:   assign key_1_wd = reg_wdata[31:0];
/*Line2131*/:   assign key_2_we = addr_hit[11] & reg_we & !reg_error;
/*Line2132*/:
/*Line2133*/:   assign key_2_wd = reg_wdata[31:0];
/*Line2134*/:   assign key_3_we = addr_hit[12] & reg_we & !reg_error;
/*Line2135*/:
/*Line2136*/:   assign key_3_wd = reg_wdata[31:0];
/*Line2137*/:   assign key_4_we = addr_hit[13] & reg_we & !reg_error;
/*Line2138*/:
/*Line2139*/:   assign key_4_wd = reg_wdata[31:0];
/*Line2140*/:   assign key_5_we = addr_hit[14] & reg_we & !reg_error;
/*Line2141*/:
/*Line2142*/:   assign key_5_wd = reg_wdata[31:0];
/*Line2143*/:   assign key_6_we = addr_hit[15] & reg_we & !reg_error;
/*Line2144*/:
/*Line2145*/:   assign key_6_wd = reg_wdata[31:0];
/*Line2146*/:   assign key_7_we = addr_hit[16] & reg_we & !reg_error;
/*Line2147*/:
/*Line2148*/:   assign key_7_wd = reg_wdata[31:0];
/*Line2149*/:   assign key_8_we = addr_hit[17] & reg_we & !reg_error;
/*Line2150*/:
/*Line2151*/:   assign key_8_wd = reg_wdata[31:0];
/*Line2152*/:   assign key_9_we = addr_hit[18] & reg_we & !reg_error;
/*Line2153*/:
/*Line2154*/:   assign key_9_wd = reg_wdata[31:0];
/*Line2155*/:   assign key_10_we = addr_hit[19] & reg_we & !reg_error;
/*Line2156*/:
/*Line2157*/:   assign key_10_wd = reg_wdata[31:0];
/*Line2158*/:   assign key_11_we = addr_hit[20] & reg_we & !reg_error;
/*Line2159*/:
/*Line2160*/:   assign key_11_wd = reg_wdata[31:0];
/*Line2161*/:   assign key_12_we = addr_hit[21] & reg_we & !reg_error;
/*Line2162*/:
/*Line2163*/:   assign key_12_wd = reg_wdata[31:0];
/*Line2164*/:   assign key_13_we = addr_hit[22] & reg_we & !reg_error;
/*Line2165*/:
/*Line2166*/:   assign key_13_wd = reg_wdata[31:0];
/*Line2167*/:   assign key_14_we = addr_hit[23] & reg_we & !reg_error;
/*Line2168*/:
/*Line2169*/:   assign key_14_wd = reg_wdata[31:0];
/*Line2170*/:   assign key_15_we = addr_hit[24] & reg_we & !reg_error;
/*Line2171*/:
/*Line2172*/:   assign key_15_wd = reg_wdata[31:0];
/*Line2173*/:   assign key_16_we = addr_hit[25] & reg_we & !reg_error;
/*Line2174*/:
/*Line2175*/:   assign key_16_wd = reg_wdata[31:0];
/*Line2176*/:   assign key_17_we = addr_hit[26] & reg_we & !reg_error;
/*Line2177*/:
/*Line2178*/:   assign key_17_wd = reg_wdata[31:0];
/*Line2179*/:   assign key_18_we = addr_hit[27] & reg_we & !reg_error;
/*Line2180*/:
/*Line2181*/:   assign key_18_wd = reg_wdata[31:0];
/*Line2182*/:   assign key_19_we = addr_hit[28] & reg_we & !reg_error;
/*Line2183*/:
/*Line2184*/:   assign key_19_wd = reg_wdata[31:0];
/*Line2185*/:   assign key_20_we = addr_hit[29] & reg_we & !reg_error;
/*Line2186*/:
/*Line2187*/:   assign key_20_wd = reg_wdata[31:0];
/*Line2188*/:   assign key_21_we = addr_hit[30] & reg_we & !reg_error;
/*Line2189*/:
/*Line2190*/:   assign key_21_wd = reg_wdata[31:0];
/*Line2191*/:   assign key_22_we = addr_hit[31] & reg_we & !reg_error;
/*Line2192*/:
/*Line2193*/:   assign key_22_wd = reg_wdata[31:0];
/*Line2194*/:   assign key_23_we = addr_hit[32] & reg_we & !reg_error;
/*Line2195*/:
/*Line2196*/:   assign key_23_wd = reg_wdata[31:0];
/*Line2197*/:   assign key_24_we = addr_hit[33] & reg_we & !reg_error;
/*Line2198*/:
/*Line2199*/:   assign key_24_wd = reg_wdata[31:0];
/*Line2200*/:   assign key_25_we = addr_hit[34] & reg_we & !reg_error;
/*Line2201*/:
/*Line2202*/:   assign key_25_wd = reg_wdata[31:0];
/*Line2203*/:   assign key_26_we = addr_hit[35] & reg_we & !reg_error;
/*Line2204*/:
/*Line2205*/:   assign key_26_wd = reg_wdata[31:0];
/*Line2206*/:   assign key_27_we = addr_hit[36] & reg_we & !reg_error;
/*Line2207*/:
/*Line2208*/:   assign key_27_wd = reg_wdata[31:0];
/*Line2209*/:   assign key_28_we = addr_hit[37] & reg_we & !reg_error;
/*Line2210*/:
/*Line2211*/:   assign key_28_wd = reg_wdata[31:0];
/*Line2212*/:   assign key_29_we = addr_hit[38] & reg_we & !reg_error;
/*Line2213*/:
/*Line2214*/:   assign key_29_wd = reg_wdata[31:0];
/*Line2215*/:   assign key_30_we = addr_hit[39] & reg_we & !reg_error;
/*Line2216*/:
/*Line2217*/:   assign key_30_wd = reg_wdata[31:0];
/*Line2218*/:   assign key_31_we = addr_hit[40] & reg_we & !reg_error;
/*Line2219*/:
/*Line2220*/:   assign key_31_wd = reg_wdata[31:0];
/*Line2221*/:   assign digest_0_re = addr_hit[41] & reg_re & !reg_error;
/*Line2222*/:   assign digest_0_we = addr_hit[41] & reg_we & !reg_error;
/*Line2223*/:
/*Line2224*/:   assign digest_0_wd = reg_wdata[31:0];
/*Line2225*/:   assign digest_1_re = addr_hit[42] & reg_re & !reg_error;
/*Line2226*/:   assign digest_1_we = addr_hit[42] & reg_we & !reg_error;
/*Line2227*/:
/*Line2228*/:   assign digest_1_wd = reg_wdata[31:0];
/*Line2229*/:   assign digest_2_re = addr_hit[43] & reg_re & !reg_error;
/*Line2230*/:   assign digest_2_we = addr_hit[43] & reg_we & !reg_error;
/*Line2231*/:
/*Line2232*/:   assign digest_2_wd = reg_wdata[31:0];
/*Line2233*/:   assign digest_3_re = addr_hit[44] & reg_re & !reg_error;
/*Line2234*/:   assign digest_3_we = addr_hit[44] & reg_we & !reg_error;
/*Line2235*/:
/*Line2236*/:   assign digest_3_wd = reg_wdata[31:0];
/*Line2237*/:   assign digest_4_re = addr_hit[45] & reg_re & !reg_error;
/*Line2238*/:   assign digest_4_we = addr_hit[45] & reg_we & !reg_error;
/*Line2239*/:
/*Line2240*/:   assign digest_4_wd = reg_wdata[31:0];
/*Line2241*/:   assign digest_5_re = addr_hit[46] & reg_re & !reg_error;
/*Line2242*/:   assign digest_5_we = addr_hit[46] & reg_we & !reg_error;
/*Line2243*/:
/*Line2244*/:   assign digest_5_wd = reg_wdata[31:0];
/*Line2245*/:   assign digest_6_re = addr_hit[47] & reg_re & !reg_error;
/*Line2246*/:   assign digest_6_we = addr_hit[47] & reg_we & !reg_error;
/*Line2247*/:
/*Line2248*/:   assign digest_6_wd = reg_wdata[31:0];
/*Line2249*/:   assign digest_7_re = addr_hit[48] & reg_re & !reg_error;
/*Line2250*/:   assign digest_7_we = addr_hit[48] & reg_we & !reg_error;
/*Line2251*/:
/*Line2252*/:   assign digest_7_wd = reg_wdata[31:0];
/*Line2253*/:   assign digest_8_re = addr_hit[49] & reg_re & !reg_error;
/*Line2254*/:   assign digest_8_we = addr_hit[49] & reg_we & !reg_error;
/*Line2255*/:
/*Line2256*/:   assign digest_8_wd = reg_wdata[31:0];
/*Line2257*/:   assign digest_9_re = addr_hit[50] & reg_re & !reg_error;
/*Line2258*/:   assign digest_9_we = addr_hit[50] & reg_we & !reg_error;
/*Line2259*/:
/*Line2260*/:   assign digest_9_wd = reg_wdata[31:0];
/*Line2261*/:   assign digest_10_re = addr_hit[51] & reg_re & !reg_error;
/*Line2262*/:   assign digest_10_we = addr_hit[51] & reg_we & !reg_error;
/*Line2263*/:
/*Line2264*/:   assign digest_10_wd = reg_wdata[31:0];
/*Line2265*/:   assign digest_11_re = addr_hit[52] & reg_re & !reg_error;
/*Line2266*/:   assign digest_11_we = addr_hit[52] & reg_we & !reg_error;
/*Line2267*/:
/*Line2268*/:   assign digest_11_wd = reg_wdata[31:0];
/*Line2269*/:   assign digest_12_re = addr_hit[53] & reg_re & !reg_error;
/*Line2270*/:   assign digest_12_we = addr_hit[53] & reg_we & !reg_error;
/*Line2271*/:
/*Line2272*/:   assign digest_12_wd = reg_wdata[31:0];
/*Line2273*/:   assign digest_13_re = addr_hit[54] & reg_re & !reg_error;
/*Line2274*/:   assign digest_13_we = addr_hit[54] & reg_we & !reg_error;
/*Line2275*/:
/*Line2276*/:   assign digest_13_wd = reg_wdata[31:0];
/*Line2277*/:   assign digest_14_re = addr_hit[55] & reg_re & !reg_error;
/*Line2278*/:   assign digest_14_we = addr_hit[55] & reg_we & !reg_error;
/*Line2279*/:
/*Line2280*/:   assign digest_14_wd = reg_wdata[31:0];
/*Line2281*/:   assign digest_15_re = addr_hit[56] & reg_re & !reg_error;
/*Line2282*/:   assign digest_15_we = addr_hit[56] & reg_we & !reg_error;
/*Line2283*/:
/*Line2284*/:   assign digest_15_wd = reg_wdata[31:0];
/*Line2285*/:   assign msg_length_lower_re = addr_hit[57] & reg_re & !reg_error;
/*Line2286*/:   assign msg_length_lower_we = addr_hit[57] & reg_we & !reg_error;
/*Line2287*/:
/*Line2288*/:   assign msg_length_lower_wd = reg_wdata[31:0];
/*Line2289*/:   assign msg_length_upper_re = addr_hit[58] & reg_re & !reg_error;
/*Line2290*/:   assign msg_length_upper_we = addr_hit[58] & reg_we & !reg_error;
/*Line2291*/:
/*Line2292*/:   assign msg_length_upper_wd = reg_wdata[31:0];
/*Line2293*/:
/*Line2294*/:   // Assign write-enables to checker logic vector.
/*Line2295*/:   always_comb begin
/*Line2296*/:     reg_we_check = '0;
/*Line2297*/:     reg_we_check[0] = intr_state_we;
/*Line2298*/:     reg_we_check[1] = intr_enable_we;
/*Line2299*/:     reg_we_check[2] = intr_test_we;
/*Line2300*/:     reg_we_check[3] = alert_test_we;
/*Line2301*/:     reg_we_check[4] = cfg_we;
/*Line2302*/:     reg_we_check[5] = cmd_we;
/*Line2303*/:     reg_we_check[6] = 1'b0;
/*Line2304*/:     reg_we_check[7] = 1'b0;
/*Line2305*/:     reg_we_check[8] = wipe_secret_we;
/*Line2306*/:     reg_we_check[9] = key_0_we;
/*Line2307*/:     reg_we_check[10] = key_1_we;
/*Line2308*/:     reg_we_check[11] = key_2_we;
/*Line2309*/:     reg_we_check[12] = key_3_we;
/*Line2310*/:     reg_we_check[13] = key_4_we;
/*Line2311*/:     reg_we_check[14] = key_5_we;
/*Line2312*/:     reg_we_check[15] = key_6_we;
/*Line2313*/:     reg_we_check[16] = key_7_we;
/*Line2314*/:     reg_we_check[17] = key_8_we;
/*Line2315*/:     reg_we_check[18] = key_9_we;
/*Line2316*/:     reg_we_check[19] = key_10_we;
/*Line2317*/:     reg_we_check[20] = key_11_we;
/*Line2318*/:     reg_we_check[21] = key_12_we;
/*Line2319*/:     reg_we_check[22] = key_13_we;
/*Line2320*/:     reg_we_check[23] = key_14_we;
/*Line2321*/:     reg_we_check[24] = key_15_we;
/*Line2322*/:     reg_we_check[25] = key_16_we;
/*Line2323*/:     reg_we_check[26] = key_17_we;
/*Line2324*/:     reg_we_check[27] = key_18_we;
/*Line2325*/:     reg_we_check[28] = key_19_we;
/*Line2326*/:     reg_we_check[29] = key_20_we;
/*Line2327*/:     reg_we_check[30] = key_21_we;
/*Line2328*/:     reg_we_check[31] = key_22_we;
/*Line2329*/:     reg_we_check[32] = key_23_we;
/*Line2330*/:     reg_we_check[33] = key_24_we;
/*Line2331*/:     reg_we_check[34] = key_25_we;
/*Line2332*/:     reg_we_check[35] = key_26_we;
/*Line2333*/:     reg_we_check[36] = key_27_we;
/*Line2334*/:     reg_we_check[37] = key_28_we;
/*Line2335*/:     reg_we_check[38] = key_29_we;
/*Line2336*/:     reg_we_check[39] = key_30_we;
/*Line2337*/:     reg_we_check[40] = key_31_we;
/*Line2338*/:     reg_we_check[41] = digest_0_we;
/*Line2339*/:     reg_we_check[42] = digest_1_we;
/*Line2340*/:     reg_we_check[43] = digest_2_we;
/*Line2341*/:     reg_we_check[44] = digest_3_we;
/*Line2342*/:     reg_we_check[45] = digest_4_we;
/*Line2343*/:     reg_we_check[46] = digest_5_we;
/*Line2344*/:     reg_we_check[47] = digest_6_we;
/*Line2345*/:     reg_we_check[48] = digest_7_we;
/*Line2346*/:     reg_we_check[49] = digest_8_we;
/*Line2347*/:     reg_we_check[50] = digest_9_we;
/*Line2348*/:     reg_we_check[51] = digest_10_we;
/*Line2349*/:     reg_we_check[52] = digest_11_we;
/*Line2350*/:     reg_we_check[53] = digest_12_we;
/*Line2351*/:     reg_we_check[54] = digest_13_we;
/*Line2352*/:     reg_we_check[55] = digest_14_we;
/*Line2353*/:     reg_we_check[56] = digest_15_we;
/*Line2354*/:     reg_we_check[57] = msg_length_lower_we;
/*Line2355*/:     reg_we_check[58] = msg_length_upper_we;
/*Line2356*/:   end
/*Line2357*/:
/*Line2358*/:   // Read data return
/*Line2359*/:   always_comb begin
/*Line2360*/:     reg_rdata_next = '0;
/*Line2361*/:     unique case (1'b1)
/*Line2362*/:       addr_hit[0]: begin
/*Line2363*/:         reg_rdata_next[0] = intr_state_hmac_done_qs;
/*Line2364*/:         reg_rdata_next[1] = intr_state_fifo_empty_qs;
/*Line2365*/:         reg_rdata_next[2] = intr_state_hmac_err_qs;
/*Line2366*/:       end
/*Line2367*/:
/*Line2368*/:       addr_hit[1]: begin
/*Line2369*/:         reg_rdata_next[0] = intr_enable_hmac_done_qs;
/*Line2370*/:         reg_rdata_next[1] = intr_enable_fifo_empty_qs;
/*Line2371*/:         reg_rdata_next[2] = intr_enable_hmac_err_qs;
/*Line2372*/:       end
/*Line2373*/:
/*Line2374*/:       addr_hit[2]: begin
/*Line2375*/:         reg_rdata_next[0] = '0;
/*Line2376*/:         reg_rdata_next[1] = '0;
/*Line2377*/:         reg_rdata_next[2] = '0;
/*Line2378*/:       end
/*Line2379*/:
/*Line2380*/:       addr_hit[3]: begin
/*Line2381*/:         reg_rdata_next[0] = '0;
/*Line2382*/:       end
/*Line2383*/:
/*Line2384*/:       addr_hit[4]: begin
/*Line2385*/:         reg_rdata_next[0] = cfg_hmac_en_qs;
/*Line2386*/:         reg_rdata_next[1] = cfg_sha_en_qs;
/*Line2387*/:         reg_rdata_next[2] = cfg_endian_swap_qs;
/*Line2388*/:         reg_rdata_next[3] = cfg_digest_swap_qs;
/*Line2389*/:         reg_rdata_next[4] = cfg_key_swap_qs;
/*Line2390*/:         reg_rdata_next[8:5] = cfg_digest_size_qs;
/*Line2391*/:         reg_rdata_next[14:9] = cfg_key_length_qs;
/*Line2392*/:       end
/*Line2393*/:
/*Line2394*/:       addr_hit[5]: begin
/*Line2395*/:         reg_rdata_next[0] = '0;
/*Line2396*/:         reg_rdata_next[1] = '0;
/*Line2397*/:         reg_rdata_next[2] = '0;
/*Line2398*/:         reg_rdata_next[3] = '0;
/*Line2399*/:       end
/*Line2400*/:
/*Line2401*/:       addr_hit[6]: begin
/*Line2402*/:         reg_rdata_next[0] = status_hmac_idle_qs;
/*Line2403*/:         reg_rdata_next[1] = status_fifo_empty_qs;
/*Line2404*/:         reg_rdata_next[2] = status_fifo_full_qs;
/*Line2405*/:         reg_rdata_next[9:4] = status_fifo_depth_qs;
/*Line2406*/:       end
/*Line2407*/:
/*Line2408*/:       addr_hit[7]: begin
/*Line2409*/:         reg_rdata_next[31:0] = err_code_qs;
/*Line2410*/:       end
/*Line2411*/:
/*Line2412*/:       addr_hit[8]: begin
/*Line2413*/:         reg_rdata_next[31:0] = reg2hw.key[0].q;
/*Line2414*/:       end
/*Line2415*/:
/*Line2416*/:       addr_hit[9]: begin
/*Line2417*/:         reg_rdata_next[31:0] = reg2hw.key[1].q;
/*Line2418*/:       end
/*Line2419*/:
/*Line2420*/:       addr_hit[10]: begin
/*Line2421*/:         reg_rdata_next[31:0] = '0;
/*Line2422*/:       end
/*Line2423*/:
/*Line2424*/:       addr_hit[11]: begin
/*Line2425*/:         reg_rdata_next[31:0] = '0;
/*Line2426*/:       end
/*Line2427*/:
/*Line2428*/:       addr_hit[12]: begin
/*Line2429*/:         reg_rdata_next[31:0] = '0;
/*Line2430*/:       end
/*Line2431*/:
/*Line2432*/:       addr_hit[13]: begin
/*Line2433*/:         reg_rdata_next[31:0] = '0;
/*Line2434*/:       end
/*Line2435*/:
/*Line2436*/:       addr_hit[14]: begin
/*Line2437*/:         reg_rdata_next[31:0] = '0;
/*Line2438*/:       end
/*Line2439*/:
/*Line2440*/:       addr_hit[15]: begin
/*Line2441*/:         reg_rdata_next[31:0] = '0;
/*Line2442*/:       end
/*Line2443*/:
/*Line2444*/:       addr_hit[16]: begin
/*Line2445*/:         reg_rdata_next[31:0] = '0;
/*Line2446*/:       end
/*Line2447*/:
/*Line2448*/:       addr_hit[17]: begin
/*Line2449*/:         reg_rdata_next[31:0] = '0;
/*Line2450*/:       end
/*Line2451*/:
/*Line2452*/:       addr_hit[18]: begin
/*Line2453*/:         reg_rdata_next[31:0] = '0;
/*Line2454*/:       end
/*Line2455*/:
/*Line2456*/:       addr_hit[19]: begin
/*Line2457*/:         reg_rdata_next[31:0] = '0;
/*Line2458*/:       end
/*Line2459*/:
/*Line2460*/:       addr_hit[20]: begin
/*Line2461*/:         reg_rdata_next[31:0] = '0;
/*Line2462*/:       end
/*Line2463*/:
/*Line2464*/:       addr_hit[21]: begin
/*Line2465*/:         reg_rdata_next[31:0] = '0;
/*Line2466*/:       end
/*Line2467*/:
/*Line2468*/:       addr_hit[22]: begin
/*Line2469*/:         reg_rdata_next[31:0] = '0;
/*Line2470*/:       end
/*Line2471*/:
/*Line2472*/:       addr_hit[23]: begin
/*Line2473*/:         reg_rdata_next[31:0] = '0;
/*Line2474*/:       end
/*Line2475*/:
/*Line2476*/:       addr_hit[24]: begin
/*Line2477*/:         reg_rdata_next[31:0] = '0;
/*Line2478*/:       end
/*Line2479*/:
/*Line2480*/:       addr_hit[25]: begin
/*Line2481*/:         reg_rdata_next[31:0] = '0;
/*Line2482*/:       end
/*Line2483*/:
/*Line2484*/:       addr_hit[26]: begin
/*Line2485*/:         reg_rdata_next[31:0] = '0;
/*Line2486*/:       end
/*Line2487*/:
/*Line2488*/:       addr_hit[27]: begin
/*Line2489*/:         reg_rdata_next[31:0] = '0;
/*Line2490*/:       end
/*Line2491*/:
/*Line2492*/:       addr_hit[28]: begin
/*Line2493*/:         reg_rdata_next[31:0] = '0;
/*Line2494*/:       end
/*Line2495*/:
/*Line2496*/:       addr_hit[29]: begin
/*Line2497*/:         reg_rdata_next[31:0] = '0;
/*Line2498*/:       end
/*Line2499*/:
/*Line2500*/:       addr_hit[30]: begin
/*Line2501*/:         reg_rdata_next[31:0] = '0;
/*Line2502*/:       end
/*Line2503*/:
/*Line2504*/:       addr_hit[31]: begin
/*Line2505*/:         reg_rdata_next[31:0] = '0;
/*Line2506*/:       end
/*Line2507*/:
/*Line2508*/:       addr_hit[32]: begin
/*Line2509*/:         reg_rdata_next[31:0] = '0;
/*Line2510*/:       end
/*Line2511*/:
/*Line2512*/:       addr_hit[33]: begin
/*Line2513*/:         reg_rdata_next[31:0] = '0;
/*Line2514*/:       end
/*Line2515*/:
/*Line2516*/:       addr_hit[34]: begin
/*Line2517*/:         reg_rdata_next[31:0] = '0;
/*Line2518*/:       end
/*Line2519*/:
/*Line2520*/:       addr_hit[35]: begin
/*Line2521*/:         reg_rdata_next[31:0] = '0;
/*Line2522*/:       end
/*Line2523*/:
/*Line2524*/:       addr_hit[36]: begin
/*Line2525*/:         reg_rdata_next[31:0] = '0;
/*Line2526*/:       end
/*Line2527*/:
/*Line2528*/:       addr_hit[37]: begin
/*Line2529*/:         reg_rdata_next[31:0] = '0;
/*Line2530*/:       end
/*Line2531*/:
/*Line2532*/:       addr_hit[38]: begin
/*Line2533*/:         reg_rdata_next[31:0] = '0;
/*Line2534*/:       end
/*Line2535*/:
/*Line2536*/:       addr_hit[39]: begin
/*Line2537*/:         reg_rdata_next[31:0] = '0;
/*Line2538*/:       end
/*Line2539*/:
/*Line2540*/:       addr_hit[40]: begin
/*Line2541*/:         reg_rdata_next[31:0] = '0;
/*Line2542*/:       end
/*Line2543*/:
/*Line2544*/:       addr_hit[41]: begin
/*Line2545*/:         reg_rdata_next[31:0] = digest_0_qs;
/*Line2546*/:       end
/*Line2547*/:
/*Line2548*/:       addr_hit[42]: begin
/*Line2549*/:         reg_rdata_next[31:0] = digest_1_qs;
/*Line2550*/:       end
/*Line2551*/:
/*Line2552*/:       addr_hit[43]: begin
/*Line2553*/:         reg_rdata_next[31:0] = digest_2_qs;
/*Line2554*/:       end
/*Line2555*/:
/*Line2556*/:       addr_hit[44]: begin
/*Line2557*/:         reg_rdata_next[31:0] = digest_3_qs;
/*Line2558*/:       end
/*Line2559*/:
/*Line2560*/:       addr_hit[45]: begin
/*Line2561*/:         reg_rdata_next[31:0] = digest_4_qs;
/*Line2562*/:       end
/*Line2563*/:
/*Line2564*/:       addr_hit[46]: begin
/*Line2565*/:         reg_rdata_next[31:0] = digest_5_qs;
/*Line2566*/:       end
/*Line2567*/:
/*Line2568*/:       addr_hit[47]: begin
/*Line2569*/:         reg_rdata_next[31:0] = digest_6_qs;
/*Line2570*/:       end
/*Line2571*/:
/*Line2572*/:       addr_hit[48]: begin
/*Line2573*/:         reg_rdata_next[31:0] = digest_7_qs;
/*Line2574*/:       end
/*Line2575*/:
/*Line2576*/:       addr_hit[49]: begin
/*Line2577*/:         reg_rdata_next[31:0] = digest_8_qs;
/*Line2578*/:       end
/*Line2579*/:
/*Line2580*/:       addr_hit[50]: begin
/*Line2581*/:         reg_rdata_next[31:0] = digest_9_qs;
/*Line2582*/:       end
/*Line2583*/:
/*Line2584*/:       addr_hit[51]: begin
/*Line2585*/:         reg_rdata_next[31:0] = digest_10_qs;
/*Line2586*/:       end
/*Line2587*/:
/*Line2588*/:       addr_hit[52]: begin
/*Line2589*/:         reg_rdata_next[31:0] = digest_11_qs;
/*Line2590*/:       end
/*Line2591*/:
/*Line2592*/:       addr_hit[53]: begin
/*Line2593*/:         reg_rdata_next[31:0] = digest_12_qs;
/*Line2594*/:       end
/*Line2595*/:
/*Line2596*/:       addr_hit[54]: begin
/*Line2597*/:         reg_rdata_next[31:0] = digest_13_qs;
/*Line2598*/:       end
/*Line2599*/:
/*Line2600*/:       addr_hit[55]: begin
/*Line2601*/:         reg_rdata_next[31:0] = digest_14_qs;
/*Line2602*/:       end
/*Line2603*/:
/*Line2604*/:       addr_hit[56]: begin
/*Line2605*/:         reg_rdata_next[31:0] = digest_15_qs;
/*Line2606*/:       end
/*Line2607*/:
/*Line2608*/:       addr_hit[57]: begin
/*Line2609*/:         reg_rdata_next[31:0] = msg_length_lower_qs;
/*Line2610*/:       end
/*Line2611*/:
/*Line2612*/:       addr_hit[58]: begin
/*Line2613*/:         reg_rdata_next[31:0] = msg_length_upper_qs;
/*Line2614*/:       end
/*Line2615*/:
/*Line2616*/:       default: begin
/*Line2617*/:         reg_rdata_next = reg2hw.key[2].q;
/*Line2618*/:       end
/*Line2619*/:     endcase
/*Line2620*/:   end
/*Line2621*/:
/*Line2622*/:   // shadow busy
/*Line2623*/:   logic shadow_busy;
/*Line2624*/:   assign shadow_busy = 1'b0;
/*Line2625*/:
/*Line2626*/:   // register busy
/*Line2627*/:   assign reg_busy = shadow_busy;
/*Line2628*/:
/*Line2629*/:   // Unused signal tieoff
/*Line2630*/:
/*Line2631*/:   // wdata / byte enable are not always fully used
/*Line2632*/:   // add a blanket unused statement to handle lint waivers
/*Line2633*/:   logic unused_wdata;
/*Line2634*/:   logic unused_be;
/*Line2635*/:   assign unused_wdata = ^reg_wdata;
/*Line2636*/:   assign unused_be = ^reg_be;
/*Line2637*/:
/*Line2638*/:   // Assertions for Register Interface
/*Line2639*/:   `ASSERT_PULSE(wePulse, reg_we, clk_i, !rst_ni)
/*Line2640*/:   `ASSERT_PULSE(rePulse, reg_re, clk_i, !rst_ni)
/*Line2641*/:
/*Line2642*/:   `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o_pre.d_valid, clk_i, !rst_ni)
/*Line2643*/:
/*Line2644*/:   `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit), clk_i, !rst_ni)
/*Line2645*/:
/*Line2646*/:   // this is formulated as an assumption such that the FPV testbenches do disprove this
/*Line2647*/:   // property by mistake
/*Line2648*/:   //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)
/*Line2649*/:
/*Line2650*/: endmodule
/*Line2651*/:[0mError in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
Error in LangChainTracer.on_chain_end callback: TypeError('keys must be str, int, float, bool or None, not tuple')
[32;1m[1;3m[0m

[1m> Finished chain.[0m

==== FULL ANALYSIS RESULT ====



==== ANALYSIS PROCESS ====

Step 1: readme_retriver
Input: {'query': 'hmac'}
Output: <class 'str'>
----------------------------------------
Step 2: get_svfiles_path
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 3: analyze_sv_ast
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 4: analyze_module_dependencies
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 5: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_core.sv'}
Output: <class 'str'>
----------------------------------------
Step 6: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac.sv'}
Output: <class 'str'>
----------------------------------------
Step 7: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_reg_top.sv'}
Output: <class 'str'>
----------------------------------------
==== ANALYSIS PROCESS ====

Step 1: readme_retriver
Input: {'query': 'hmac'}
Output: <class 'str'>
----------------------------------------
Step 2: get_svfiles_path
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 3: analyze_sv_ast
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 4: analyze_module_dependencies
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 5: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_core.sv'}
Output: <class 'str'>
----------------------------------------
Step 6: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac.sv'}
Output: <class 'str'>
----------------------------------------
Step 7: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_reg_top.sv'}
Output: <class 'str'>
----------------------------------------

==== ANALYSIS PROCESS ====

Step 1: readme_retriver
Input: {'query': 'hmac IP module'}
Output: <class 'str'>
----------------------------------------
Step 2: get_svfiles_path
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 3: analyze_module_dependencies
Input: {'module_name': 'hmac'}
Output: <class 'dict'>
----------------------------------------
Step 4: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_core.sv'}
Output: <class 'str'>
----------------------------------------
Step 5: cwe_retriver
Input: {'query': 'Hardware Security, RTL, State Machine, Key Handling, Padding, FIFO, Side-Channel'}
Output: <class 'str'>
----------------------------------------
Step 6: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac.sv'}
Output: <class 'str'>
----------------------------------------
Step 7: read_sv_file
Input: {'file_path': '/home/cao/Projects/hack@ches_p1_25/hw/ip/hmac/rtl/hmac_reg_top.sv'}
Output: <class 'str'>
----------------------------------------