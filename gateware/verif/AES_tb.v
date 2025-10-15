`timescale 1ns/1ps
module AES_tb;

  reg clk = 0, resetn = 0;
  always #5 clk = ~clk; // 100MHz

  reg [6:0] awaddr, araddr;
  reg [2:0] awprot = 0, arprot = 0;
  reg awvalid = 0, arvalid = 0, wvalid = 0, bready = 0, rready = 0;
  reg [31:0] wdata = 0;
  reg [3:0] wstrb = 4'b1111;
  wire awready, wready, bvalid, arready, rvalid;
  wire [1:0] bresp, rresp;
  wire [31:0] rdata;

  AES dut (
    .s00_axi_aclk(clk), .s00_axi_aresetn(resetn),
    .s00_axi_awaddr(awaddr), .s00_axi_awprot(awprot),
    .s00_axi_awvalid(awvalid), .s00_axi_awready(awready),
    .s00_axi_wdata(wdata), .s00_axi_wstrb(wstrb),
    .s00_axi_wvalid(wvalid), .s00_axi_wready(wready),
    .s00_axi_bresp(bresp), .s00_axi_bvalid(bvalid), .s00_axi_bready(bready),
    .s00_axi_araddr(araddr), .s00_axi_arprot(arprot),
    .s00_axi_arvalid(arvalid), .s00_axi_arready(arready),
    .s00_axi_rdata(rdata), .s00_axi_rresp(rresp),
    .s00_axi_rvalid(rvalid), .s00_axi_rready(rready)
  );

  initial begin
    $display("--- AES AXI TB Starting ---");
    #50 resetn = 1;
    aes128_nist();
    aes192_nist();
    aes256_nist();
    edge_disable();
    $display("--- AES AXI TB Done ---");
    $finish;
  end

  task axi_write(input [6:0] addr, input [31:0] data);
    begin
      awaddr = addr; awvalid = 1;
      wdata = data; wvalid = 1; wstrb = 4'b1111;
      @(posedge clk);
      while(!(awready && wready)) @(posedge clk);
      awvalid = 0; wvalid = 0;
      bready = 1; @(posedge clk);
      while(!bvalid) @(posedge clk);
      bready = 0; @(posedge clk);
    end
  endtask

  task axi_read(input [6:0] addr, output [31:0] data);
    begin
      araddr = addr; arvalid = 1; rready = 1; @(posedge clk);
      while(!arready) @(posedge clk);
      arvalid = 0;
      while(!rvalid) @(posedge clk);
      data = rdata;
      rready = 0; @(posedge clk);
    end
  endtask

  // AES-128
  task aes128_nist;
    reg [127:0] key, pt, ref_ct, got_ct;
    reg [31:0] ctwords[3:0], regval; integer i, cycles;
    begin
      $display("AES128 test...");
      key = 128'h000102030405060708090a0b0c0d0e0f;
      pt  = 128'h00112233445566778899aabbccddeeff;
      ref_ct = 128'h69c4e0d86a7b0430d8cdb78070b4c55a;
      for(i=0;i<4;i=i+1) axi_write(7'h06+i,key[127-i*32-:32]);
      for(i=0;i<4;i=i+1) axi_write(7'h02+i,pt[127-i*32-:32]);
      axi_write(7'h01,0); axi_write(7'h00,1);
      cycles=0;
      repeat(1000) begin: wait_loop1
        axi_read(7'h12,regval); cycles=cycles+1;
        if(regval==1) disable wait_loop1;
        @(posedge clk);
      end
      for(i=0;i<4;i=i+1) axi_read(7'h14+i,ctwords[i]);
      got_ct = {ctwords[0],ctwords[1],ctwords[2],ctwords[3]};
      if(got_ct===ref_ct)
        $display("AES128 PASS cycles=%0d",cycles);
      else
        $display("AES128 FAIL got=%h ref=%h",got_ct,ref_ct);
      axi_write(7'h00,0); #10;
    end
  endtask

  // AES-192
  task aes192_nist;
    reg [191:0] key; reg [127:0] pt, ref_ct, got_ct;
    reg [31:0] ctwords[3:0], regval; integer i, cycles;
    begin
      $display("AES192 test...");
      key = 192'h000102030405060708090a0b0c0d0e0f1011121314151617;
      pt  = 128'h00112233445566778899aabbccddeeff;
      ref_ct = 128'hdda97ca4864cdfe06eaf70a0ec0d7191;
      for(i=0;i<6;i=i+1) axi_write(7'h06+i,key[191-i*32-:32]);
      for(i=0;i<4;i=i+1) axi_write(7'h02+i,pt[127-i*32-:32]);
      axi_write(7'h01,1); axi_write(7'h00,1);
      cycles=0;
      repeat(1000) begin: wait_loop2
        axi_read(7'h12,regval); cycles=cycles+1;
        if(regval==1) disable wait_loop2;
        @(posedge clk);
      end
      for(i=0;i<4;i=i+1) axi_read(7'h14+i,ctwords[i]);
      got_ct = {ctwords[0],ctwords[1],ctwords[2],ctwords[3]};
      if(got_ct===ref_ct)
        $display("AES192 PASS cycles=%0d",cycles);
      else
        $display("AES192 FAIL got=%h ref=%h",got_ct,ref_ct);
      axi_write(7'h00,0); #10;
    end
  endtask

  // AES-256
  task aes256_nist;
    reg [255:0] key; reg [127:0] pt, ref_ct, got_ct;
    reg [31:0] ctwords[3:0], regval; integer i, cycles;
    begin
      $display("AES256 test...");
      key = 256'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
      pt  = 128'h00112233445566778899aabbccddeeff;
      ref_ct = 128'h8ea2b7ca516745bfeafc49904b496089;
      for(i=0;i<8;i=i+1) axi_write(7'h06+i,key[255-i*32-:32]);
      for(i=0;i<4;i=i+1) axi_write(7'h02+i,pt[127-i*32-:32]);
      axi_write(7'h01,2); axi_write(7'h00,1);
      cycles=0;
      repeat(1000) begin: wait_loop3
        axi_read(7'h12,regval); cycles=cycles+1;
        if(regval==1) disable wait_loop3;
        @(posedge clk);
      end
      for(i=0;i<4;i=i+1) axi_read(7'h14+i,ctwords[i]);
      got_ct = {ctwords[0],ctwords[1],ctwords[2],ctwords[3]};
      if(got_ct===ref_ct)
        $display("AES256 PASS cycles=%0d",cycles);
      else
        $display("AES256 FAIL got=%h ref=%h",got_ct,ref_ct);
      axi_write(7'h00,0); #10;
    end
  endtask

  // Edge-case: enable not set
  task edge_disable;
    reg [31:0] regval;
    begin
      $display("Edge case: no enable...");
      axi_write(7'h01,0);
      axi_write(7'h00,0);
      axi_read(7'h12,regval);
      if(regval==0)
        $display("Edge disable PASS");
      else
        $display("Edge disable FAIL done=%h",regval);
    end
  endtask

endmodule
