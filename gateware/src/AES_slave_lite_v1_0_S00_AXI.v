
`timescale 1 ns / 1 ps

	module AES_slave_lite_v1_0_S00_AXI #
	(
		// Users to add parameters here

		// User parameters ends
		// Do not modify the parameters beyond this line

		// Width of S_AXI data bus
		parameter integer C_S_AXI_DATA_WIDTH	= 32,
		// Width of S_AXI address bus
		parameter integer C_S_AXI_ADDR_WIDTH	= 7
	)
	(
		// Users to add ports here
        output wire [1:0] AES_KEY_CHOICE,
        output wire [4*C_S_AXI_DATA_WIDTH -1:0] PLAINTEXT,
        output wire [8*C_S_AXI_DATA_WIDTH -1:0] KEY,
        input wire [4*C_S_AXI_DATA_WIDTH -1:0] CIPHERTEXT,
		// User ports ends
		// Do not modify the ports beyond this line

		// Global Clock Signal
		input wire  S_AXI_ACLK,
		// Global Reset Signal. This Signal is Active LOW
		input wire  S_AXI_ARESETN,
		// Write address (issued by master, acceped by Slave)
		input wire [C_S_AXI_ADDR_WIDTH-1 : 0] S_AXI_AWADDR,
		// Write channel Protection type. This signal indicates the
    		// privilege and security level of the transaction, and whether
    		// the transaction is a data access or an instruction access.
		input wire [2 : 0] S_AXI_AWPROT,
		// Write address valid. This signal indicates that the master signaling
    		// valid write address and control information.
		input wire  S_AXI_AWVALID,
		// Write address ready. This signal indicates that the slave is ready
    		// to accept an address and associated control signals.
		output wire  S_AXI_AWREADY,
		// Write data (issued by master, acceped by Slave) 
		input wire [C_S_AXI_DATA_WIDTH-1 : 0] S_AXI_WDATA,
		// Write strobes. This signal indicates which byte lanes hold
    		// valid data. There is one write strobe bit for each eight
    		// bits of the write data bus.    
		input wire [(C_S_AXI_DATA_WIDTH/8)-1 : 0] S_AXI_WSTRB,
		// Write valid. This signal indicates that valid write
    		// data and strobes are available.
		input wire  S_AXI_WVALID,
		// Write ready. This signal indicates that the slave
    		// can accept the write data.
		output wire  S_AXI_WREADY,
		// Write response. This signal indicates the status
    		// of the write transaction.
		output wire [1 : 0] S_AXI_BRESP,
		// Write response valid. This signal indicates that the channel
    		// is signaling a valid write response.
		output wire  S_AXI_BVALID,
		// Response ready. This signal indicates that the master
    		// can accept a write response.
		input wire  S_AXI_BREADY,
		// Read address (issued by master, acceped by Slave)
		input wire [C_S_AXI_ADDR_WIDTH-1 : 0] S_AXI_ARADDR,
		// Protection type. This signal indicates the privilege
    		// and security level of the transaction, and whether the
    		// transaction is a data access or an instruction access.
		input wire [2 : 0] S_AXI_ARPROT,
		// Read address valid. This signal indicates that the channel
    		// is signaling valid read address and control information.
		input wire  S_AXI_ARVALID,
		// Read address ready. This signal indicates that the slave is
    		// ready to accept an address and associated control signals.
		output wire  S_AXI_ARREADY,
		// Read data (issued by slave)
		output wire [C_S_AXI_DATA_WIDTH-1 : 0] S_AXI_RDATA,
		// Read response. This signal indicates the status of the
    		// read transfer.
		output wire [1 : 0] S_AXI_RRESP,
		// Read valid. This signal indicates that the channel is
    		// signaling the required read data.
		output wire  S_AXI_RVALID,
		// Read ready. This signal indicates that the master can
    		// accept the read data and response information.
		input wire  S_AXI_RREADY
	);

	// AXI4LITE signals
	reg [C_S_AXI_ADDR_WIDTH-1 : 0] 	axi_awaddr;
	reg  	axi_awready;
	reg  	axi_wready;
	reg [1 : 0] 	axi_bresp;
	reg  	axi_bvalid;
	reg [C_S_AXI_ADDR_WIDTH-1 : 0] 	axi_araddr;
	reg  	axi_arready;
	reg [1 : 0] 	axi_rresp;
	reg  	axi_rvalid;

	// Example-specific design signals
	// local parameter for addressing 32 bit / 64 bit C_S_AXI_DATA_WIDTH
	// ADDR_LSB is used for addressing 32/64 bit registers/memories
	// ADDR_LSB = 2 for 32 bits (n downto 2)
	// ADDR_LSB = 3 for 64 bits (n downto 3)
	localparam integer ADDR_LSB = (C_S_AXI_DATA_WIDTH/32) + 1;
	localparam integer OPT_MEM_ADDR_BITS = 4;
	//----------------------------------------------
	//-- Signals for user logic register space example
	//------------------------------------------------
	//-- Number of Slave Registers 24
	reg [C_S_AXI_DATA_WIDTH-1:0]	enable_reg;
	reg [C_S_AXI_DATA_WIDTH-1:0]	aes_key_choice_reg;
	reg [C_S_AXI_DATA_WIDTH-1:0]	plaintext_reg0;
	reg [C_S_AXI_DATA_WIDTH-1:0]	plaintext_reg1;
	reg [C_S_AXI_DATA_WIDTH-1:0]	plaintext_reg2;
	reg [C_S_AXI_DATA_WIDTH-1:0]	plaintext_reg3;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg0;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg1;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg2;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg3;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg4;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg5;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg6;
	reg [C_S_AXI_DATA_WIDTH-1:0]	key_reg7;
	reg [C_S_AXI_DATA_WIDTH-1:0]	done_reg;
	reg [C_S_AXI_DATA_WIDTH-1:0]	comp_state_reg;
	reg [C_S_AXI_DATA_WIDTH-1:0]	ciphertext_reg0;
	reg [C_S_AXI_DATA_WIDTH-1:0]	ciphertext_reg1;
	reg [C_S_AXI_DATA_WIDTH-1:0]	ciphertext_reg2;
	reg [C_S_AXI_DATA_WIDTH-1:0]	ciphertext_reg3;
	integer	 byte_index;

	// I/O Connections assignments

	assign S_AXI_AWREADY	= axi_awready;
	assign S_AXI_WREADY	= axi_wready;
	assign S_AXI_BRESP	= axi_bresp;
	assign S_AXI_BVALID	= axi_bvalid;
	assign S_AXI_ARREADY	= axi_arready;
	assign S_AXI_RRESP	= axi_rresp;
	assign S_AXI_RVALID	= axi_rvalid;
	 //state machine varibles 
	 reg [1:0] state_write;
	 reg [1:0] state_read;
	 //State machine local parameters
	 localparam Idle = 2'b00,Raddr = 2'b10,Rdata = 2'b11 ,Waddr = 2'b10,Wdata = 2'b11;
	// Implement Write state machine
	// Outstanding write transactions are not supported by the slave i.e., master should assert bready to receive response on or before it starts sending the new transaction
	always @(posedge S_AXI_ACLK)                                 
	  begin                                 
	     if (S_AXI_ARESETN == 1'b0)                                 
	       begin                                 
	         axi_awready <= 0;                                 
	         axi_wready <= 0;                                 
	         axi_bvalid <= 0;                                 
	         axi_bresp <= 0;                                 
	         axi_awaddr <= 0;                                 
	         state_write <= Idle;                                 
	       end                                 
	     else                                  
	       begin                                 
	         case(state_write)                                 
	           Idle:                                      
	             begin                                 
	               if(S_AXI_ARESETN == 1'b1)                                  
	                 begin                                 
	                   axi_awready <= 1'b1;                                 
	                   axi_wready <= 1'b1;                                 
	                   state_write <= Waddr;                                 
	                 end                                 
	               else state_write <= state_write;                                 
	             end                                 
	           Waddr:        //At this state, slave is ready to receive address along with corresponding control signals and first data packet. Response valid is also handled at this state                                 
	             begin                                 
	               if (S_AXI_AWVALID && S_AXI_AWREADY)                                 
	                  begin                                 
	                    axi_awaddr <= S_AXI_AWADDR;                                 
	                    if(S_AXI_WVALID)                                  
	                      begin                                   
	                        axi_awready <= 1'b1;                                 
	                        state_write <= Waddr;                                 
	                        axi_bvalid <= 1'b1;                                 
	                      end                                 
	                    else                                  
	                      begin                                 
	                        axi_awready <= 1'b0;                                 
	                        state_write <= Wdata;                                 
	                        if (S_AXI_BREADY && axi_bvalid) axi_bvalid <= 1'b0;                                 
	                      end                                 
	                  end                                 
	               else                                  
	                  begin                                 
	                    state_write <= state_write;                                 
	                    if (S_AXI_BREADY && axi_bvalid) axi_bvalid <= 1'b0;                                 
	                   end                                 
	             end                                 
	          Wdata:        //At this state, slave is ready to receive the data packets until the number of transfers is equal to burst length                                 
	             begin                                 
	               if (S_AXI_WVALID)                                 
	                 begin                                 
	                   state_write <= Waddr;                                 
	                   axi_bvalid <= 1'b1;                                 
	                   axi_awready <= 1'b1;                                 
	                 end                                 
	                else                                  
	                 begin                                 
	                   state_write <= state_write;                                 
	                   if (S_AXI_BREADY && axi_bvalid) axi_bvalid <= 1'b0;                                 
	                 end                                              
	             end                                 
	          endcase                                 
	        end                                 
	      end                                 

	// Implement memory mapped register select and write logic generation
	// The write data is accepted and written to memory mapped registers when
	// axi_awready, S_AXI_WVALID, axi_wready and S_AXI_WVALID are asserted. Write strobes are used to
	// select byte enables of slave registers while writing.
	// These registers are cleared when reset (active low) is applied.
	// Slave register write enable is asserted when valid address and data are available
	// and the slave is ready to accept the write address and write data.
	 

	always @( posedge S_AXI_ACLK )
	begin
	  if ( S_AXI_ARESETN == 1'b0 )
	    begin
	      enable_reg <= 0;
	      aes_key_choice_reg <= 0;
	      plaintext_reg0 <= 0;
	      plaintext_reg1 <= 0;
	      plaintext_reg2 <= 0;
	      plaintext_reg3 <= 0;
	      key_reg0 <= 0;
	      key_reg1 <= 0;
	      key_reg2 <= 0;
	      key_reg3 <= 0;
	      key_reg4 <= 0;
	      key_reg5 <= 0;
	      key_reg6 <= 0;
	      key_reg7 <= 0;
	    end 
	  else begin
	    if (S_AXI_WVALID)
	      begin
	        case ( (S_AXI_AWVALID) ? S_AXI_AWADDR[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] : axi_awaddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] )
	          5'h00:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 0
	                enable_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h01:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 1
	                aes_key_choice_reg[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h02:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 2
	                plaintext_reg0[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h03:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 3
	                plaintext_reg1[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h04:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 4
	                plaintext_reg2[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h05:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 5
	                plaintext_reg3[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h06:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 6
	                key_reg0[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h07:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 7
	                key_reg1[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h08:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 8
	                key_reg2[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h09:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 9
	                key_reg3[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h0A:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 10
	                key_reg4[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h0B:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 11
	                key_reg5[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h0C:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 12
	                key_reg6[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end  
	          5'h0D:
	            for ( byte_index = 0; byte_index <= (C_S_AXI_DATA_WIDTH/8)-1; byte_index = byte_index+1 )
	              if ( S_AXI_WSTRB[byte_index] == 1 ) begin
	                // Respective byte enables are asserted as per write strobes 
	                // Slave register 13
	                key_reg7[(byte_index*8) +: 8] <= S_AXI_WDATA[(byte_index*8) +: 8];
	              end
	          default : begin
	                      enable_reg <= enable_reg;
	                      aes_key_choice_reg <= aes_key_choice_reg;
	                      plaintext_reg0 <= plaintext_reg0;
	                      plaintext_reg1 <= plaintext_reg1;
	                      plaintext_reg2 <= plaintext_reg2;
	                      plaintext_reg3 <= plaintext_reg3;
	                      key_reg0 <= key_reg0;
	                      key_reg1 <= key_reg1;
	                      key_reg2 <= key_reg2;
	                      key_reg3 <= key_reg3;
	                      key_reg4 <= key_reg4;
	                      key_reg5 <= key_reg5;
	                      key_reg6 <= key_reg6;
	                      key_reg7 <= key_reg7;
	                    end
	        endcase
	      end
	  end
	end    

	// Implement read state machine
	  always @(posedge S_AXI_ACLK)                                       
	    begin                                       
	      if (S_AXI_ARESETN == 1'b0)                                       
	        begin                                       
	         //asserting initial values to all 0's during reset                                       
	         axi_arready <= 1'b0;                                       
	         axi_rvalid <= 1'b0;                                       
	         axi_rresp <= 1'b0;                                       
	         state_read <= Idle;                                       
	        end                                       
	      else                                       
	        begin                                       
	          case(state_read)                                       
	            Idle:     //Initial state inidicating reset is done and ready to receive read/write transactions                                       
	              begin                                                
	                if (S_AXI_ARESETN == 1'b1)                                        
	                  begin                                       
	                    state_read <= Raddr;                                       
	                    axi_arready <= 1'b1;                                       
	                  end                                       
	                else state_read <= state_read;                                       
	              end                                       
	            Raddr:        //At this state, slave is ready to receive address along with corresponding control signals                                       
	              begin                                       
	                if (S_AXI_ARVALID && S_AXI_ARREADY)                                       
	                  begin                                       
	                    state_read <= Rdata;                                       
	                    axi_araddr <= S_AXI_ARADDR;                                       
	                    axi_rvalid <= 1'b1;                                       
	                    axi_arready <= 1'b0;                                       
	                  end                                       
	                else state_read <= state_read;                                       
	              end                                       
	            Rdata:        //At this state, slave is ready to send the data packets until the number of transfers is equal to burst length                                       
	              begin                                           
	                if (S_AXI_RVALID && S_AXI_RREADY)                                       
	                  begin                                       
	                    axi_rvalid <= 1'b0;                                       
	                    axi_arready <= 1'b1;                                       
	                    state_read <= Raddr;                                       
	                  end                                       
	                else state_read <= state_read;                                       
	              end                                       
	           endcase                                       
	          end                                       
	        end                                         
	// Implement memory mapped register select and read logic generation
	  assign S_AXI_RDATA = (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h0) ? enable_reg : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h1) ? aes_key_choice_reg : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h2) ? plaintext_reg0 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h3) ? plaintext_reg1 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h4) ? plaintext_reg2 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h5) ? plaintext_reg3 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h6) ? key_reg0 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h7) ? key_reg1 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h8) ? key_reg2 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h9) ? key_reg3 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'hA) ? key_reg4 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'hB) ? key_reg5 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'hC) ? key_reg6 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'hD) ? key_reg7 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h12) ? done_reg : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h13) ? comp_state_reg : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h14) ? ciphertext_reg0 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h15) ? ciphertext_reg1 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h16) ? ciphertext_reg2 : (axi_araddr[ADDR_LSB+OPT_MEM_ADDR_BITS:ADDR_LSB] == 5'h17) ? ciphertext_reg3 : 0; 
	
	// Add user logic here
	
    assign ENABLE         = enable_reg[0];
    assign AES_KEY_CHOICE = ENABLE?aes_key_choice_reg[1:0]:0;
    
    assign PLAINTEXT[0*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?plaintext_reg0:0;
    assign PLAINTEXT[1*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?plaintext_reg1:0;
    assign PLAINTEXT[2*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?plaintext_reg2:0;
    assign PLAINTEXT[3*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?plaintext_reg3:0;
    
    assign KEY[0*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg0:0;
    assign KEY[1*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg1:0;
    assign KEY[2*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg2:0;
    assign KEY[3*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg3:0; 
    assign KEY[4*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg4:0;
    assign KEY[5*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg5:0;
    assign KEY[6*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg6:0;
    assign KEY[7*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH] = ENABLE?key_reg7:0;
    
    
    // IP states
    localparam IDLE = 2'b00;
    localparam BUSY = 2'b01;
    localparam FINISHED = 2'b10;
    
    // State register
    reg [1:0] comp_state;
    
    always @( posedge S_AXI_ACLK )
    begin
      if ( S_AXI_ARESETN == 1'b0 )
      begin
        done_reg <= 32'h0;    // Status register `Done` and `Correct`
        comp_state_reg <= 32'h0;    // IP state register
        ciphertext_reg0 <= 32'h0;    // Result registers
        ciphertext_reg1 <= 32'h0;
        ciphertext_reg2 <= 32'h0;
        ciphertext_reg3 <= 32'h0;
        comp_state <= IDLE;
      end
      else
      begin
        case (comp_state)
          IDLE:
          begin
            // Wait for the master to command a start
            if (ENABLE) 
            begin
              comp_state <= BUSY;
              done_reg <= 32'h0;    // Status register `Done`
              ciphertext_reg0 <= 32'h0;    // Result registers
              ciphertext_reg1 <= 32'h0;
              ciphertext_reg2 <= 32'h0;
              ciphertext_reg3 <= 32'h0;
            end
          end
    
          BUSY:
          begin
              done_reg <= 32'h1;    // Status register `Done`
              ciphertext_reg0 <= CIPHERTEXT[0*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH];    // Result registers
              ciphertext_reg1 <= CIPHERTEXT[1*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH];
              ciphertext_reg2 <= CIPHERTEXT[2*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH];
              ciphertext_reg3 <= CIPHERTEXT[3*C_S_AXI_DATA_WIDTH+:C_S_AXI_DATA_WIDTH];
              comp_state <= FINISHED;
          end
    
          FINISHED:
          begin
            if (!ENABLE) // Wait for master to read the output registers and set the enable register to low.
            begin
              comp_state <= IDLE;
            end
          end
    
          default:
            comp_state <= IDLE;
    
        endcase
        // Continuously update the status register for the master to read
        comp_state_reg <= comp_state; 
      end
    end

	// User logic ends

	endmodule
