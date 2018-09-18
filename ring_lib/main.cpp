#include <cstdio>
#include "ring_lib.h"
#include "stdlib.h"
#include <string.h>

#define RINGSIZE	10

uint32_t key[] = {
	0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c
};
uint32_t IV[] = {
	0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c
};

int main()
{
	icp_qat_fw_la_bulk_req_t msg;
	icp_qat_fw_la_bulk_req_t *memory_tx;
	uint8_t *memory_rx;
	uint32_t off_temp_tx;
	uint32_t off_temp_rx;
	int i;
	uint8_t msg_id;
	
	//初始化tx memory
	memory_tx = (icp_qat_fw_la_bulk_req_t *)malloc(RINGSIZE * MSG_SIZE);
	memory_rx = (uint8_t *)malloc(RINGSIZE *MSG_RES_SIZE);

	//配置ring的大小，基地址等信息到bar空间
	// 设置base_addrees 和 size
	initTxRing((uint8_t *)memory_tx, RINGSIZE);
	initRxRing((uint8_t *)memory_rx, RINGSIZE);
	memset(memory_rx,0x7f, RINGSIZE *MSG_RES_SIZE);
	msg_id = 0x00;
	//msg.comn_mid.src_data_addr
	while (1)
	{
		//init msg
		initDefaultMsg(&msg, msg_id);
		off_temp_tx = addMsgToTxRing(&msg);
		setIV(&msg,IV,sizeof(IV));
		setKey(&msg, key, sizeof(key));
		//addMsgToTxRing((icp_qat_fw_la_bulk_req_t *)(&0x11));

		if (off_temp_tx != 0x1111)
		{
			printf("set TX offset 0x%x,msg id is 0x%x\n", off_temp_tx, msg_id);
			msg_id++;
			if (msg_id % 2 == 0)
			{
				printf("is odd\n");
				msg.comn_mid.src_data_addr = 0x80002000;
			}
			else
			{
				printf("is even\n");
				msg.comn_mid.src_data_addr = 0x90002000;
			}
		}
		else
		{
			printf("ring is full\n");
		}
		// receive response msg
		off_temp_rx = getRxRingOff();
		// simulate rec msg
		memset(memory_rx+ off_temp_rx,0x00, MSG_RES_SIZE);
		// read rx msg
		off_temp_rx = getMsgFromRxRing();

		if (off_temp_rx != 0x1111)
		{
			printf("set RX offset 0x%x\n", off_temp_rx);
		}
		else
		{
			printf("no response receive\n");
		}

	}
	free(memory_tx);
	free(memory_rx);
	//printf("hello from ring_lib!\n");
    return 0;
}