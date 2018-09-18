#include "ring_lib.h"
#include <string.h>


uint32_t RingSize;
//uint32_t RxRingSize;
uint8_t *TxRingBase_address;
uint8_t *RxRingBase_address;


uint32_t TxRingOff;
uint32_t RxRingOff;

uint32_t ring_full;

void initDefaultMsg(icp_qat_fw_la_bulk_req_t *msg,uint8_t id)
{
	
	icp_qat_fw_comn_req_hdr_t *pHdr =(icp_qat_fw_comn_req_hdr_t *) &(msg->comn_hdr);
	icp_qat_fw_comn_req_hdr_cd_pars_t *pCd_pars =(icp_qat_fw_comn_req_hdr_cd_pars_t *) &(msg->cd_pars);
	icp_qat_fw_comn_req_mid_t *pMid =(icp_qat_fw_comn_req_mid_t *) &(msg->comn_mid);

	icp_qat_fw_la_cipher_req_params_t *pCipher_req = (icp_qat_fw_la_cipher_req_params_t*)((uint8_t *) &(msg->serv_specif_rqpars) + ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET);
	icp_qat_fw_la_auth_req_params_t *pAuth_req = (icp_qat_fw_la_auth_req_params_t * )((uint8_t *)&(msg->serv_specif_rqpars) + ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET);
	
	icp_qat_fw_cipher_cd_ctrl_hdr_t *pCipher_cd_ctrl = (icp_qat_fw_cipher_cd_ctrl_hdr_t *)&(msg->cd_ctrl);

	icp_qat_fw_auth_cd_ctrl_hdr_t *pAuth_cd_ctrl = (icp_qat_fw_auth_cd_ctrl_hdr_t *)&(msg->cd_ctrl);


	// init hdr 
	pHdr->resrvd1 = id;
	pHdr->service_cmd_id = 0x00; //cipher
	pHdr->service_type = 0x04;
	pHdr->hdr_flags = 0x80;
	pHdr->serv_specif_flags = 0x0000;
	pHdr->comn_req_flags = 0x0001;
	// init cd_pars
	pCd_pars->s.content_desc_addr = 0x1234567812345678;
	pCd_pars->s.content_desc_resrvd1 = 0x0000;
	pCd_pars->s.content_desc_params_sz = 0x02;
	pCd_pars->s.content_desc_hdr_resrvd2 = 0x00;
	pCd_pars->s.content_desc_resrvd3 = 0x00000000;

	// init pMid
	pMid->opaque_data = 0x2222222222222222;
	pMid->src_data_addr = 0x3333333333333333;
	pMid->dest_data_addr = 0x4444444444444444;
	pMid->src_length = 0x00000010;
	pMid->dst_length = 0x00000010;

	// init cipher
	pCipher_req->cipher_offset = 0x00000000;
	pCipher_req->cipher_length = 0x00111111;
	pCipher_req->u.cipher_IV_array[0] = 0x00;
	pCipher_req->u.cipher_IV_array[1] = 0x00;
	pCipher_req->u.cipher_IV_array[2] = 0x00;
	pCipher_req->u.cipher_IV_array[3] = 0x00;
	
	//init auth 
	pAuth_req->auth_len = 0x00000000;
	pAuth_req->auth_off = 0x00;
	pAuth_req->u1.auth_partial_st_prefix = 0x0;
	//pAuth_req->u1.aad_adr = 0x0;
	pAuth_req->auth_res_addr = 0x0;
	pAuth_req->u2.inner_prefix_sz = 0x0;
	//pAuth_req->u2.aad_sz = 0x0;
	pAuth_req->resrvd1 = 0x0;
	pAuth_req->hash_state_sz = 0x0;
	pAuth_req->auth_res_sz = 0x0;

	//init cipher cd_ctrl
	pCipher_cd_ctrl->cipher_state_sz = 0x00;
	pCipher_cd_ctrl->cipher_key_sz = 0x00;
	pCipher_cd_ctrl->cipher_cfg_offset = 0x00;
	pCipher_cd_ctrl->next_curr_id = 0x00;
	pCipher_cd_ctrl->cipher_padding_sz = 0x00;
	//init auth cd_ctrl
	pAuth_cd_ctrl->hash_flags = 0x00;
	pAuth_cd_ctrl->hash_cfg_offset = 0x00;
	pAuth_cd_ctrl->next_curr_id = 0x00;
	pAuth_cd_ctrl->resrvd3 = 0x00;
	pAuth_cd_ctrl->outer_prefix_sz = 0x00;
	pAuth_cd_ctrl->final_sz = 0x00;
	pAuth_cd_ctrl->inner_res_sz = 0x00;
	pAuth_cd_ctrl->resrvd4 = 0x00;
	pAuth_cd_ctrl->inner_state1_sz = 0x00;
	pAuth_cd_ctrl->inner_state2_offset = 0x00;
	pAuth_cd_ctrl->inner_state2_sz = 0x00;
	pAuth_cd_ctrl->outer_config_offset = 0x00;
	pAuth_cd_ctrl->outer_state1_sz = 0x00;
	pAuth_cd_ctrl->outer_res_sz = 0x00;
	pAuth_cd_ctrl->outer_prefix_offset = 0x00;

	//init auth cd_ctrl

}

void initTxRing(uint8_t * base_address, uint32_t lenth)
{
	RingSize = lenth;
	TxRingBase_address = base_address;
	ring_full = 0;

}

void initRxRing(uint8_t * base_address, uint32_t lenth)
{
	RingSize = lenth;
	RxRingBase_address = base_address;
	ring_full = 0;
}


uint32_t addMsgToTxRing(icp_qat_fw_la_bulk_req_t *msg)
{
	if (ring_full < RingSize) //未满
	{
		//copy data
		memcpy(TxRingBase_address + TxRingOff, msg, MSG_SIZE);
		//add offset
		TxRingOff = TxRingOff + MSG_SIZE;
		if (TxRingOff >= RingSize * MSG_SIZE)
		{
			TxRingOff = 0x00;
		}
		//add ring_full
		ring_full++;
		return TxRingOff;
	}
	else
		return 0x1111;

}

//读一个包
uint32_t getMsgFromRxRing()
{
	// 收到回复包了
	if (*(RxRingBase_address + RxRingOff) != 0x7f)
	{
		//擦除
		memset(RxRingBase_address + RxRingOff, 0x7f, MSG_RES_SIZE);
		// add offset
		RxRingOff = RxRingOff + MSG_RES_SIZE;
		if (RxRingOff >= RingSize * MSG_RES_SIZE)
		{
			RxRingOff = 0x00;
		}
		ring_full--;
		return RxRingOff;
	}
	else
		return 0x1111;

}


uint32_t getRxRingOff()
{
	return RxRingOff;
}


void setIV(icp_qat_fw_la_bulk_req_t *msg, uint32_t *key, uint32_t length)
{
	icp_qat_fw_la_cipher_req_params_t *pCipher_req = (icp_qat_fw_la_cipher_req_params_t*)((uint8_t *) &(msg->serv_specif_rqpars) + ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET);
	memcpy((uint32_t *)pCipher_req->u.cipher_IV_array,key,length);

}


void setKey(icp_qat_fw_la_bulk_req_t *msg, uint32_t *IV, uint32_t length)
{
	icp_qat_fw_comn_req_hdr_cd_pars_t *pCd_pars = (icp_qat_fw_comn_req_hdr_cd_pars_t *) &(msg->cd_pars);
	memcpy((uint32_t *)pCd_pars->s1.serv_specif_fields, IV, length);
}
