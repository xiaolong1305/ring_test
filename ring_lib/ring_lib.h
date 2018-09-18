#ifndef __RING_LIB_H
#define __RING_LIB_H

#include <stdint.h>

#define ICP_QAT_FW_NUM_LONGWORDS_13 13
#define ICP_QAT_FW_NUM_LONGWORDS_5 5
#define ICP_QAT_FW_NUM_LONGWORDS_4 4
#define ICP_QAT_FW_NUM_LONGWORDS_3 3
#define MSG_SIZE	128
#define MSG_RES_SIZE	64
// typedef
typedef uint16_t icp_qat_fw_comn_flags;
typedef uint16_t icp_qat_fw_serv_specif_flags;

typedef struct icp_qat_fw_comn_req_hdr_s
{
	/**< LW0 */
	uint8_t resrvd1;
	/**< reserved field */

	uint8_t service_cmd_id;
	/**< Service Command Id  - this field is service-specific
	* Please use service-specific command Id here e.g.Crypto Command Id
	* or Compression Command Id etc. */

	uint8_t service_type;
	/**< Service type */

	uint8_t hdr_flags;
	/**< This represents a flags field for the Service Request.
	* The most significant bit is the 'valid' flag and the only
	* one used. All remaining bit positions are unused and
	* are therefore reserved and need to be set to 0. */

	/**< LW1 */
	icp_qat_fw_serv_specif_flags serv_specif_flags;
	/**< Common Request service-specific flags
	* e.g. Symmetric Crypto Command Flags */

	icp_qat_fw_comn_flags comn_req_flags;
	/**< Common Request Flags consisting of
	* - 14 reserved bits,
	* - 1 Content Descriptor field type bit and
	* - 1 Source/destination pointer type bit */

} icp_qat_fw_comn_req_hdr_t;

typedef union icp_qat_fw_comn_req_hdr_cd_pars_s {
	/**< LWs 2-5 */
	struct
	{
		uint64_t content_desc_addr;
		/**< Address of the content descriptor */

		uint16_t content_desc_resrvd1;
		/**< Content descriptor reserved field */

		uint8_t content_desc_params_sz;
		/**< Size of the content descriptor parameters in quad words. These
		* parameters describe the session setup configuration info for the
		* slices that this request relies upon i.e. the configuration word and
		* cipher key needed by the cipher slice if there is a request for
		* cipher processing. */

		uint8_t content_desc_hdr_resrvd2;
		/**< Content descriptor reserved field */

		uint32_t content_desc_resrvd3;
		/**< Content descriptor reserved field */
	} s;

	struct
	{
		uint32_t serv_specif_fields[ICP_QAT_FW_NUM_LONGWORDS_4];

	} s1;

} icp_qat_fw_comn_req_hdr_cd_pars_t;

typedef struct icp_qat_fw_comn_req_mid_s
{
	/**< LWs 6-13 */
	uint64_t opaque_data;
	/**< Opaque data passed unmodified from the request to response messages by
	* firmware (fw) */

	uint64_t src_data_addr;
	/**< Generic definition of the source data supplied to the QAT AE. The
	* common flags are used to further describe the attributes of this
	* field */

	uint64_t dest_data_addr;
	/**< Generic definition of the destination data supplied to the QAT AE. The
	* common flags are used to further describe the attributes of this
	* field */

	uint32_t src_length;
	/** < Length of source flat buffer incase src buffer
	* type is flat */

	uint32_t dst_length;
	/** < Length of source flat buffer incase dst buffer
	* type is flat */

} icp_qat_fw_comn_req_mid_t;

typedef struct icp_qat_fw_comn_req_rqpars_s
{
	/**< LWs 14-26 */
	uint32_t serv_specif_rqpars_lw[ICP_QAT_FW_NUM_LONGWORDS_13];

} icp_qat_fw_comn_req_rqpars_t;

typedef struct icp_qat_fw_comn_req_cd_ctrl_s
{
	/**< LWs 27-31 */
	uint32_t content_desc_ctrl_lw[ICP_QAT_FW_NUM_LONGWORDS_5];

} icp_qat_fw_comn_req_cd_ctrl_t;


typedef struct icp_qat_fw_la_bulk_req_s
{
	/**< LWs 0-1 */
	icp_qat_fw_comn_req_hdr_t comn_hdr;
	/**< Common request header - for Service Command Id,
	* use service-specific Crypto Command Id.
	* Service Specific Flags - use Symmetric Crypto Command Flags
	* (all of cipher, auth, SSL3, TLS and MGF,
	* excluding TRNG - field unused) */

	/**< LWs 2-5 */
	icp_qat_fw_comn_req_hdr_cd_pars_t cd_pars;
	/**< Common Request content descriptor field which points either to a
	* content descriptor
	* parameter block or contains the service-specific data itself. */

	/**< LWs 6-13 */
	icp_qat_fw_comn_req_mid_t comn_mid;
	/**< Common request middle section */

	/**< LWs 14-26 */
	icp_qat_fw_comn_req_rqpars_t serv_specif_rqpars;
	/**< Common request service-specific parameter field */

	/**< LWs 27-31 */
	icp_qat_fw_comn_req_cd_ctrl_t cd_ctrl;
	/**< Common request content descriptor control block -
	* this field is service-specific */

} icp_qat_fw_la_bulk_req_t;


typedef struct icp_qat_fw_la_cipher_req_params_s
{
	/**< LW 14 */
	uint32_t cipher_offset;
	/**< Cipher offset long word. */

	/**< LW 15 */
	uint32_t cipher_length;
	/**< Cipher length long word. */

	/**< LWs 16-19 */
	union {
		uint32_t cipher_IV_array[ICP_QAT_FW_NUM_LONGWORDS_4];
		/**< Cipher IV array  */

		struct
		{
			uint64_t cipher_IV_ptr;
			/**< Cipher IV pointer or Partial State Pointer */

			uint64_t resrvd1;
			/**< reserved */

		} s;

	} u;

} icp_qat_fw_la_cipher_req_params_t;
#define ICP_QAT_FW_HASH_REQUEST_PARAMETERS_OFFSET                              \
    (sizeof(icp_qat_fw_la_cipher_req_params_t))

#define ICP_QAT_FW_CIPHER_REQUEST_PARAMETERS_OFFSET (0)

#pragma pack(push, 1)
typedef struct icp_qat_fw_la_auth_req_params_s
{

	/**< LW 20 */
	uint32_t auth_off;
	/**< Byte offset from the start of packet to the auth data region */

	/**< LW 21 */
	uint32_t auth_len;
	/**< Byte length of the auth data region */

	/**< LWs 22-23 */
	union {
		uint64_t auth_partial_st_prefix;
		/**< Address of the authentication partial state prefix
		* information */

		uint64_t aad_adr;
		/**< Address of the AAD info in DRAM. Used for the CCM and GCM
		* protocols */

	} u1;

	/**< LWs 24-25 */
	uint64_t auth_res_addr;
	/**< Address of the authentication result information to validate or
	* the location to which the digest information can be written back to */

	/**< LW 26 */
	union {
		uint8_t inner_prefix_sz;
		/**< Size in bytes of the inner prefix data */

		uint8_t aad_sz;
		/**< Size in bytes of padded AAD data to prefix to the packet for CCM
		*  or GCM processing */
	} u2;

	uint8_t resrvd1;
	/**< reserved */

	uint8_t hash_state_sz;
	/**< Number of quad words of inner and outer hash prefix data to process
	* Maximum size is 240 */

	uint8_t auth_res_sz;
	/**< Size in bytes of the authentication result */

} icp_qat_fw_la_auth_req_params_t;
#pragma pack(pop)

typedef struct icp_qat_fw_cipher_cd_ctrl_hdr_s
{
	/**< LW 27 */
	uint8_t cipher_state_sz;
	/**< State size in quad words of the cipher algorithm used in this session.
	* Set to zero if the algorithm doesnt provide any state */

	uint8_t cipher_key_sz;
	/**< Key size in quad words of the cipher algorithm used in this session */

	uint8_t cipher_cfg_offset;
	/**< Quad word offset from the content descriptor parameters address i.e.
	* (content_address + (cd_hdr_sz << 3)) to the parameters for the cipher
	* processing */

	uint8_t next_curr_id;
	/**< This field combines the next and current id (each four bits) -
	* the next id is the most significant nibble.
	* Next Id:  Set to the next slice to pass the ciphered data through.
	* Set to ICP_QAT_FW_SLICE_DRAM_WR if the data is not to go through
	* any more slices after cipher.
	* Current Id: Initialised with the cipher  slice type */

	/**< LW 28 */
	uint8_t cipher_padding_sz;
	/**< State padding size in quad words. Set to 0 if no padding is required.
	*/

	uint8_t resrvd1;
	uint16_t resrvd2;
	/**< Reserved bytes to bring the struct to the word boundary, used by
	* authentication. MUST be set to 0 */

	/**< LWs 29-31 */
	uint32_t resrvd3[ICP_QAT_FW_NUM_LONGWORDS_3];
	/**< Reserved bytes used by authentication. MUST be set to 0 */

} icp_qat_fw_cipher_cd_ctrl_hdr_t;

typedef struct icp_qat_fw_auth_cd_ctrl_hdr_s
{
	/**< LW 27 */
	uint32_t resrvd1;
	/**< Reserved bytes, used by cipher only. MUST be set to 0 */

	/**< LW 28 */
	uint8_t resrvd2;
	/**< Reserved byte, used by cipher only. MUST be set to 0 */

	uint8_t hash_flags;
	/**< General flags defining the processing to perform. 0 is normal
	* processing
	* and 1 means there is a nested hash processing loop to go through */

	uint8_t hash_cfg_offset;
	/**< Quad word offset from the content descriptor parameters address to the
	* parameters for the auth processing */

	uint8_t next_curr_id;
	/**< This field combines the next and current id (each four bits) -
	* the next id is the most significant nibble.
	* Next Id:  Set to the next slice to pass the authentication data through.
	* Set to ICP_QAT_FW_SLICE_DRAM_WR if the data is not to go through
	* any more slices after authentication.
	* Current Id: Initialised with the authentication slice type */

	/**< LW 29 */
	uint8_t resrvd3;
	/**< Now a reserved field. MUST be set to 0 */

	uint8_t outer_prefix_sz;
	/**< Size in bytes of outer prefix data */

	uint8_t final_sz;
	/**< Size in bytes of digest to be returned to the client if requested */

	uint8_t inner_res_sz;
	/**< Size in bytes of the digest from the inner hash algorithm */

	/**< LW 30 */
	uint8_t resrvd4;
	/**< Now a reserved field. MUST be set to zero. */

	uint8_t inner_state1_sz;
	/**< Size in bytes of inner hash state1 data. Must be a qword multiple */

	uint8_t inner_state2_offset;
	/**< Quad word offset from the content descriptor parameters pointer to the
	* inner state2 value */

	uint8_t inner_state2_sz;
	/**< Size in bytes of inner hash state2 data. Must be a qword multiple */

	/**< LW 31 */
	uint8_t outer_config_offset;
	/**< Quad word offset from the content descriptor parameters pointer to the
	* outer configuration information */

	uint8_t outer_state1_sz;
	/**< Size in bytes of the outer state1 value */

	uint8_t outer_res_sz;
	/**< Size in bytes of digest from the outer auth algorithm */

	uint8_t outer_prefix_offset;
	/**< Quad word offset from the start of the inner prefix data to the outer
	* prefix information. Should equal the rounded inner prefix size, converted
	* to qwords  */

} icp_qat_fw_auth_cd_ctrl_hdr_t;


// init default msg value
void initDefaultMsg(icp_qat_fw_la_bulk_req_t *msg,uint8_t msg_id);

void initTxRing(uint8_t * base_address, uint32_t lenth);

void initRxRing(uint8_t * base_address, uint32_t lenth);

uint32_t addMsgToTxRing(icp_qat_fw_la_bulk_req_t *msg);

uint32_t getMsgFromRxRing();

uint32_t getRxRingOff();

void setIV(icp_qat_fw_la_bulk_req_t *msg, uint32_t *key, uint32_t length);
void setKey(icp_qat_fw_la_bulk_req_t *msg, uint32_t *IV, uint32_t length);
#endif // !__RING_LIB_H

