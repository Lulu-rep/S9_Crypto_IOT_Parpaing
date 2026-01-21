/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    app_netxduo.c
  * @author  MCD Application Team
  * @brief   NetXDuo applicative file
  ******************************************************************************
    * @attention
  *
  * Copyright (c) 2021 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "app_netxduo.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "app_azure_rtos.h"
#include "nx_ip.h"
#include  MOSQUITTO_CERT_FILE
#include "nx_secure_tls_api.h"
#include "nx_http_client.h"
#include "stsafea_core.h"
#include "stsafea_service.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
extern RNG_HandleTypeDef hrng;

extern StSafeA_Handle_t stsafea_handle;

TX_THREAD AppMainThread;
TX_THREAD AppSNTPThread;
TX_THREAD AppHTTPThread;

TX_QUEUE  MsgQueueOne;

TX_SEMAPHORE Semaphore;

NX_PACKET_POOL  AppPool;
NX_IP           IpInstance;
NX_DHCP         DhcpClient;
NX_SNTP_CLIENT  SntpClient;
NX_HTTP_CLIENT  HttpClient;
static NX_DNS   DnsClient;

TX_EVENT_FLAGS_GROUP     SntpFlags;

ULONG   IpAddress;
ULONG   NetMask;

ULONG mqtt_client_stack[MQTT_CLIENT_STACK_SIZE];

TX_EVENT_FLAGS_GROUP mqtt_app_flag;

/* Declare buffers to hold message and topic. */
static char message[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR message_buffer[NXD_MQTT_MAX_MESSAGE_LENGTH];
static UCHAR topic_buffer[NXD_MQTT_MAX_TOPIC_NAME_LENGTH];

/* TLS buffers and certificate containers. */
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;
/* calculated with nx_secure_tls_metadata_size_calculate */
static CHAR crypto_metadata_client[11600];
/* Define the TLS packet reassembly buffer. */
UCHAR tls_packet_buffer[4000];

ULONG                    current_time;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN PFP */
static VOID App_Main_Thread_Entry(ULONG thread_input);
static VOID App_MQTT_Client_Thread_Entry(ULONG thread_input);
static VOID App_HTTP_Get_Thread_Entry(ULONG thread_input);
static VOID App_SNTP_Thread_Entry(ULONG thread_input);
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr);
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time);
static ULONG nx_secure_tls_session_time_function(void);
static UINT dns_create(NX_DNS *dns_ptr);
static UINT Performance_ECDH_Exchange(VOID);

/* USER CODE END PFP */

/**
  * @brief  Application NetXDuo Initialization.
  * @param memory_ptr: memory pointer
  * @retval int
  */
UINT MX_NetXDuo_Init(VOID *memory_ptr)
{
  UINT ret = NX_SUCCESS;
  TX_BYTE_POOL *byte_pool = (TX_BYTE_POOL*)memory_ptr;

   /* USER CODE BEGIN App_NetXDuo_MEM_POOL */

  /* USER CODE END App_NetXDuo_MEM_POOL */
  /* USER CODE BEGIN 0 */

  /* USER CODE END 0 */

  /* USER CODE BEGIN MX_NetXDuo_Init */
#if (USE_STATIC_ALLOCATION == 1)
  printf("Nx_MQTT_Client application started..\n");

  CHAR *pointer;

  /* Initialize the NetX system. */
  nx_system_initialize();

  /* Allocate the memory for packet_pool.  */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer,  NX_PACKET_POOL_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the Packet pool to be used for packet allocation */
  ret = nx_packet_pool_create(&AppPool, "Main Packet Pool", PAYLOAD_SIZE, pointer, NX_PACKET_POOL_SIZE);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for Ip_Instance */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, 2 * DEFAULT_MEMORY_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the main NX_IP instance */
  ret = nx_ip_create(&IpInstance, "Main Ip instance", NULL_ADDRESS, NULL_ADDRESS, &AppPool, nx_driver_emw3080_entry,
                     pointer, 2 * DEFAULT_MEMORY_SIZE, DEFAULT_MAIN_PRIORITY);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* create the DHCP client */
  ret = nx_dhcp_create(&DhcpClient, &IpInstance, "DHCP Client");

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for ARP */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, ARP_MEMORY_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Enable the ARP protocol and provide the ARP cache size for the IP instance */
  ret = nx_arp_enable(&IpInstance, (VOID *)pointer, ARP_MEMORY_SIZE);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Enable the ICMP */
  ret = nx_icmp_enable(&IpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Enable the UDP protocol required for DHCP communication */
  ret = nx_udp_enable(&IpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Enable the TCP protocol required for DNS, MQTT.. */
  ret = nx_tcp_enable(&IpInstance);

  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for main thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, THREAD_MEMORY_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* Create the main thread */
  ret = tx_thread_create(&AppMainThread, "App Main thread", App_Main_Thread_Entry, 0, pointer, THREAD_MEMORY_SIZE,
                         DEFAULT_MAIN_PRIORITY, DEFAULT_MAIN_PRIORITY, TX_NO_TIME_SLICE, TX_AUTO_START);

  if (ret != TX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for SNTP client thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, SNTP_CLIENT_THREAD_MEMORY, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  /* create the SNTP client thread */
  ret = tx_thread_create(&AppSNTPThread, "App SNTP Thread", App_SNTP_Thread_Entry, 0, pointer, SNTP_CLIENT_THREAD_MEMORY,
                         SNTP_PRIORITY, SNTP_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != TX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Create the event flags. */
  ret = tx_event_flags_create(&SntpFlags, "SNTP event flags");

  /* Check for errors */
  if (ret != NX_SUCCESS)
  {
    return NX_NOT_ENABLED;
  }

  /* Allocate the memory for HTTP client thread   */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, THREAD_MEMORY_SIZE, TX_NO_WAIT) != TX_SUCCESS)
  {
    return TX_POOL_ERROR;
  }

  ret = tx_thread_create(&AppHTTPThread, "App POST Thread", App_HTTP_Get_Thread_Entry, 0, pointer, THREAD_MEMORY_SIZE,
            MQTT_PRIORITY, MQTT_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);

  if (ret != NX_SUCCESS)
  {
      printf("Erreur fatale: nx_http_client_create (0x%02x)\n", ret);
      tx_thread_suspend(tx_thread_identify()); // On arrête tout avant le crash
  }

//  /* Allocate the memory for MQTT client thread   */
//  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, THREAD_MEMORY_SIZE, TX_NO_WAIT) != TX_SUCCESS)
//  {
//    return TX_POOL_ERROR;
//  }
//
//
//  /* create the MQTT client thread */
//  ret = tx_thread_create(&AppMQTTClientThread, "App MQTT Thread", App_MQTT_Client_Thread_Entry, 0, pointer, THREAD_MEMORY_SIZE,
//                         MQTT_PRIORITY, MQTT_PRIORITY, TX_NO_TIME_SLICE, TX_DONT_START);
//
//  if (ret != TX_SUCCESS)
//  {
//    return NX_NOT_ENABLED;
//  }

  /* Allocate the MsgQueueOne.  */
  if (tx_byte_allocate(byte_pool, (VOID **) &pointer, APP_QUEUE_SIZE*sizeof(ULONG), TX_NO_WAIT) != TX_SUCCESS)
  {
    ret = TX_POOL_ERROR;
  }

  /* Create the MsgQueueOne shared by MsgSenderThreadOne and MsgReceiverThread */
  if (tx_queue_create(&MsgQueueOne, "Message Queue One",TX_1_ULONG, pointer, APP_QUEUE_SIZE*sizeof(ULONG)) != TX_SUCCESS)
  {
    ret = TX_QUEUE_ERROR;
  }

  /* set DHCP notification callback  */
  tx_semaphore_create(&Semaphore, "DHCP Semaphore", 0);
#endif
  /* USER CODE END MX_NetXDuo_Init */

  return ret;
}

/* USER CODE BEGIN 1 */
/**
* @brief  ip address change callback.
* @param ip_instance: NX_IP instance
* @param ptr: user data
* @retval none
*/
static VOID ip_address_change_notify_callback(NX_IP *ip_instance, VOID *ptr)
{
  /* release the semaphore as soon as an IP address is available */
  tx_semaphore_put(&Semaphore);
}

/**
* @brief  DNS Create Function.
* @param dns_ptr
* @retval ret
*/
UINT dns_create(NX_DNS *dns_ptr)
{
  UINT ret = NX_SUCCESS;

  /* Create a DNS instance for the Client */
  ret = nx_dns_create(dns_ptr, &IpInstance, (UCHAR *)"DNS Client");
  if (ret)
  {
    Error_Handler();
  }
  /* Initialize DNS instance with a dummy server */
  ret = nx_dns_server_add(dns_ptr, USER_DNS_ADDRESS);
  if (ret)
  {
    Error_Handler();
  }

  return ret;
}

/**
* @brief  Main thread entry.
* @param thread_input: ULONG user argument used by the thread entry
* @retval none
*/
static VOID App_Main_Thread_Entry(ULONG thread_input)
{
  UINT ret = NX_SUCCESS;

  /* Create a DNS client */
  ret = dns_create(&DnsClient);

  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  ret = nx_ip_address_change_notify(&IpInstance, ip_address_change_notify_callback, NULL);

  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* start DHCP client */
  ret = nx_dhcp_start(&DhcpClient);

  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* wait until an IP address is ready */
  if(tx_semaphore_get(&Semaphore, TX_WAIT_FOREVER) != TX_SUCCESS)
  {
    Error_Handler();
  }

  ret = nx_ip_address_get(&IpInstance, &IpAddress, &NetMask);

  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }

  PRINT_IP_ADDRESS(IpAddress);

  /* start the SNTP client thread */
  tx_thread_resume(&AppSNTPThread);

  tx_thread_resume(&AppHTTPThread);

  /* this thread is not needed any more, we relinquish it */
  tx_thread_relinquish();

  return;
}

/* Declare the disconnect notify function. */
static VOID my_disconnect_func(NXD_MQTT_CLIENT *client_ptr)
{
  NX_PARAMETER_NOT_USED(client_ptr);

  printf("client disconnected from broker < %s >.\n", MQTT_BROKER_NAME);
}

/* Declare the notify function. */
static VOID my_notify_func(NXD_MQTT_CLIENT* client_ptr, UINT number_of_messages)
{
  NX_PARAMETER_NOT_USED(client_ptr);
  NX_PARAMETER_NOT_USED(number_of_messages);

  tx_event_flags_set(&mqtt_app_flag, DEMO_MESSAGE_EVENT, TX_OR);
  return;
}

/**
* @brief  message generation Function.
* @param  RandomNbr
* @retval none
*/
UINT message_generate()
{
  uint32_t RandomNbr = 0;

  HAL_RNG_Init(&hrng);

  /* generate a random number */
  if(HAL_RNG_GenerateRandomNumber(&hrng, &RandomNbr) != HAL_OK)
  {
    Error_Handler();
  }

  return RandomNbr %= 50;
}

/* Function (set by user) to call when TLS needs the current time. */
ULONG nx_secure_tls_session_time_function(void)
{
  return (current_time);
}

/* Callback to setup TLS parameters for secure MQTT connection. */
UINT tls_setup_callback(NXD_MQTT_CLIENT *client_pt,
                        NX_SECURE_TLS_SESSION *TLS_session_ptr,
                        NX_SECURE_X509_CERT *certificate_ptr,
                        NX_SECURE_X509_CERT *trusted_certificate_ptr)
{
  UINT ret = NX_SUCCESS;
  NX_PARAMETER_NOT_USED(client_pt);

  /* Initialize TLS module */
  nx_secure_tls_initialize();

  /* Create a TLS session */
  ret = nx_secure_tls_session_create(TLS_session_ptr, &nx_crypto_tls_ciphers,
                                     crypto_metadata_client, sizeof(crypto_metadata_client));
  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }
  /* Need to allocate space for the certificate coming in from the broker. */
  memset((certificate_ptr), 0, sizeof(NX_SECURE_X509_CERT));

  ret = nx_secure_tls_session_time_function_set(TLS_session_ptr, nx_secure_tls_session_time_function);

  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }

  /* Allocate space for packet reassembly. */
  ret = nx_secure_tls_session_packet_buffer_set(TLS_session_ptr, tls_packet_buffer,
                                                sizeof(tls_packet_buffer));
  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }

  /* allocate space for the certificate coming in from the remote host */
  ret = nx_secure_tls_remote_certificate_allocate(TLS_session_ptr, certificate_ptr,
                                                  tls_packet_buffer, sizeof(tls_packet_buffer));
  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }

  /* initialize Certificate to verify incoming server certificates. */
  ret = nx_secure_x509_certificate_initialize(trusted_certificate_ptr, (UCHAR*)mosquitto_org_der,
                                              mosquitto_org_der_len, NX_NULL, 0, NULL, 0,
                                              NX_SECURE_X509_KEY_TYPE_NONE);
  if (ret != TX_SUCCESS)
  {
    printf("Certificate issue..\nPlease make sure that your X509_certificate is valid. \n");
    Error_Handler();
  }

  /* Add a CA Certificate to our trusted store */
  ret = nx_secure_tls_trusted_certificate_add(TLS_session_ptr, trusted_certificate_ptr);
  if (ret != TX_SUCCESS)
  {
    Error_Handler();
  }

  return ret;
}

/* This application defined handler for notifying SNTP time update event.  */
static VOID time_update_callback(NX_SNTP_TIME_MESSAGE *time_update_ptr, NX_SNTP_TIME *local_time)
{
  NX_PARAMETER_NOT_USED(time_update_ptr);
  NX_PARAMETER_NOT_USED(local_time);

  tx_event_flags_set(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR);
}

/** @brief  SNTP Client thread entry.
* @param thread_input: ULONG user argument used by the thread entry
* @retval none
*/
static VOID App_SNTP_Thread_Entry(ULONG thread_input)
{
  UINT ret;
  ULONG  fraction;
  ULONG  events = 0;
  UINT   server_status;
  NXD_ADDRESS sntp_server_ip;

  sntp_server_ip.nxd_ip_version = 4;

  /* Look up SNTP Server address. */
  ret = nx_dns_host_by_name_get(&DnsClient, (UCHAR *)SNTP_SERVER_NAME, &sntp_server_ip.nxd_ip_address.v4, DEFAULT_TIMEOUT);

  /* Check for error. */
  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* Create the SNTP Client */
  ret =  nx_sntp_client_create(&SntpClient, &IpInstance, 0, &AppPool, NULL, NULL, NULL);

  /* Check for error. */
  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* Setup time update callback function. */
  nx_sntp_client_set_time_update_notify(&SntpClient, time_update_callback);

  /* Use the IPv4 service to set up the Client and set the IPv4 SNTP server. */
  ret = nx_sntp_client_initialize_unicast(&SntpClient, sntp_server_ip.nxd_ip_address.v4);

  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* Run whichever service the client is configured for. */
  ret = nx_sntp_client_run_unicast(&SntpClient);

  if (ret != NX_SUCCESS)
  {
    Error_Handler();
  }

  /* Wait for a server update event. */
  tx_event_flags_get(&SntpFlags, SNTP_UPDATE_EVENT, TX_OR_CLEAR, &events, PERIODIC_CHECK_INTERVAL);

  if (events == SNTP_UPDATE_EVENT)
  {
    /* Check for valid SNTP server status. */
    ret = nx_sntp_client_receiving_updates(&SntpClient, &server_status);

    if ((ret != NX_SUCCESS) || (server_status == NX_FALSE))
    {
      /* We do not have a valid update. */
      Error_Handler();
    }
    /* We have a valid update.  Get the SNTP Client time.  */
    ret = nx_sntp_client_get_local_time_extended(&SntpClient, &current_time, &fraction, NX_NULL, 0);

    /* take off 70 years difference */
    current_time -= EPOCH_TIME_DIFF;

  }
  else
  {
    Error_Handler();
  }

  /* start the MQTT client thread */
  //tx_thread_resume(&AppMQTTClientThread);

}

static VOID App_HTTP_Get_Thread_Entry(ULONG thread_input)
{
  UINT ret;
  NXD_ADDRESS server_ip;
  NX_PACKET *response_packet;

  printf("HTTP GET thread started (API 6.1.6)\n");

  server_ip.nxd_ip_version = NX_IP_VERSION_V4;
  server_ip.nxd_ip_address.v4 = IP_ADDRESS(144, 24, 206, 188);

  while(1)
  {
	  /* 1. Création du client propre */
	      nx_http_client_create(&HttpClient, "HTTP Client", &IpInstance, &AppPool, 2048);
	      nx_http_client_set_connect_port(&HttpClient, 8000);

	      /* 2. Appel de l'échange Diffie-Hellman */
	      Performance_ECDH_Exchange();

	      /* 3. Cleanup */
	      nx_http_client_delete(&HttpClient);

	      tx_thread_sleep(1000); // 10 secondes entre chaque test
	      //if exchange valid => main loop collection and sent with cypher
  }
}

/**
 * @brief Génère la clé STSAFE et l'envoie via HTTP POST
 */
// 1. Ajoute ce prototype en haut du fichier pour supprimer le warning Success_Handler
void Success_Handler(void);

UINT Performance_ECDH_Exchange(VOID)
{
    UINT ret;
    NXD_ADDRESS server_ip;
    NX_PACKET *send_packet = NX_NULL;
    NX_PACKET *response_packet = NX_NULL;
    NX_TCP_SOCKET tcp_socket;

    /* Buffers */
    uint8_t dataX[32], dataY[32];
    StSafeA_LVBuffer_t pubX = {32, dataX}, pubY = {32, dataY};
    uint8_t point_rep;

    char json_payload[512];
    char pub_key_hex[135];
    char server_pub_key_hex[135];
    char http_request[1024];

    server_ip.nxd_ip_version = NX_IP_VERSION_V4;
    server_ip.nxd_ip_address.v4 = IP_ADDRESS(144, 24, 206, 188);

    /* 1. STSAFE - Génération Paire de clés */
    while(1) {
        if (StSafeA_GenerateKeyPair(&stsafea_handle, STSAFEA_KEY_SLOT_1, 0xFFFF, 0, 0x0C, 0, 32, &point_rep, &pubX, &pubY, 0) == STSAFEA_OK) break;
        tx_thread_sleep(100);
    }

    /* 2. Formatage JSON */
    sprintf(pub_key_hex, "04");
    for(int i=0; i<32; i++) sprintf(&pub_key_hex[(i*2)+2], "%02X", dataX[i]);
    for(int i=0; i<32; i++) sprintf(&pub_key_hex[66+(i*2)], "%02X", dataY[i]);

    snprintf(json_payload, sizeof(json_payload), "{\"client_id\":\"Pierre_STM32\",\"client_public_key_hex\":\"%s\"}", pub_key_hex);

    /* 3. Construction Requête HTTP */
    int req_len = snprintf(http_request, sizeof(http_request),
        "PUT /exchange/ecdh HTTP/1.1\r\nHost: 144.24.206.188:8000\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        (int)strlen(json_payload), json_payload);

    /* 4. Connexion & Envoi */
    nx_tcp_socket_create(&IpInstance, &tcp_socket, "TCP RAW", NX_IP_NORMAL, NX_DONT_FRAGMENT, NX_IP_TIME_TO_LIVE, 8192, NX_NULL, NX_NULL);
    nx_tcp_client_socket_bind(&tcp_socket, NX_ANY_PORT, NX_WAIT_FOREVER);

    ret = nxd_tcp_client_socket_connect(&tcp_socket, &server_ip, 8000, 500);
    if (ret == NX_SUCCESS) {
        if (nx_packet_allocate(&AppPool, &send_packet, NX_TCP_PACKET, TX_WAIT_FOREVER) == NX_SUCCESS) {
            nx_packet_data_append(send_packet, http_request, req_len, &AppPool, TX_WAIT_FOREVER);
            nx_tcp_socket_send(&tcp_socket, send_packet, 500);
        }

        // --- LECTURE MULTI-PAQUETS ---
        int key_found = 0;
        while (nx_tcp_socket_receive(&tcp_socket, &response_packet, 500) == NX_SUCCESS) {
            char *data = (char *)response_packet->nx_packet_prepend_ptr;
            ULONG len = response_packet->nx_packet_length;

            printf("PAQUET RECU (%lu octets)\n", len);

            char *token = "server_public_key_hex\":\"";
            char *found = strstr(data, token);

            if (found != NULL) {
                found += strlen(token);
                memcpy(server_pub_key_hex, found, 130);
                server_pub_key_hex[130] = '\0';
                printf(">>> CLE SERVEUR EXTRAITE : %s\n", server_pub_key_hex);
                key_found = 1;
            }
            nx_packet_release(response_packet);
            if (key_found) break;
        }

        if (key_found) {
			/* --- 5. CALCUL DU SECRET --- */
			uint8_t srvX[32], srvY[32];
			StSafeA_LVBuffer_t srvX_lv = {32, srvX}, srvY_lv = {32, srvY};
			StSafeA_SharedSecretBuffer_t shared_out;
			uint8_t shared_secret[32];

			// 1. Conversion hex -> bin rigoureuse
			// Note : Ton sscanf utilisait %02lx (long). Utilisons une méthode plus sûre.
			for (int i = 0; i < 32; i++) {
				unsigned int valX, valY;
				// On saute le "04" (2 chars). X commence à l'index 2, Y à l'index 66
				sscanf(&server_pub_key_hex[2 + (i * 2)], "%02x", &valX);
				sscanf(&server_pub_key_hex[66 + (i * 2)], "%02x", &valY);
				srvX[i] = (uint8_t)valX;
				srvY[i] = (uint8_t)valY;
			}

			// 2. Initialisation structure de sortie
			// Vérifie bien dans stsafea_core.h si c'est pData ou SharedKey.Data
			shared_out.Length = 32;
			shared_out.SharedKey.Data = shared_secret;

			printf("Tentative EstablishKey sur Slot 1...\n");

			// 3. Appel avec cast explicite si nécessaire
			ret = StSafeA_EstablishKey(&stsafea_handle,
									   STSAFEA_KEY_SLOT_1,
									   (const StSafeA_LVBuffer_t *)&srvX_lv,
									   (const StSafeA_LVBuffer_t *)&srvY_lv,
									   32,
									   &shared_out,
									   STSAFEA_MAC_NONE, // Utilise la constante si définie
									   0);

			if (ret == STSAFEA_OK) {
				printf(">>> SHARED SECRET CALCULÉ AVEC SUCCÈS !\nSECRET: ");
				for(int i=0; i<32; i++) printf("%02X", shared_secret[i]);
				printf("\n");
			} else {
				// Si tu as encore 0x11, c'est que le point X/Y envoyé par le serveur
				// n'est pas reconnu comme valide par le STSAFE.
				printf("Erreur STSAFE EstablishKey: 0x%02X\n", ret);
			}

			/* Nettoyage Socket */
			nx_tcp_socket_disconnect(&tcp_socket, 100);
			nx_tcp_client_socket_unbind(&tcp_socket);
			nx_tcp_socket_delete(&tcp_socket);
			return (ret == STSAFEA_OK) ? NX_SUCCESS : NX_NOT_SUCCESSFUL;
        }
    }

    // Nettoyage en cas d'erreur
    nx_tcp_socket_disconnect(&tcp_socket, 100);
    nx_tcp_client_socket_unbind(&tcp_socket);
    nx_tcp_socket_delete(&tcp_socket);
    return ret;
}
/* USER CODE END 1 */
