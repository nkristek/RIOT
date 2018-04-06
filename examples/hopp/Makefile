APPLICATION = hopp

# If no BOARD is found in the environment, use this default:
BOARD ?= native

BOARD_WHITELIST := fox iotlab-m3 msba2 mulle native pba-d-01-kw2x samr21-xpro


# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

CFLAGS += -DDEVELHELP
CFLAGS += -DUSE_LINKLAYER
#CFLAGS += -DUSE_RONR
CFLAGS += -DCCNL_UAPI_H_
CFLAGS += -DUSE_SUITE_NDNTLV
CFLAGS += -DNEEDS_PREFIX_MATCHING
CFLAGS += -DNEEDS_PACKET_CRAFTING
#CFLAGS += -DCOMPAS_DEBUG=1
CFLAGS += -DCOMPAS_NAM_CACHE_LEN=20
CFLAGS += -DCCNL_CACHE_SIZE=25
CFLAGS += -DCCNL_FACE_TIMEOUT=15
CFLAGS += -DCCNL_INTEREST_TIMEOUT=5
CFLAGS += -DCCNL_MAX_INTEREST_RETRANSMIT=4
CFLAGS += -DCOMPAS_NAM_CACHE_RETRIES=3
CFLAGS += -DCCNL_THREAD_PRIORITY="THREAD_PRIORITY_MAIN-3"
CFLAGS += -DCCNL_STACK_SIZE="THREAD_STACKSIZE_DEFAULT+THREAD_EXTRA_STACKSIZE_PRINTF+1024"
CFLAGS += -DCCNL_QUEUE_SIZE=32
CFLAGS += -D_NETIF_NETAPI_MSG_QUEUE_SIZE=32
CFLAGS += -DCCNL_CONTENT_TIMEOUT=10
#CFLAGS += -DNOPUBSUB

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

USEMODULE += ps
USEMODULE += shell
USEMODULE += shell_commands
# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
USEMODULE += timex
USEMODULE += xtimer
USEMODULE += random
USEMODULE += prng_xorshift
USEMODULE += evtimer
USEMODULE += netstats_l2
#USEMODULE += l2filter_blacklist
USEMODULE += hopp
USEMODULE += pktcnt

USEPKG += tlsf
USEPKG += ccn-lite
USEPKG += compas

include $(RIOTBASE)/Makefile.include
