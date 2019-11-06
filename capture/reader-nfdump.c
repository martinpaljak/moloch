/* reader-nfdump.c
 *
 * Copyright 2019 Estonian Central Criminal Police
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Written by Martin Paljak martin@martinpaljak.net
// Based on reader-libpcap-file.c and nfreader.c from nfdump by Peter Haag

#include "molochconfig.h"
#ifdef HAVE_NFDUMP

#include "moloch.h"
#include <errno.h>

#include "pcap.h" // for DLT_EN10MB

#include "exporter.h"
#include "flist.h"
#include "nffile.h"
#include "nftree.h"
#include "nfx.h"

// From util.h of nfdump
void SetupInputFileSequence(char *multiple_dirs, char *single_file, char *multiple_files);
char *GetCurrentFilename(void);
void LogError(char *format, ...);

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

// sizeof void p == 8, AKA 64b little endian (amd64)
typedef uint64_t pointer_addr_t;
#define htonll(n) (((uint64_t)htonl(n)) << 32) + htonl((n) >> 32)

// defined in util.h and used in nffile_inline.h but not meaningful
#define dbg_printf(...) /* printf(__VA_ARGS__) */
#define dbg_assert(a)   /* assert(a) */

// Depends on pointer address
#include "nffile_inline.c"

// global Moloch things
extern MolochConfig_t config;
extern void *esServer;
extern uint32_t pluginsCbs;

// global nfdump things
extern exporter_t **exporter_list;

// Local things
LOCAL extension_map_list_t *extension_map_list;
LOCAL FilterEngine_data_t *Engine;
LOCAL nffile_t *nffile; // Currently processed file

// Declarations
LOCAL void reader_nfdump_done();          // When nfdump should be shut down, together with moloch
LOCAL gboolean reader_nfdump_read_file(); // Called by timer, reads a file. Retruns true to
                                          // keep timer, false to remove it
LOCAL gboolean reader_nfdump_next();      // Sets the nffile pointer to next file.
                                          // Returns true if next file available,
                                          // false otherwise. Might schedule quit

// TODO: add to moloch.h ?
void moloch_session_close(MolochSession_t *session);

// Allocate and fill with needed data
LOCAL MolochSession_t *moloch_session_create() {
    MolochSession_t *session;
    session = MOLOCH_TYPE_ALLOC0(MolochSession_t);
    session->stopSaving = 0xffff;

    session->filePosArray = g_array_sized_new(FALSE, FALSE, sizeof(uint64_t), 1);
    if (config.enablePacketLen) {
        session->fileLenArray = g_array_sized_new(FALSE, FALSE, sizeof(uint16_t), 1);
    }
    session->fileNumArray = g_array_new(FALSE, FALSE, 4);

    session->fields = MOLOCH_SIZE_ALLOC0(fields, sizeof(MolochField_t *) * config.maxField);
    session->maxFields = config.maxField;

    // We have no pcap, but db.c requires array of size > 0
    int64_t pos = 0;
    g_array_append_val(session->filePosArray, pos);

    return session;
}

// Moves session to closingQ on packet thread.
LOCAL void reader_nfdump_save_on_packet_thread(MolochSession_t *session, gpointer UNUSED(uw1),
                                               gpointer UNUSED(uw2)) {
    if (pluginsCbs & MOLOCH_PLUGIN_NEW)
        moloch_plugins_cb_new(session);

    moloch_session_close(session);
}

// create a new moloch session based on nfdump data and push it to packet thread for saving.
LOCAL void import_nfdump_record(master_record_t *r) {
    MolochSession_t *session = moloch_session_create();
    char sessionId[MOLOCH_SESSIONID_LEN];

    // times
    session->firstPacket.tv_sec = r->first;
    session->lastPacket.tv_sec = r->last;

    // ports
    session->port1 = r->srcport;
    session->port2 = r->dstport;

    // addresses
    if ((r->flags & FLAG_IPV6_ADDR) != 0) {
        // uint8[16] vs uint64[2]
        ((uint64_t *)session->addr1.s6_addr)[0] = htonll(r->V6.srcaddr[0]);
        ((uint64_t *)session->addr1.s6_addr)[1] = htonll(r->V6.srcaddr[1]);
        ((uint64_t *)session->addr2.s6_addr)[0] = htonll(r->V6.dstaddr[0]);
        ((uint64_t *)session->addr2.s6_addr)[1] = htonll(r->V6.dstaddr[1]);
        moloch_session_id6(sessionId, session->addr1.s6_addr, r->srcport, session->addr2.s6_addr,
                           r->dstport);
    } else {
        ((uint32_t *)session->addr1.s6_addr)[2] = htonl(0xffff);
        ((uint32_t *)session->addr1.s6_addr)[3] = htonl(r->V4.srcaddr);
        ((uint32_t *)session->addr2.s6_addr)[2] = htonl(0xffff);
        ((uint32_t *)session->addr2.s6_addr)[3] = htonl(r->V4.dstaddr);
        moloch_session_id(sessionId, r->V4.srcaddr, r->srcport, r->V4.dstaddr, r->dstport);
    }
    memcpy(session->sessionId, sessionId, MOLOCH_SESSIONID_LEN);

    // These are by direction
    session->databytes[0] = r->dOctets;
    session->packets[0] = r->dPkts;

    // These are generic
    session->protocol = r->prot;
    session->ip_tos = r->tos;
    session->tcp_flags = r->tcp_flags;

    // internal for moloch operation - assign one of packet threads
    session->thread = moloch_session_hash(sessionId) % config.packetThreads;

    // protocol tags and extra tags from command line
    moloch_parsers_initial_tag(session);

    // pushes fresh session pointer to packet thread via command queue; session
    // will be freed in packet thread
    moloch_session_add_cmd(session, MOLOCH_SES_CMD_FUNC, NULL, NULL,
                           reader_nfdump_save_on_packet_thread);
}

/******************************************************************************/
int reader_nfdump_stats(MolochReaderStats_t *stats) {
    stats->dropped = 0;
    stats->total = 0;
    return 0;
}

// Called by timer, reads a file, returns, until process_file assigns next file.
LOCAL gboolean reader_nfdump_read_file() {
    master_record_t *master_record;
    common_record_t *flow_record;
    int ret;
    unsigned int j;

    // pause reading if too many waiting ES operations (magic 40 from from reader-libpcap-file.c)
    if (moloch_http_queue_length(esServer) > 40) {
        if (config.debug)
            LOG("Waiting to start next file, es q: %d", moloch_http_queue_length(esServer));
        return G_SOURCE_CONTINUE;
    }

    for (int i = 0; i < 1000000; i++) {
        // get next data block from file
        ret = ReadBlock(nffile);

        // Check if next file should be triggered
        switch (ret) {
        case NF_CORRUPT:
        case NF_ERROR:
            if (ret == NF_CORRUPT)
                fprintf(stderr, "Skip corrupt data file '%s'\n", GetCurrentFilename());
            else
                fprintf(stderr, "Read error in file '%s': %s\n", GetCurrentFilename(),
                        strerror(errno));

            // fall through - get next file in chain
        case NF_EOF:
            return reader_nfdump_next(); // re-trigger this function if there is a
                                         // next file, clear the trigger if not.
                                         // g_timeout_add docs
        }

        // Process blocks
        if (nffile->block_header->id == Large_BLOCK_Type) {
            // skip
            continue;
        }

        if (nffile->block_header->id != DATA_BLOCK_TYPE_2) {
            fprintf(stderr, "Can't process block type %u. Skip block.\n",
                    nffile->block_header->id);
            continue;
        }

        flow_record = nffile->buff_ptr;
        uint32_t sumSize = 0;
        for (j = 0; j < nffile->block_header->NumRecords; j++) {
            if ((sumSize + flow_record->size) > ret || (flow_record->size < sizeof(record_header_t))) {
                LOGEXIT("Corrupt data file. Inconsistent block size");
            }
            sumSize += flow_record->size;

            switch (flow_record->type) {
            case CommonRecordType: {
                uint32_t map_id = flow_record->ext_map;
                exporter_t *exp_info = exporter_list[flow_record->exporter_sysid];
                if (extension_map_list->slot[map_id] == NULL) {
                    LOGEXIT("Corrupt data file! No such extension map id: %u. Skip record",
                            flow_record->ext_map);
                } else {
                    master_record = &(extension_map_list->slot[map_id]->master_record);
                    Engine->nfrecord = (uint64_t *)master_record;
                    ExpandRecord_v2(flow_record, extension_map_list->slot[flow_record->ext_map],
                                    exp_info ? &(exp_info->info) : NULL, master_record);
                    if ((*Engine->FilterEngine)(Engine) != 0) {
                        import_nfdump_record(master_record);
                        extension_map_list->slot[map_id]->ref_count++;
                    }
                }
            } break;
            case ExtensionMapType: {
                extension_map_t *map = (extension_map_t *)flow_record;

                int ret = Insert_Extension_Map(extension_map_list, map);
                switch (ret) {
                case 0:
                    // map already known and flushed
                    break;
                case 1:
                    // new map
                    break;
                default:
                    LOGEXIT("Corrupt data file. Unable to decode");
                }
            } break;
            case ExporterInfoRecordType:
            case ExporterStatRecordType:
            case SamplerInfoRecordype:
                // Silently skip exporter records
                break;
            default:
                fprintf(stderr, "Skip unknown record type %i\n", flow_record->type);
            }

            // Advance pointer by number of bytes for netflow record
            flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);

        } // for all records in block

    } // while
    // Million records read, continue with next round
    return G_SOURCE_CONTINUE;
}

// Sets the file pointer to next file
LOCAL gboolean reader_nfdump_next() {

    if (config.flushBetween)
        moloch_session_flush();

    nffile_t *next = GetNextFile(nffile, 0, 0);

    if (next == EMPTY_LIST) {
        reader_nfdump_done();
        return FALSE;
    }

    if (next == NULL) {
        LOG("Unexpected end of file list");
        reader_nfdump_done();
        return FALSE;
    }

    fprintf(stderr, "Reading '%s'\n", GetCurrentFilename());
    return TRUE;
}

/******************************************************************************/
LOCAL void reader_nfdump_start() {
    char *filter = config.bpf;
    printf("Starting nfdump import from: %s\n", config.readNfdump);

    // FIXME: just to please moloch in main.c:634
    moloch_packet_set_linksnap(DLT_EN10MB, 65535);

    extension_map_list = InitExtensionMaps(NEEDS_EXTENSION_LIST);
    if (!InitExporterList()) {
        LOGEXIT("InitExporterList() failed");
    }

    // if no filter is given, match all
    if (!filter || strlen(filter) == 0)
        filter = "any";

    Engine = CompileFilter(filter);
    if (!Engine) {
        LOGEXIT("CompileFilter() failed for '%s'", filter);
    }

    SetupInputFileSequence(NULL, NULL, config.readNfdump);

    // Get the first file handle. Quit if fail.
    nffile = GetNextFile(NULL, 0, 0);
    if (!nffile) {
        LOGEXIT("GetNextFile() error %s", strerror(errno));
    }

    if (nffile == EMPTY_LIST) {
        LOGEXIT("Empty file list. No files to process");
    }

    fprintf(stderr, "Reading '%s'\n", GetCurrentFilename());

    // Trigger reading
    g_timeout_add(100, reader_nfdump_read_file, 0);
}

LOCAL void reader_nfdump_done() {
    fprintf(stderr, "nfdump import is done\n");
    CloseFile(nffile);
    DisposeFile(nffile);
    PackExtensionMapList(extension_map_list);
    FreeExtensionMaps(extension_map_list);
    moloch_quit();
}

void reader_nfdump_init(char *UNUSED(name)) {
    moloch_reader_start = reader_nfdump_start;
    moloch_reader_stats = reader_nfdump_stats;
}
#endif
