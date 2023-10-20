#include <stdint.h>

struct qed_observation {
    uint32_t observation_point;
    uint64_t epoch_nanoseconds;
    uint32_t packet_id;
    uint16_t payload_len;
};

struct observation_list_entry {
    struct observation_list_entry *next;
    struct qed_observation *observation;
};

struct observation_list {
    struct observation_list_entry *first;
    struct observation_list_entry *last;
};

struct observation_list *sent_packet_list_create();
void sent_packet_list_destroy(struct observation_list *spl);
void remove_packet(struct observation_list_entry *packet,
                   struct observation_list_entry *prev_packet,
                   struct observation_list *spl);