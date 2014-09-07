#ifndef DEF_DISSECTOR_H
#define DEF_DISSECTOR_H

typedef struct dissector {
  int (*is_proto)(packet_t*);
  void (*parser)(packet_t**, u8*, u32);
}dissector_t;

void dissector_run(dissector_t *dis, packet_t *cur_layer, u8* data, u32 size);

#endif /* DEF_DISSECTOR_H */
