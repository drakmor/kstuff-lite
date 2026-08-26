#pragma once
#include <stdint.h>

int register_fake_key(const uint8_t key_data[32]);
int unregister_fake_key(int key_id);
int get_fake_key(int key_id, uint8_t key_data[32]);
