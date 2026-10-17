// SPDX-License-Identifier: Apache-2.0
// Self-built, in-memory fixture. No filesystem, network, or external target.
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct record { int owner; const char *content; };
static const struct record records[] = {{0, "dummy-own"}, {1, "dummy-other"}, {0, "dummy-extra"}};

static const char *process(const char *token, bool patched) {
    size_t length = strlen(token);
    if (length == 0 || length > 8) return NULL;
    for (size_t i = 0; i < length; i++) if (token[i] < '0' || token[i] > '9') return NULL;
    long index = strtol(token, NULL, 10);
    if (index < 0 || index >= 3) return NULL;
    if (patched && records[index].owner != 0) return NULL;
    return records[index].content;
}

static bool effect(const char *token, bool patched) {
    const char *content = process(token, patched);
    return content != NULL && strcmp(content, "dummy-other") == 0;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--search") != 0) return 2;
    long max_cases = strtol(argv[2], NULL, 10);
    if (max_cases < 1 || max_cases > 1000) return 2;
    char candidate[32] = "";
    int attempts = 0;
    bool found = false;
    for (long index = 0; index < max_cases; index++) {
        snprintf(candidate, sizeof(candidate), index == 0 ? "%ld" : "%04ld", index);
        attempts++;
        if (effect(candidate, false) && !effect(candidate, true)) { found = true; break; }
    }
    if (!found) { puts("{\"status\":\"no-counterexample-within-budget\",\"proved_safe\":false}"); return 0; }
    char original[32];
    memcpy(original, candidate, sizeof(candidate));
    int replays = 0;
    size_t index = 0;
    while (index < strlen(candidate) && replays < 64) {
        char trial[32];
        strcpy(trial, candidate);
        memmove(trial + index, trial + index + 1, strlen(trial) - index);
        replays++;
        if (effect(trial, false) && !effect(trial, true)) strcpy(candidate, trial);
        else index++;
    }
    bool normal = strcmp(process("0", false), "dummy-own") == 0 && strcmp(process("0", true), "dummy-own") == 0;
    printf("{\"search_attempts\":%d,\"counterexample\":\"%s\",\"minimal\":\"%s\",\"minimize_replays\":%d,\"vulnerable_security_effect\":%s,\"patched_security_effect\":%s,\"normal_control\":%s,\"proved_safe\":false}\n",
           attempts, original, candidate, replays, effect(candidate, false) ? "true" : "false", effect(candidate, true) ? "true" : "false", normal ? "true" : "false");
    return 0;
}
