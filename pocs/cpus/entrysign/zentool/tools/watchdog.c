/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>

static int watchdog;
static int reset;

void notification(int n)
{
    if (n == SIGUSR1)
        watchdog++;
    if (n == SIGUSR2)
        reset++;
}

int main(int argc, char **argv)
{
    FILE *trigger;
    struct timespec req = {
        .tv_sec = 8,
    };

    daemon(false, false);

    nice(-1);

    trigger = fopen("/proc/sysrq-trigger", "w");

    signal(SIGUSR1, notification);
    signal(SIGUSR2, notification);

    do {
        // We wait for a first notification before monitoring, meaning fuzzing has
        // started.
        pause();

        reset = 0;

        while (true) {
            watchdog = 0;

            nanosleep(&req, NULL);

            printf("watchdog @%u\n", watchdog);

            // User wants to halt watchdog.
            if (reset != 0)
                break;

            if (watchdog == 0) {
                fprintf(trigger, "c\n");
                fclose(trigger);
                exit(0);
            }
        }

    } while (true);

    // unreachable
    return 1;
}
