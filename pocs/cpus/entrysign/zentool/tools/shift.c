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

#include <stdio.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <linux/keyboard.h>

int main()
{
    char shift_state = 6;

    if (ioctl(0, TIOCLINUX, &shift_state) < 0) {
        perror("ioctl TIOCLINUX 6 (get shift state)");
        return 1;
    }

    //printf("%x\n", shift_state);

    if (shift_state & (1 << KG_SHIFT))
        return 0;

    return 1;
}
